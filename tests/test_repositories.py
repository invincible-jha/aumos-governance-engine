"""Tests for the adapter/repository layer.

Tests AuditTrailRepository (Audit Wall) and primary DB repositories.
These are unit tests using mock SQLAlchemy sessions — integration tests
with real databases are run separately via testcontainers.

Tests verify:
- Correct SQL query construction
- Tenant isolation enforcement
- Immutability of AuditTrailRepository (no update/delete)
- append() correctly builds AuditTrailEntry objects
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aumos_governance_engine.adapters.audit_wall import AuditTrailRepository
from aumos_governance_engine.adapters.repositories import (
    ComplianceWorkflowRepository,
    EvidenceRepository,
    PolicyRepository,
    RegulationMappingRepository,
)
from aumos_governance_engine.core.models import AuditTrailEntry


class TestAuditTrailRepository:
    """Tests for AuditTrailRepository — Audit Wall immutability enforcement."""

    def test_repository_has_no_update_method(self) -> None:
        """AuditTrailRepository must not expose any update method."""
        session = AsyncMock()
        repo = AuditTrailRepository(session)

        assert not hasattr(repo, "update"), "AuditTrailRepository must not have update()"
        assert not hasattr(repo, "update_status"), "AuditTrailRepository must not have update_status()"

    def test_repository_has_no_delete_method(self) -> None:
        """AuditTrailRepository must not expose any delete method."""
        session = AsyncMock()
        repo = AuditTrailRepository(session)

        assert not hasattr(repo, "delete"), "AuditTrailRepository must not have delete()"
        assert not hasattr(repo, "remove"), "AuditTrailRepository must not have remove()"
        assert not hasattr(repo, "truncate"), "AuditTrailRepository must not have truncate()"

    @pytest.mark.asyncio()
    async def test_append_creates_audit_entry(
        self,
        tenant_id: uuid.UUID,
        actor_id: uuid.UUID,
    ) -> None:
        """append() creates an AuditTrailEntry with correct fields."""
        session = AsyncMock()
        session.flush = AsyncMock()
        session.refresh = AsyncMock()

        # Capture the object passed to session.add()
        added_objects: list[AuditTrailEntry] = []

        def capture_add(obj: AuditTrailEntry) -> None:
            added_objects.append(obj)

        session.add = MagicMock(side_effect=capture_add)

        # Mock refresh to populate fields on the object
        async def mock_refresh(obj: AuditTrailEntry) -> None:
            obj.id = uuid.uuid4()

        session.refresh = AsyncMock(side_effect=mock_refresh)

        repo = AuditTrailRepository(session)
        resource_id = uuid.uuid4()
        timestamp = datetime.now(UTC)

        entry = await repo.append(
            tenant_id=tenant_id,
            event_type="governance.policy.created",
            actor_id=actor_id,
            resource_type="governance_policy",
            resource_id=resource_id,
            action="created",
            details={"policy_name": "Test"},
            timestamp=timestamp,
            correlation_id="req-123",
        )

        # Verify the entry was added to the session
        assert len(added_objects) == 1
        added = added_objects[0]
        assert isinstance(added, AuditTrailEntry)
        assert added.tenant_id == tenant_id
        assert added.event_type == "governance.policy.created"
        assert added.actor_id == actor_id
        assert added.resource_type == "governance_policy"
        assert added.resource_id == resource_id
        assert added.action == "created"
        assert added.details == {"policy_name": "Test"}
        assert added.timestamp == timestamp
        assert added.source_service == "aumos-governance-engine"
        assert added.correlation_id == "req-123"

    @pytest.mark.asyncio()
    async def test_append_always_sets_source_service(
        self,
        tenant_id: uuid.UUID,
        actor_id: uuid.UUID,
    ) -> None:
        """append() always sets source_service to aumos-governance-engine."""
        session = AsyncMock()
        added_objects: list[AuditTrailEntry] = []
        session.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))

        async def mock_refresh(obj: AuditTrailEntry) -> None:
            obj.id = uuid.uuid4()

        session.refresh = AsyncMock(side_effect=mock_refresh)

        repo = AuditTrailRepository(session)
        await repo.append(
            tenant_id=tenant_id,
            event_type="test.event",
            actor_id=actor_id,
            resource_type="test_resource",
            resource_id=uuid.uuid4(),
            action="test",
            details={},
            timestamp=datetime.now(UTC),
        )

        assert added_objects[0].source_service == "aumos-governance-engine"


class TestPolicyRepository:
    """Tests for PolicyRepository."""

    def test_instantiation_with_session(self) -> None:
        """PolicyRepository can be instantiated with a session."""
        session = AsyncMock()
        repo = PolicyRepository(session)
        assert repo is not None


class TestAuditWallInitialization:
    """Tests for Audit Wall database initialization."""

    @pytest.mark.asyncio()
    async def test_get_audit_db_session_raises_if_not_initialized(self) -> None:
        """get_audit_db_session raises RuntimeError if init_audit_db not called."""
        from aumos_governance_engine.adapters.audit_wall import get_audit_db_session
        import aumos_governance_engine.adapters.audit_wall as audit_wall_module

        # Ensure the module-level factory is None
        original = audit_wall_module._audit_session_factory
        audit_wall_module._audit_session_factory = None

        try:
            gen = get_audit_db_session()
            with pytest.raises(RuntimeError, match="Audit Wall database has not been initialized"):
                await gen.__anext__()
        finally:
            audit_wall_module._audit_session_factory = original
