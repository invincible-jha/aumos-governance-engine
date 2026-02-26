"""Test fixtures for aumos-governance-engine.

Provides:
- mock_tenant: A fake TenantContext for use in service and API tests
- mock_opa_client: A mock OPAClient that returns configurable results
- mock_event_publisher: A mock GovernanceEventPublisher that captures calls
- mock_audit_repo: A mock AuditTrailRepository that captures append() calls
- mock_policy_repo: A mock IPolicyRepository
- mock_workflow_repo: A mock IComplianceWorkflowRepository
- mock_evidence_repo: A mock IEvidenceRepository
- mock_mapping_repo: A mock IRegulationMappingRepository
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from aumos_common.auth import TenantContext


@pytest.fixture()
def tenant_id() -> uuid.UUID:
    """Return a fixed tenant UUID for consistent test assertions.

    Returns:
        A deterministic UUID for the test tenant.
    """
    return uuid.UUID("00000000-0000-0000-0000-000000000001")


@pytest.fixture()
def actor_id() -> uuid.UUID:
    """Return a fixed actor UUID for consistent test assertions.

    Returns:
        A deterministic UUID for the test actor (user).
    """
    return uuid.UUID("00000000-0000-0000-0000-000000000002")


@pytest.fixture()
def mock_tenant(tenant_id: uuid.UUID, actor_id: uuid.UUID) -> TenantContext:
    """Create a fake TenantContext for service and API tests.

    Args:
        tenant_id: Injected tenant UUID fixture.
        actor_id: Injected actor UUID fixture.

    Returns:
        A TenantContext instance with deterministic UUIDs.
    """
    tenant = MagicMock(spec=TenantContext)
    tenant.tenant_id = tenant_id
    tenant.user_id = actor_id
    return tenant


@pytest.fixture()
def mock_opa_client() -> AsyncMock:
    """Create a mock OPAClient that simulates successful evaluations.

    Returns:
        AsyncMock with evaluate returning allow=True and no violations.
    """
    client = AsyncMock()
    client.evaluate.return_value = {"allow": True, "violations": [], "raw": {}}
    client.upload_policy.return_value = None
    client.delete_policy.return_value = None
    client.health_check.return_value = True
    return client


@pytest.fixture()
def mock_event_publisher() -> AsyncMock:
    """Create a mock GovernanceEventPublisher that captures all calls.

    Returns:
        AsyncMock with all publish methods returning None.
    """
    publisher = AsyncMock()
    publisher.publish_policy_created.return_value = None
    publisher.publish_policy_activated.return_value = None
    publisher.publish_policy_evaluated.return_value = None
    publisher.publish_workflow_status_changed.return_value = None
    publisher.publish_evidence_submitted.return_value = None
    return publisher


@pytest.fixture()
def mock_audit_repo() -> AsyncMock:
    """Create a mock AuditTrailRepository.

    Returns:
        AsyncMock with append() returning a fake AuditTrailEntry.
    """
    repo = AsyncMock()
    fake_entry = MagicMock()
    fake_entry.id = uuid.uuid4()
    fake_entry.tenant_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    fake_entry.event_type = "governance.policy.created"
    fake_entry.timestamp = datetime.now(UTC)
    repo.append.return_value = fake_entry
    repo.query.return_value = []
    return repo


def make_fake_policy(
    tenant_id: uuid.UUID,
    name: str = "Test Policy",
    status: str = "draft",
    policy_type: str = "opa_rego",
    rego_content: str | None = "package test\n\ndefault allow = true",
    regulation_refs: list[str] | None = None,
) -> MagicMock:
    """Create a fake GovernancePolicy ORM object for tests.

    Args:
        tenant_id: Owning tenant UUID.
        name: Policy name.
        status: Policy status.
        policy_type: Engine type.
        rego_content: Rego source.
        regulation_refs: Associated regulation codes.

    Returns:
        MagicMock with policy-like attributes.
    """
    policy = MagicMock()
    policy.id = uuid.uuid4()
    policy.tenant_id = tenant_id
    policy.name = name
    policy.status = status
    policy.policy_type = policy_type
    policy.rego_content = rego_content
    policy.version = 1
    policy.regulation_refs = regulation_refs or []
    policy.description = None
    policy.created_at = datetime.now(UTC)
    policy.updated_at = datetime.now(UTC)
    return policy


def make_fake_workflow(
    tenant_id: uuid.UUID,
    regulation: str = "iso42001",
    status: str = "initiated",
    evidence_count: int = 0,
) -> MagicMock:
    """Create a fake ComplianceWorkflow ORM object for tests.

    Args:
        tenant_id: Owning tenant UUID.
        regulation: Regulation code.
        status: Workflow status.
        evidence_count: Denormalized evidence count.

    Returns:
        MagicMock with workflow-like attributes.
    """
    workflow = MagicMock()
    workflow.id = uuid.uuid4()
    workflow.tenant_id = tenant_id
    workflow.regulation = regulation
    workflow.name = f"{regulation.upper()} Assessment"
    workflow.status = status
    workflow.evidence_count = evidence_count
    workflow.last_assessment = None
    workflow.next_due = None
    workflow.assigned_to = None
    workflow.notes = None
    workflow.created_at = datetime.now(UTC)
    workflow.updated_at = datetime.now(UTC)
    return workflow


def make_fake_evidence(
    tenant_id: uuid.UUID,
    workflow_id: uuid.UUID,
) -> MagicMock:
    """Create a fake EvidenceRecord ORM object for tests.

    Args:
        tenant_id: Owning tenant UUID.
        workflow_id: Associated workflow UUID.

    Returns:
        MagicMock with evidence-like attributes.
    """
    evidence = MagicMock()
    evidence.id = uuid.uuid4()
    evidence.tenant_id = tenant_id
    evidence.workflow_id = workflow_id
    evidence.evidence_type = "audit_log"
    evidence.title = "Test Evidence"
    evidence.description = "Test evidence description"
    evidence.artifact_uri = "s3://bucket/test.json"
    evidence.collected_at = datetime.now(UTC)
    evidence.collector = "manual"
    evidence.control_ids = ["CC6.1"]
    evidence.status = "pending_review"
    evidence.reviewed_by = None
    evidence.reviewed_at = None
    evidence.created_at = datetime.now(UTC)
    evidence.updated_at = datetime.now(UTC)
    return evidence
