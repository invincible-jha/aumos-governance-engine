"""Tests for core business logic services.

Tests PolicyService, ComplianceService, AuditService, EvidenceService,
and RegulationMapperService. Uses mock repositories and adapters.

Coverage target: >= 80% for core/ modules.
"""

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from aumos_common.errors import ValidationError

from aumos_governance_engine.core.services import (
    AuditService,
    ComplianceService,
    EvidenceService,
    PolicyService,
    RegulationMapperService,
    _SUPPORTED_REGULATIONS,
)
from tests.conftest import make_fake_evidence, make_fake_policy, make_fake_workflow


# ---------------------------------------------------------------------------
# PolicyService tests
# ---------------------------------------------------------------------------


class TestPolicyService:
    """Tests for PolicyService — policy lifecycle management."""

    def _make_service(
        self,
        policy_repo: AsyncMock | None = None,
        audit_service: Any | None = None,
        opa_client: AsyncMock | None = None,
        event_publisher: AsyncMock | None = None,
    ) -> PolicyService:
        """Construct a PolicyService with mock dependencies.

        Args:
            policy_repo: Mock policy repository.
            audit_service: Mock audit service.
            opa_client: Mock OPA client.
            event_publisher: Mock event publisher.

        Returns:
            PolicyService instance.
        """
        return PolicyService(
            policy_repo=policy_repo or AsyncMock(),
            audit_service=audit_service or AsyncMock(),
            opa_client=opa_client or AsyncMock(),
            event_publisher=event_publisher or AsyncMock(),
        )

    @pytest.mark.asyncio()
    async def test_create_policy_success(
        self,
        mock_tenant: MagicMock,
        mock_audit_repo: AsyncMock,
        mock_opa_client: AsyncMock,
        mock_event_publisher: AsyncMock,
    ) -> None:
        """Creating a valid OPA Rego policy returns a response with draft status."""
        policy_repo = AsyncMock()
        fake_policy = make_fake_policy(mock_tenant.tenant_id)
        policy_repo.create.return_value = fake_policy

        audit_service = AuditService(mock_audit_repo)
        service = self._make_service(
            policy_repo=policy_repo,
            audit_service=audit_service,
            opa_client=mock_opa_client,
            event_publisher=mock_event_publisher,
        )

        result = await service.create_policy(
            tenant=mock_tenant,
            name="Model Promotion Gate",
            policy_type="opa_rego",
            rego_content="package test\ndefault allow = true",
            description="Gate for model promotions",
            regulation_refs=["iso42001"],
            actor_id=mock_tenant.user_id,
        )

        assert result.name == fake_policy.name
        assert result.status == "draft"
        policy_repo.create.assert_called_once()
        mock_audit_repo.append.assert_called_once()
        mock_event_publisher.publish_policy_created.assert_called_once()

    @pytest.mark.asyncio()
    async def test_create_policy_missing_rego_raises_validation_error(
        self,
        mock_tenant: MagicMock,
    ) -> None:
        """Creating an opa_rego policy without rego_content raises ValidationError."""
        service = self._make_service()

        with pytest.raises(ValidationError):
            await service.create_policy(
                tenant=mock_tenant,
                name="Bad Policy",
                policy_type="opa_rego",
                rego_content=None,  # Missing — should raise
                description=None,
                regulation_refs=[],
                actor_id=mock_tenant.user_id,
            )

    @pytest.mark.asyncio()
    async def test_activate_policy_uploads_to_opa(
        self,
        mock_tenant: MagicMock,
        mock_audit_repo: AsyncMock,
        mock_opa_client: AsyncMock,
        mock_event_publisher: AsyncMock,
    ) -> None:
        """Activating a draft policy uploads the Rego bundle to OPA."""
        policy_repo = AsyncMock()
        fake_policy = make_fake_policy(mock_tenant.tenant_id, status="draft")
        active_policy = make_fake_policy(mock_tenant.tenant_id, status="active")
        policy_repo.get_by_id.return_value = fake_policy
        policy_repo.update_status.return_value = active_policy

        audit_service = AuditService(mock_audit_repo)
        service = self._make_service(
            policy_repo=policy_repo,
            audit_service=audit_service,
            opa_client=mock_opa_client,
            event_publisher=mock_event_publisher,
        )

        result = await service.activate_policy(
            policy_id=fake_policy.id,
            tenant=mock_tenant,
            actor_id=mock_tenant.user_id,
        )

        assert result.status == "active"
        mock_opa_client.upload_policy.assert_called_once_with(
            policy_id=fake_policy.id,
            rego_content=fake_policy.rego_content,
        )
        mock_audit_repo.append.assert_called_once()

    @pytest.mark.asyncio()
    async def test_activate_policy_already_active_raises_error(
        self,
        mock_tenant: MagicMock,
    ) -> None:
        """Activating an already-active policy raises ValidationError."""
        policy_repo = AsyncMock()
        active_policy = make_fake_policy(mock_tenant.tenant_id, status="active")
        policy_repo.get_by_id.return_value = active_policy

        service = self._make_service(policy_repo=policy_repo)

        with pytest.raises(ValidationError):
            await service.activate_policy(
                policy_id=active_policy.id,
                tenant=mock_tenant,
                actor_id=mock_tenant.user_id,
            )

    @pytest.mark.asyncio()
    async def test_evaluate_policy_returns_allow_decision(
        self,
        mock_tenant: MagicMock,
        mock_audit_repo: AsyncMock,
        mock_opa_client: AsyncMock,
        mock_event_publisher: AsyncMock,
    ) -> None:
        """Evaluating an active policy returns OPA allow/deny decision."""
        policy_repo = AsyncMock()
        active_policy = make_fake_policy(mock_tenant.tenant_id, status="active")
        policy_repo.get_by_id.return_value = active_policy
        mock_opa_client.evaluate.return_value = {
            "allow": True,
            "violations": [],
            "raw": {},
        }

        audit_service = AuditService(mock_audit_repo)
        service = self._make_service(
            policy_repo=policy_repo,
            audit_service=audit_service,
            opa_client=mock_opa_client,
            event_publisher=mock_event_publisher,
        )

        result = await service.evaluate_policy(
            policy_id=active_policy.id,
            input_data={"model": {"risk_level": "low"}},
            tenant=mock_tenant,
            actor_id=mock_tenant.user_id,
        )

        assert result.allowed is True
        assert result.violations == []
        assert result.policy_id == active_policy.id
        mock_opa_client.evaluate.assert_called_once()
        mock_audit_repo.append.assert_called_once()

    @pytest.mark.asyncio()
    async def test_evaluate_policy_not_active_raises_error(
        self,
        mock_tenant: MagicMock,
    ) -> None:
        """Evaluating a draft policy raises ValidationError."""
        policy_repo = AsyncMock()
        draft_policy = make_fake_policy(mock_tenant.tenant_id, status="draft")
        policy_repo.get_by_id.return_value = draft_policy

        service = self._make_service(policy_repo=policy_repo)

        with pytest.raises(ValidationError):
            await service.evaluate_policy(
                policy_id=draft_policy.id,
                input_data={},
                tenant=mock_tenant,
                actor_id=mock_tenant.user_id,
            )


# ---------------------------------------------------------------------------
# ComplianceService tests
# ---------------------------------------------------------------------------


class TestComplianceService:
    """Tests for ComplianceService — compliance workflow management."""

    def _make_service(
        self,
        workflow_repo: AsyncMock | None = None,
        audit_service: Any | None = None,
        event_publisher: AsyncMock | None = None,
    ) -> ComplianceService:
        """Construct a ComplianceService with mock dependencies."""
        return ComplianceService(
            workflow_repo=workflow_repo or AsyncMock(),
            audit_service=audit_service or AsyncMock(),
            event_publisher=event_publisher or AsyncMock(),
        )

    @pytest.mark.asyncio()
    async def test_create_workflow_success(
        self,
        mock_tenant: MagicMock,
        mock_audit_repo: AsyncMock,
        mock_event_publisher: AsyncMock,
    ) -> None:
        """Creating a workflow for a supported regulation returns initiated status."""
        workflow_repo = AsyncMock()
        fake_workflow = make_fake_workflow(mock_tenant.tenant_id, regulation="iso42001")
        workflow_repo.create.return_value = fake_workflow

        audit_service = AuditService(mock_audit_repo)
        service = self._make_service(
            workflow_repo=workflow_repo,
            audit_service=audit_service,
            event_publisher=mock_event_publisher,
        )

        result = await service.create_workflow(
            tenant=mock_tenant,
            regulation="iso42001",
            name="ISO 42001 Assessment 2026",
            next_due=None,
            assigned_to=None,
            notes=None,
            actor_id=mock_tenant.user_id,
        )

        assert result.regulation == "iso42001"
        assert result.status == "initiated"
        workflow_repo.create.assert_called_once()
        mock_audit_repo.append.assert_called_once()

    @pytest.mark.asyncio()
    async def test_create_workflow_unsupported_regulation(
        self,
        mock_tenant: MagicMock,
    ) -> None:
        """Creating a workflow for an unsupported regulation raises ValidationError."""
        service = self._make_service()

        with pytest.raises(ValidationError):
            await service.create_workflow(
                tenant=mock_tenant,
                regulation="gdpr",  # Not supported
                name="GDPR Assessment",
                next_due=None,
                assigned_to=None,
                notes=None,
                actor_id=mock_tenant.user_id,
            )

    @pytest.mark.asyncio()
    async def test_get_dashboard_aggregates_workflows(
        self,
        mock_tenant: MagicMock,
    ) -> None:
        """Dashboard returns per-regulation summaries."""
        workflow_repo = AsyncMock()
        workflow_repo.get_dashboard_summary.return_value = [
            {
                "regulation": "soc2",
                "total_workflows": 2,
                "attested_workflows": 1,
                "in_progress_workflows": 1,
                "total_evidence": 10,
                "compliance_score": 0.5,
                "last_assessment": datetime.now(UTC),
                "next_due": None,
            }
        ]

        service = self._make_service(workflow_repo=workflow_repo)
        result = await service.get_dashboard(tenant=mock_tenant)

        assert len(result.regulations) == 1
        assert result.regulations[0].regulation == "soc2"
        assert result.regulations[0].compliance_score == 0.5


# ---------------------------------------------------------------------------
# AuditService tests
# ---------------------------------------------------------------------------


class TestAuditService:
    """Tests for AuditService — immutable audit trail."""

    @pytest.mark.asyncio()
    async def test_record_appends_entry(
        self,
        mock_tenant: MagicMock,
        mock_audit_repo: AsyncMock,
        actor_id: uuid.UUID,
    ) -> None:
        """Recording an event appends an entry to the audit repository."""
        service = AuditService(mock_audit_repo)
        resource_id = uuid.uuid4()

        await service.record(
            tenant_id=mock_tenant.tenant_id,
            event_type="governance.policy.created",
            actor_id=actor_id,
            resource_type="governance_policy",
            resource_id=resource_id,
            action="created",
            details={"policy_name": "Test"},
        )

        mock_audit_repo.append.assert_called_once()
        call_kwargs = mock_audit_repo.append.call_args.kwargs
        assert call_kwargs["event_type"] == "governance.policy.created"
        assert call_kwargs["resource_type"] == "governance_policy"
        assert call_kwargs["action"] == "created"

    @pytest.mark.asyncio()
    async def test_audit_service_has_no_update_or_delete(self) -> None:
        """AuditService must not expose update or delete methods (immutability check)."""
        audit_repo = AsyncMock()
        service = AuditService(audit_repo)

        assert not hasattr(service, "update"), "AuditService must not have update() method"
        assert not hasattr(service, "delete"), "AuditService must not have delete() method"
        assert not hasattr(service, "remove"), "AuditService must not have remove() method"

    @pytest.mark.asyncio()
    async def test_query_trail_returns_entries(
        self,
        mock_tenant: MagicMock,
        mock_audit_repo: AsyncMock,
    ) -> None:
        """Querying the audit trail delegates to the repository."""
        mock_audit_repo.query.return_value = []
        service = AuditService(mock_audit_repo)

        result = await service.query_trail(tenant=mock_tenant)

        mock_audit_repo.query.assert_called_once()
        assert result == []


# ---------------------------------------------------------------------------
# EvidenceService tests
# ---------------------------------------------------------------------------


class TestEvidenceService:
    """Tests for EvidenceService — compliance evidence submission."""

    @pytest.mark.asyncio()
    async def test_submit_evidence_creates_record_and_increments_count(
        self,
        mock_tenant: MagicMock,
        mock_audit_repo: AsyncMock,
        mock_event_publisher: AsyncMock,
    ) -> None:
        """Submitting evidence creates a record and increments workflow count."""
        evidence_repo = AsyncMock()
        workflow_repo = AsyncMock()
        workflow_id = uuid.uuid4()
        fake_workflow = make_fake_workflow(mock_tenant.tenant_id)
        fake_evidence = make_fake_evidence(mock_tenant.tenant_id, workflow_id)

        workflow_repo.get_by_id.return_value = fake_workflow
        evidence_repo.create.return_value = fake_evidence
        workflow_repo.increment_evidence_count.return_value = None

        audit_service = AuditService(mock_audit_repo)
        service = EvidenceService(
            evidence_repo=evidence_repo,
            workflow_repo=workflow_repo,
            audit_service=audit_service,
            event_publisher=mock_event_publisher,
        )

        result = await service.submit_evidence(
            tenant=mock_tenant,
            workflow_id=workflow_id,
            evidence_type="audit_log",
            title="System Access Logs",
            description="90-day access log export",
            artifact_uri="s3://bucket/logs.json",
            collector="auto",
            control_ids=["CC6.1"],
            actor_id=mock_tenant.user_id,
        )

        assert result.evidence_type == "audit_log"
        evidence_repo.create.assert_called_once()
        workflow_repo.increment_evidence_count.assert_called_once_with(workflow_id, mock_tenant)
        mock_audit_repo.append.assert_called_once()
        mock_event_publisher.publish_evidence_submitted.assert_called_once()


# ---------------------------------------------------------------------------
# RegulationMapperService tests
# ---------------------------------------------------------------------------


class TestRegulationMapperService:
    """Tests for RegulationMapperService — regulation metadata and control mappings."""

    def test_list_regulations_returns_all_supported(self) -> None:
        """list_regulations returns all six supported regulations."""
        mapping_repo = AsyncMock()
        service = RegulationMapperService(mapping_repo=mapping_repo)

        result = service.list_regulations()

        codes = {r["code"] for r in result.regulations}
        assert "soc2" in codes
        assert "iso27001" in codes
        assert "hipaa" in codes
        assert "iso42001" in codes
        assert "eu_ai_act" in codes
        assert "fedramp" in codes
        assert len(result.regulations) == len(_SUPPORTED_REGULATIONS)

    @pytest.mark.asyncio()
    async def test_get_controls_returns_db_mappings_when_available(
        self,
        mock_tenant: MagicMock,
    ) -> None:
        """get_controls returns DB mappings when the repository has rows."""
        mapping_repo = AsyncMock()
        fake_mapping = MagicMock()
        fake_mapping.regulation = "soc2"
        fake_mapping.article_ref = "CC6.1"
        fake_mapping.requirement_text = "Logical access controls"
        fake_mapping.control_ids = ["ACCESS_CONTROL"]
        fake_mapping.automated = True
        fake_mapping.notes = None
        mapping_repo.list_by_regulation.return_value = [fake_mapping]

        service = RegulationMapperService(mapping_repo=mapping_repo)
        result = await service.get_controls(regulation="soc2", tenant=mock_tenant)

        assert len(result) == 1
        assert result[0].article_ref == "CC6.1"

    @pytest.mark.asyncio()
    async def test_get_controls_falls_back_to_static_when_db_empty(
        self,
        mock_tenant: MagicMock,
    ) -> None:
        """get_controls falls back to static baseline when DB returns no rows."""
        mapping_repo = AsyncMock()
        mapping_repo.list_by_regulation.return_value = []  # Empty DB

        service = RegulationMapperService(mapping_repo=mapping_repo)
        result = await service.get_controls(regulation="soc2", tenant=mock_tenant)

        # Should return static baseline controls
        assert len(result) > 0
        article_refs = {r.article_ref for r in result}
        assert "CC6.1" in article_refs

    @pytest.mark.asyncio()
    async def test_get_controls_unsupported_regulation_raises(
        self,
        mock_tenant: MagicMock,
    ) -> None:
        """get_controls with an unsupported regulation code raises ValidationError."""
        from aumos_common.errors import ValidationError

        mapping_repo = AsyncMock()
        service = RegulationMapperService(mapping_repo=mapping_repo)

        with pytest.raises(ValidationError):
            await service.get_controls(regulation="gdpr", tenant=mock_tenant)

    @pytest.mark.asyncio()
    async def test_get_controls_automated_only_filter(
        self,
        mock_tenant: MagicMock,
    ) -> None:
        """automated_only=True filters the static baseline to only automated controls."""
        mapping_repo = AsyncMock()
        mapping_repo.list_by_regulation.return_value = []  # Fall back to static

        service = RegulationMapperService(mapping_repo=mapping_repo)
        all_controls = await service.get_controls(regulation="soc2", tenant=mock_tenant)
        auto_controls = await service.get_controls(
            regulation="soc2", tenant=mock_tenant, automated_only=True
        )

        # All automated controls must be a subset of all controls
        auto_refs = {c.article_ref for c in auto_controls}
        all_refs = {c.article_ref for c in all_controls}
        assert auto_refs.issubset(all_refs)
        # All returned controls must have automated=True
        assert all(c.automated for c in auto_controls)
