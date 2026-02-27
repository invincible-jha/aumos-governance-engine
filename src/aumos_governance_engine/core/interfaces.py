"""Abstract interfaces (Protocol classes) for the governance engine.

Defines the contracts between the service layer and the adapter layer using
Python's typing.Protocol. Services depend on these protocols — never on
concrete adapter implementations. This enables testing with mock adapters.

Protocols defined:
- IPolicyRepository
- IComplianceWorkflowRepository
- IAuditTrailRepository
- IEvidenceRepository
- IRegulationMappingRepository
- IOPAClient
- IGovernanceEventPublisher
- IConsentManager
- IDataResidencyEnforcer
- IComplianceReporter
"""

import uuid
from datetime import datetime
from typing import Any, Protocol

from aumos_common.auth import TenantContext

from aumos_governance_engine.core.models import (
    AuditTrailEntry,
    ComplianceWorkflow,
    EvidenceRecord,
    GovernancePolicy,
    RegulationMapping,
)


class IPolicyRepository(Protocol):
    """Repository contract for GovernancePolicy persistence."""

    async def create(
        self,
        tenant: TenantContext,
        name: str,
        policy_type: str,
        rego_content: str | None,
        description: str | None,
        regulation_refs: list[str],
    ) -> GovernancePolicy:
        """Create and persist a new governance policy.

        Args:
            tenant: The tenant context.
            name: Human-readable policy name.
            policy_type: Engine type — opa_rego or custom.
            rego_content: Rego source code (required for opa_rego policies).
            description: Optional description.
            regulation_refs: Regulation codes this policy implements.

        Returns:
            The persisted GovernancePolicy record.
        """
        ...

    async def get_by_id(self, policy_id: uuid.UUID, tenant: TenantContext) -> GovernancePolicy:
        """Retrieve a policy by ID.

        Args:
            policy_id: The policy UUID.
            tenant: The tenant context (enforces RLS).

        Returns:
            The GovernancePolicy record.

        Raises:
            NotFoundError: If no policy exists with the given ID for this tenant.
        """
        ...

    async def list_all(
        self,
        tenant: TenantContext,
        status_filter: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> list[GovernancePolicy]:
        """List policies for a tenant with optional status filter.

        Args:
            tenant: The tenant context.
            status_filter: Optional status to filter by (draft, active, deprecated, archived).
            page: Page number (1-indexed).
            page_size: Number of records per page.

        Returns:
            List of GovernancePolicy records.
        """
        ...

    async def update_status(
        self,
        policy_id: uuid.UUID,
        new_status: str,
        tenant: TenantContext,
    ) -> GovernancePolicy:
        """Update a policy's lifecycle status.

        Args:
            policy_id: The policy UUID.
            new_status: Target status.
            tenant: The tenant context.

        Returns:
            The updated GovernancePolicy.
        """
        ...


class IComplianceWorkflowRepository(Protocol):
    """Repository contract for ComplianceWorkflow persistence."""

    async def create(
        self,
        tenant: TenantContext,
        regulation: str,
        name: str,
        next_due: datetime | None = None,
        assigned_to: uuid.UUID | None = None,
        notes: str | None = None,
    ) -> ComplianceWorkflow:
        """Create a new compliance workflow.

        Args:
            tenant: The tenant context.
            regulation: Regulation code.
            name: Workflow name.
            next_due: Optional due date for first assessment action.
            assigned_to: Optional UUID of responsible user.
            notes: Optional notes.

        Returns:
            The persisted ComplianceWorkflow record.
        """
        ...

    async def get_by_id(
        self,
        workflow_id: uuid.UUID,
        tenant: TenantContext,
    ) -> ComplianceWorkflow:
        """Retrieve a workflow by ID.

        Args:
            workflow_id: The workflow UUID.
            tenant: The tenant context.

        Returns:
            The ComplianceWorkflow record.

        Raises:
            NotFoundError: If no workflow exists with the given ID.
        """
        ...

    async def list_all(
        self,
        tenant: TenantContext,
        regulation_filter: str | None = None,
        status_filter: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> list[ComplianceWorkflow]:
        """List workflows for a tenant.

        Args:
            tenant: The tenant context.
            regulation_filter: Optional regulation code to filter by.
            status_filter: Optional status to filter by.
            page: Page number (1-indexed).
            page_size: Number of records per page.

        Returns:
            List of ComplianceWorkflow records.
        """
        ...

    async def update_status(
        self,
        workflow_id: uuid.UUID,
        new_status: str,
        tenant: TenantContext,
    ) -> ComplianceWorkflow:
        """Update a workflow's lifecycle status.

        Args:
            workflow_id: The workflow UUID.
            new_status: Target status.
            tenant: The tenant context.

        Returns:
            The updated ComplianceWorkflow.
        """
        ...

    async def increment_evidence_count(
        self,
        workflow_id: uuid.UUID,
        tenant: TenantContext,
    ) -> None:
        """Atomically increment the denormalized evidence count.

        Args:
            workflow_id: The workflow UUID.
            tenant: The tenant context.
        """
        ...

    async def get_dashboard_summary(
        self,
        tenant: TenantContext,
    ) -> list[dict[str, Any]]:
        """Aggregate compliance status across all regulations for a tenant.

        Args:
            tenant: The tenant context.

        Returns:
            List of dicts with regulation, status counts, and compliance score.
        """
        ...


class IAuditTrailRepository(Protocol):
    """Repository contract for AuditTrailEntry — APPEND-ONLY, no update/delete.

    IMPORTANT: This protocol intentionally omits update() and delete() methods.
    The audit trail is immutable. Implementations must enforce this at the
    database level (INSERT-only credentials on the audit DB).
    """

    async def append(
        self,
        tenant_id: uuid.UUID,
        event_type: str,
        actor_id: uuid.UUID,
        resource_type: str,
        resource_id: uuid.UUID,
        action: str,
        details: dict[str, Any],
        timestamp: datetime,
        correlation_id: str | None = None,
    ) -> AuditTrailEntry:
        """Append an immutable audit trail entry.

        This is the ONLY write operation on the audit trail. There is no
        update() or delete() method. Once written, entries are permanent.

        Args:
            tenant_id: The owning tenant UUID.
            event_type: Dot-notation event type.
            actor_id: UUID of the actor performing the action.
            resource_type: Type of the affected resource.
            resource_id: UUID of the affected resource.
            action: Short action verb.
            details: Structured event-specific payload.
            timestamp: Event timestamp (UTC).
            correlation_id: Optional request correlation ID.

        Returns:
            The persisted AuditTrailEntry.
        """
        ...

    async def query(
        self,
        tenant: TenantContext,
        event_type_filter: str | None = None,
        resource_type_filter: str | None = None,
        resource_id_filter: uuid.UUID | None = None,
        actor_id_filter: uuid.UUID | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[AuditTrailEntry]:
        """Query the immutable audit trail with filters.

        Args:
            tenant: The tenant context (enforces tenant isolation).
            event_type_filter: Optional event type prefix filter.
            resource_type_filter: Optional resource type filter.
            resource_id_filter: Optional specific resource UUID filter.
            actor_id_filter: Optional actor UUID filter.
            start_time: Optional start of time range.
            end_time: Optional end of time range.
            page: Page number (1-indexed).
            page_size: Number of records per page.

        Returns:
            List of AuditTrailEntry records (read-only).
        """
        ...


class IEvidenceRepository(Protocol):
    """Repository contract for EvidenceRecord persistence."""

    async def create(
        self,
        tenant: TenantContext,
        workflow_id: uuid.UUID,
        evidence_type: str,
        title: str,
        description: str,
        artifact_uri: str | None,
        collected_at: datetime,
        collector: str,
        control_ids: list[str],
    ) -> EvidenceRecord:
        """Create and persist a new evidence record.

        Args:
            tenant: The tenant context.
            workflow_id: The associated workflow UUID.
            evidence_type: Evidence type classification.
            title: Short title.
            description: Detailed description.
            artifact_uri: Optional storage URI.
            collected_at: Collection timestamp.
            collector: auto or manual.
            control_ids: List of control IDs satisfied.

        Returns:
            The persisted EvidenceRecord.
        """
        ...

    async def list_by_workflow(
        self,
        workflow_id: uuid.UUID,
        tenant: TenantContext,
        page: int = 1,
        page_size: int = 20,
    ) -> list[EvidenceRecord]:
        """List evidence records for a specific workflow.

        Args:
            workflow_id: The workflow UUID.
            tenant: The tenant context.
            page: Page number.
            page_size: Records per page.

        Returns:
            List of EvidenceRecord records.
        """
        ...


class IRegulationMappingRepository(Protocol):
    """Repository contract for RegulationMapping read operations."""

    async def list_by_regulation(
        self,
        regulation: str,
        tenant: TenantContext,
        automated_only: bool = False,
    ) -> list[RegulationMapping]:
        """List all control mappings for a regulation.

        Includes both platform-wide and tenant-specific mappings, with
        tenant-specific mappings taking precedence.

        Args:
            regulation: The regulation code.
            tenant: The tenant context.
            automated_only: If True, return only automatically-assessable controls.

        Returns:
            List of RegulationMapping records.
        """
        ...


class IOPAClient(Protocol):
    """Client contract for OPA (Open Policy Agent) REST API integration."""

    async def evaluate(
        self,
        policy_id: uuid.UUID,
        input_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate a policy against input data.

        Args:
            policy_id: The policy UUID (used to construct the OPA path).
            input_data: Structured JSON input for the Rego policy.

        Returns:
            OPA evaluation result dict — includes allow, violations, etc.

        Raises:
            PolicyEvaluationError: If OPA returns an error or times out.
        """
        ...

    async def upload_policy(
        self,
        policy_id: uuid.UUID,
        rego_content: str,
    ) -> None:
        """Upload a Rego policy bundle to OPA.

        Args:
            policy_id: The policy UUID (used as the bundle path).
            rego_content: Full Rego source code to upload.

        Raises:
            PolicyUploadError: If OPA rejects the bundle.
        """
        ...

    async def delete_policy(self, policy_id: uuid.UUID) -> None:
        """Remove a policy bundle from OPA.

        Args:
            policy_id: The policy UUID to remove.
        """
        ...

    async def health_check(self) -> bool:
        """Check if OPA is reachable and healthy.

        Returns:
            True if OPA is healthy, False otherwise.
        """
        ...


class IGovernanceEventPublisher(Protocol):
    """Event publisher contract for governance domain events."""

    async def publish_policy_created(
        self,
        tenant_id: uuid.UUID,
        policy_id: uuid.UUID,
        policy_name: str,
        policy_type: str,
        regulation_refs: list[str],
        correlation_id: str | None = None,
    ) -> None:
        """Publish a policy.created event.

        Args:
            tenant_id: Owning tenant UUID.
            policy_id: New policy UUID.
            policy_name: Policy name.
            policy_type: Policy engine type.
            regulation_refs: Associated regulation codes.
            correlation_id: Optional request correlation ID.
        """
        ...

    async def publish_policy_activated(
        self,
        tenant_id: uuid.UUID,
        policy_id: uuid.UUID,
        policy_name: str,
        correlation_id: str | None = None,
    ) -> None:
        """Publish a policy.activated event.

        Args:
            tenant_id: Owning tenant UUID.
            policy_id: Activated policy UUID.
            policy_name: Policy name.
            correlation_id: Optional request correlation ID.
        """
        ...

    async def publish_policy_evaluated(
        self,
        tenant_id: uuid.UUID,
        policy_id: uuid.UUID,
        evaluation_result: bool,
        latency_ms: float,
        correlation_id: str | None = None,
    ) -> None:
        """Publish a policy.evaluated event.

        Args:
            tenant_id: Owning tenant UUID.
            policy_id: Evaluated policy UUID.
            evaluation_result: True if policy allowed the action.
            latency_ms: Evaluation latency in milliseconds.
            correlation_id: Optional request correlation ID.
        """
        ...

    async def publish_workflow_status_changed(
        self,
        tenant_id: uuid.UUID,
        workflow_id: uuid.UUID,
        regulation: str,
        old_status: str,
        new_status: str,
        correlation_id: str | None = None,
    ) -> None:
        """Publish a compliance.workflow.status_changed event.

        Args:
            tenant_id: Owning tenant UUID.
            workflow_id: Workflow UUID.
            regulation: Regulation code.
            old_status: Previous status.
            new_status: New status.
            correlation_id: Optional request correlation ID.
        """
        ...

    async def publish_evidence_submitted(
        self,
        tenant_id: uuid.UUID,
        evidence_id: uuid.UUID,
        workflow_id: uuid.UUID,
        evidence_type: str,
        collector: str,
        correlation_id: str | None = None,
    ) -> None:
        """Publish an evidence.submitted event.

        Args:
            tenant_id: Owning tenant UUID.
            evidence_id: Evidence record UUID.
            workflow_id: Associated workflow UUID.
            evidence_type: Evidence type classification.
            collector: auto or manual.
            correlation_id: Optional request correlation ID.
        """
        ...


class IConsentManager(Protocol):
    """Contract for the consent lifecycle management adapter.

    Manages data subject consent records including capture, verification,
    withdrawal, and expiry. Integrates with GDPR Article 7 obligations.
    """

    async def record_consent(
        self,
        tenant_id: uuid.UUID,
        subject_id: str,
        purpose: str,
        legal_basis: str,
        granted: bool,
        expiry_days: int | None,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """Record a consent decision for a data subject.

        Args:
            tenant_id: Owning tenant UUID.
            subject_id: Opaque data subject identifier (hashed or pseudonymous).
            purpose: Processing purpose (e.g., 'analytics', 'marketing').
            legal_basis: GDPR legal basis (e.g., 'consent', 'legitimate_interest').
            granted: True if consent was given, False if withdrawn.
            expiry_days: Optional days until consent expires. None = no expiry.
            metadata: Additional consent context (channel, version, etc.).

        Returns:
            Consent record dict with id, tenant_id, subject_id, purpose,
            granted, captured_at, and expires_at.
        """
        ...

    async def verify_consent(
        self,
        tenant_id: uuid.UUID,
        subject_id: str,
        purpose: str,
    ) -> dict[str, Any]:
        """Verify whether a data subject has active consent for a purpose.

        Args:
            tenant_id: Owning tenant UUID.
            subject_id: Opaque data subject identifier.
            purpose: Processing purpose to verify.

        Returns:
            Verification dict with has_consent, granted_at, expires_at,
            withdrawal_at, and legal_basis.
        """
        ...

    async def withdraw_consent(
        self,
        tenant_id: uuid.UUID,
        subject_id: str,
        purpose: str,
        reason: str | None,
    ) -> dict[str, Any]:
        """Record a consent withdrawal for a data subject and purpose.

        Args:
            tenant_id: Owning tenant UUID.
            subject_id: Opaque data subject identifier.
            purpose: Processing purpose to withdraw consent from.
            reason: Optional reason for withdrawal.

        Returns:
            Updated consent record dict with withdrawal_at populated.
        """
        ...

    async def get_audit_trail(
        self,
        tenant_id: uuid.UUID,
        subject_id: str,
    ) -> list[dict[str, Any]]:
        """Retrieve the full consent history for a data subject.

        Args:
            tenant_id: Owning tenant UUID.
            subject_id: Opaque data subject identifier.

        Returns:
            List of consent event dicts ordered by captured_at descending.
        """
        ...


class IDataResidencyEnforcer(Protocol):
    """Contract for the data residency enforcement adapter.

    Evaluates data movement requests against tenant residency policies and
    jurisdiction-specific transfer restrictions (GDPR Chapter V, etc.).
    """

    async def check_transfer(
        self,
        tenant_id: uuid.UUID,
        source_region: str,
        destination_region: str,
        data_classification: str,
        data_categories: list[str],
    ) -> dict[str, Any]:
        """Check whether a data transfer complies with residency policy.

        Args:
            tenant_id: Owning tenant UUID.
            source_region: ISO 3166-1 alpha-2 country or region code of origin.
            destination_region: ISO 3166-1 alpha-2 destination country or region.
            data_classification: Data sensitivity classification (public/internal/
                confidential/restricted).
            data_categories: List of GDPR special category indicators or
                general data type labels.

        Returns:
            Dict with allowed (bool), transfer_mechanism, blocking_restrictions,
            required_safeguards, and jurisdiction_requirements.
        """
        ...

    async def get_policy(
        self,
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Retrieve the data residency policy for a tenant.

        Args:
            tenant_id: Owning tenant UUID.

        Returns:
            Policy dict with allowed_regions, restricted_regions, and
            default_transfer_mechanism.
        """
        ...

    async def validate_storage_location(
        self,
        tenant_id: uuid.UUID,
        region: str,
        data_classification: str,
    ) -> dict[str, Any]:
        """Validate that a storage region complies with tenant policy.

        Args:
            tenant_id: Owning tenant UUID.
            region: Proposed storage region code.
            data_classification: Classification of the data to store.

        Returns:
            Dict with compliant (bool), violations, and recommended_alternatives.
        """
        ...


class IComplianceReporter(Protocol):
    """Contract for the compliance report generation adapter.

    Generates structured compliance status reports suitable for submission
    to auditors, regulators, and internal governance boards.
    """

    async def generate_report(
        self,
        tenant_id: uuid.UUID,
        regulation: str,
        workflow_ids: list[uuid.UUID],
        report_format: str,
        include_evidence: bool,
    ) -> dict[str, Any]:
        """Generate a compliance status report for a regulation.

        Args:
            tenant_id: Owning tenant UUID.
            regulation: Regulation code (soc2, iso27001, hipaa, iso42001,
                eu_ai_act, fedramp).
            workflow_ids: Specific workflow UUIDs to include. Empty = all.
            report_format: Output format ('json', 'pdf', 'csv').
            include_evidence: Whether to embed evidence artifact links.

        Returns:
            Report dict with regulation, generated_at, summary, controls,
            evidence_count, compliance_score, and download_uri.
        """
        ...

    async def get_control_status(
        self,
        tenant_id: uuid.UUID,
        regulation: str,
        control_id: str,
    ) -> dict[str, Any]:
        """Get the current status of a specific compliance control.

        Args:
            tenant_id: Owning tenant UUID.
            regulation: Regulation code.
            control_id: Control identifier.

        Returns:
            Dict with control_id, status (passed/failed/not_assessed),
            evidence_count, last_assessed, and automated.
        """
        ...

    async def get_readiness_score(
        self,
        tenant_id: uuid.UUID,
        regulation: str,
    ) -> dict[str, Any]:
        """Compute an overall compliance readiness score for a regulation.

        Args:
            tenant_id: Owning tenant UUID.
            regulation: Regulation code.

        Returns:
            Dict with regulation, score (0.0-1.0), breakdown_by_domain,
            blocking_gaps, and recommendations.
        """
        ...
