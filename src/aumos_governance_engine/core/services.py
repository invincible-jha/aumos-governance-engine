"""Core business logic services for the governance engine.

Five service classes:
- PolicyService: Governance policy lifecycle — create, activate, evaluate
- ComplianceService: Compliance workflow management and dashboard
- AuditService: Append-only audit trail write orchestration
- EvidenceService: Evidence record submission and retrieval
- RegulationMapperService: Regulation-to-control mapping and static metadata

All services are async-first. They accept injected repositories and adapters
through their constructors, contain no framework code, and publish Kafka events
after every state-changing operation. Audit trail writes happen in AuditService,
which is always called from PolicyService and ComplianceService after mutations.
"""

import time
import uuid
from datetime import UTC, datetime
from typing import Any

from aumos_common.auth import TenantContext
from aumos_common.errors import NotFoundError, ValidationError
from aumos_common.observability import get_logger

from aumos_governance_engine.api.schemas import (
    ComplianceDashboardResponse,
    ComplianceDashboardRegulationSummary,
    ComplianceWorkflowResponse,
    EvidenceRecordResponse,
    GovernancePolicyResponse,
    PolicyEvaluateResponse,
    RegulationControlResponse,
    RegulationListResponse,
)
from aumos_governance_engine.core.interfaces import (
    IAuditTrailRepository,
    IComplianceWorkflowRepository,
    IComplianceReporter,
    IConsentManager,
    IDataResidencyEnforcer,
    IEvidenceRepository,
    IGovernanceEventPublisher,
    IOPAClient,
    IPolicyRepository,
    IRegulationMappingRepository,
)
from aumos_governance_engine.core.models import (
    AuditTrailEntry,
    ComplianceWorkflow,
    EvidenceRecord,
    GovernancePolicy,
)

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Supported regulation metadata (static — drives RegulationMapperService)
# ---------------------------------------------------------------------------

_SUPPORTED_REGULATIONS: list[dict[str, Any]] = [
    {
        "code": "soc2",
        "name": "SOC 2 Type II",
        "full_name": "Service Organization Controls 2 Type II",
        "issuing_body": "AICPA",
        "scope": "Security, Availability, Processing Integrity, Confidentiality, Privacy",
        "ai_specific": False,
    },
    {
        "code": "iso27001",
        "name": "ISO 27001:2022",
        "full_name": "Information Security Management Systems — Requirements",
        "issuing_body": "ISO/IEC",
        "scope": "Information security management",
        "ai_specific": False,
    },
    {
        "code": "hipaa",
        "name": "HIPAA",
        "full_name": "Health Insurance Portability and Accountability Act",
        "issuing_body": "HHS (US)",
        "scope": "Healthcare data protection and patient privacy",
        "ai_specific": False,
    },
    {
        "code": "iso42001",
        "name": "ISO 42001:2023",
        "full_name": "Artificial Intelligence — Management System",
        "issuing_body": "ISO/IEC",
        "scope": "AI management systems — responsible AI governance",
        "ai_specific": True,
    },
    {
        "code": "eu_ai_act",
        "name": "EU AI Act",
        "full_name": "Regulation on Artificial Intelligence (EU) 2024/1689",
        "issuing_body": "European Parliament and Council",
        "scope": "AI system risk classification, obligations by risk tier",
        "ai_specific": True,
    },
    {
        "code": "fedramp",
        "name": "FedRAMP Moderate",
        "full_name": "Federal Risk and Authorization Management Program — Moderate Baseline",
        "issuing_body": "GSA (US Federal)",
        "scope": "Cloud services for US federal agencies",
        "ai_specific": False,
    },
]

# Static control samples per regulation (used as fallback when DB has no rows)
_STATIC_CONTROL_SAMPLES: dict[str, list[dict[str, Any]]] = {
    "soc2": [
        {
            "article_ref": "CC6.1",
            "requirement_text": "Logical and physical access controls to meet the entity's objectives",
            "control_ids": ["ACCESS_CONTROL", "AUTH_MFA", "RBAC"],
            "automated": True,
        },
        {
            "article_ref": "CC7.2",
            "requirement_text": "Monitor system components for anomalies that indicate malicious acts",
            "control_ids": ["ANOMALY_DETECTION", "SIEM_ALERTING"],
            "automated": True,
        },
        {
            "article_ref": "CC9.2",
            "requirement_text": "Vendor risk management and third-party assessments",
            "control_ids": ["VENDOR_MGMT", "THIRD_PARTY_ASSESSMENT"],
            "automated": False,
        },
    ],
    "iso27001": [
        {
            "article_ref": "A.8.1",
            "requirement_text": "Inventory of assets — identify and maintain an inventory of information assets",
            "control_ids": ["ASSET_INVENTORY", "DATA_CLASSIFICATION"],
            "automated": True,
        },
        {
            "article_ref": "A.9.2",
            "requirement_text": "User access management — formal registration and deregistration process",
            "control_ids": ["USER_PROVISIONING", "ACCESS_REVIEW"],
            "automated": False,
        },
    ],
    "hipaa": [
        {
            "article_ref": "164.312(a)(1)",
            "requirement_text": "Access Control — assign a unique identifier to each user",
            "control_ids": ["UNIQUE_USER_ID", "ACCESS_CONTROL"],
            "automated": True,
        },
        {
            "article_ref": "164.312(b)",
            "requirement_text": "Audit Controls — hardware, software, and procedural mechanisms to examine activity",
            "control_ids": ["AUDIT_LOGGING", "LOG_RETENTION"],
            "automated": True,
        },
    ],
    "iso42001": [
        {
            "article_ref": "6.1",
            "requirement_text": "Actions to address risks and opportunities in AI management",
            "control_ids": ["AI_RISK_ASSESSMENT", "AI_IMPACT_ANALYSIS"],
            "automated": True,
        },
        {
            "article_ref": "9.1",
            "requirement_text": "Monitoring, measurement, analysis and evaluation of AI system performance",
            "control_ids": ["MODEL_MONITORING", "DRIFT_DETECTION", "BIAS_DETECTION"],
            "automated": True,
        },
        {
            "article_ref": "8.4",
            "requirement_text": "System impact assessment for AI systems",
            "control_ids": ["AI_IMPACT_ASSESSMENT", "EXPLAINABILITY_REPORT"],
            "automated": False,
        },
    ],
    "eu_ai_act": [
        {
            "article_ref": "Art. 9",
            "requirement_text": "Risk management system for high-risk AI systems",
            "control_ids": ["AI_RISK_MGMT", "RISK_CLASSIFICATION"],
            "automated": True,
        },
        {
            "article_ref": "Art. 13",
            "requirement_text": "Transparency and provision of information to deployers",
            "control_ids": ["MODEL_CARD", "SYSTEM_CARD", "EXPLAINABILITY"],
            "automated": False,
        },
        {
            "article_ref": "Art. 17",
            "requirement_text": "Quality management system for high-risk AI providers",
            "control_ids": ["MLOPS_LIFECYCLE", "MODEL_VERSIONING", "DATA_GOVERNANCE"],
            "automated": True,
        },
    ],
    "fedramp": [
        {
            "article_ref": "AC-2",
            "requirement_text": "Account Management — manage information system accounts",
            "control_ids": ["ACCOUNT_MGMT", "USER_PROVISIONING"],
            "automated": True,
        },
        {
            "article_ref": "AU-2",
            "requirement_text": "Audit Events — determine which events require auditing",
            "control_ids": ["AUDIT_EVENTS", "AUDIT_LOGGING"],
            "automated": True,
        },
    ],
}


class PolicyService:
    """Governance policy lifecycle management.

    Handles creation, versioning, activation, and OPA-based evaluation of
    governance policies. After every state-changing operation, writes an
    AuditTrailEntry and publishes a Kafka event.

    Args:
        policy_repo: Repository for GovernancePolicy persistence.
        audit_service: Service for writing immutable audit trail entries.
        opa_client: OPA REST API client for bundle management.
        event_publisher: Kafka event publisher.
    """

    def __init__(
        self,
        policy_repo: IPolicyRepository,
        audit_service: "AuditService",
        opa_client: IOPAClient,
        event_publisher: IGovernanceEventPublisher,
    ) -> None:
        """Initialize PolicyService with injected dependencies.

        Args:
            policy_repo: Repository implementing IPolicyRepository.
            audit_service: AuditService for writing audit trail entries.
            opa_client: Client implementing IOPAClient.
            event_publisher: Publisher implementing IGovernanceEventPublisher.
        """
        self._policy_repo = policy_repo
        self._audit_service = audit_service
        self._opa_client = opa_client
        self._event_publisher = event_publisher

    async def create_policy(
        self,
        tenant: TenantContext,
        name: str,
        policy_type: str,
        rego_content: str | None,
        description: str | None,
        regulation_refs: list[str],
        actor_id: uuid.UUID,
        correlation_id: str | None = None,
    ) -> GovernancePolicyResponse:
        """Create a new governance policy in draft status.

        Args:
            tenant: The tenant context.
            name: Human-readable policy name.
            policy_type: Engine type — opa_rego or custom.
            rego_content: Rego source code (required for opa_rego).
            description: Optional description.
            regulation_refs: Regulation codes this policy implements.
            actor_id: UUID of the user creating the policy.
            correlation_id: Optional request correlation ID.

        Returns:
            The created GovernancePolicyResponse.

        Raises:
            ValidationError: If policy_type is opa_rego but rego_content is absent.
        """
        if policy_type == "opa_rego" and not rego_content:
            raise ValidationError(
                message="rego_content is required when policy_type is opa_rego",
                field="rego_content",
            )

        logger.info(
            "Creating governance policy",
            tenant_id=str(tenant.tenant_id),
            policy_name=name,
            policy_type=policy_type,
        )

        policy = await self._policy_repo.create(
            tenant=tenant,
            name=name,
            policy_type=policy_type,
            rego_content=rego_content,
            description=description,
            regulation_refs=regulation_refs,
        )

        # Write immutable audit entry
        await self._audit_service.record(
            tenant_id=tenant.tenant_id,
            event_type="governance.policy.created",
            actor_id=actor_id,
            resource_type="governance_policy",
            resource_id=policy.id,
            action="created",
            details={
                "policy_name": name,
                "policy_type": policy_type,
                "regulation_refs": regulation_refs,
                "version": policy.version,
            },
            correlation_id=correlation_id,
        )

        # Publish Kafka event
        await self._event_publisher.publish_policy_created(
            tenant_id=tenant.tenant_id,
            policy_id=policy.id,
            policy_name=name,
            policy_type=policy_type,
            regulation_refs=regulation_refs,
            correlation_id=correlation_id,
        )

        logger.info(
            "Governance policy created",
            policy_id=str(policy.id),
            tenant_id=str(tenant.tenant_id),
        )

        return _policy_to_response(policy)

    async def get_policy(
        self,
        policy_id: uuid.UUID,
        tenant: TenantContext,
    ) -> GovernancePolicyResponse:
        """Get a governance policy by ID.

        Args:
            policy_id: The policy UUID.
            tenant: The tenant context.

        Returns:
            The GovernancePolicyResponse.

        Raises:
            NotFoundError: If the policy does not exist for this tenant.
        """
        policy = await self._policy_repo.get_by_id(policy_id, tenant)
        return _policy_to_response(policy)

    async def list_policies(
        self,
        tenant: TenantContext,
        status_filter: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> list[GovernancePolicyResponse]:
        """List governance policies for a tenant.

        Args:
            tenant: The tenant context.
            status_filter: Optional status to filter by.
            page: Page number.
            page_size: Records per page.

        Returns:
            List of GovernancePolicyResponse.
        """
        policies = await self._policy_repo.list_all(tenant, status_filter, page, page_size)
        return [_policy_to_response(p) for p in policies]

    async def activate_policy(
        self,
        policy_id: uuid.UUID,
        tenant: TenantContext,
        actor_id: uuid.UUID,
        correlation_id: str | None = None,
    ) -> GovernancePolicyResponse:
        """Activate a policy — uploads Rego bundle to OPA and sets status to active.

        Args:
            policy_id: The policy UUID to activate.
            tenant: The tenant context.
            actor_id: UUID of the user activating the policy.
            correlation_id: Optional request correlation ID.

        Returns:
            The updated GovernancePolicyResponse.

        Raises:
            NotFoundError: If the policy does not exist.
            ValidationError: If the policy is not in draft status or has no rego_content.
        """
        policy = await self._policy_repo.get_by_id(policy_id, tenant)

        if policy.status not in ("draft", "deprecated"):
            raise ValidationError(
                message=f"Cannot activate policy in status '{policy.status}'. Expected draft or deprecated.",
                field="status",
            )

        if policy.policy_type == "opa_rego" and not policy.rego_content:
            raise ValidationError(
                message="Cannot activate policy — rego_content is missing.",
                field="rego_content",
            )

        # Upload to OPA if Rego policy
        if policy.policy_type == "opa_rego" and policy.rego_content:
            logger.info("Uploading policy bundle to OPA", policy_id=str(policy_id))
            await self._opa_client.upload_policy(
                policy_id=policy_id,
                rego_content=policy.rego_content,
            )

        policy = await self._policy_repo.update_status(policy_id, "active", tenant)

        await self._audit_service.record(
            tenant_id=tenant.tenant_id,
            event_type="governance.policy.activated",
            actor_id=actor_id,
            resource_type="governance_policy",
            resource_id=policy_id,
            action="activated",
            details={"policy_name": policy.name, "policy_type": policy.policy_type},
            correlation_id=correlation_id,
        )

        await self._event_publisher.publish_policy_activated(
            tenant_id=tenant.tenant_id,
            policy_id=policy_id,
            policy_name=policy.name,
            correlation_id=correlation_id,
        )

        logger.info("Policy activated", policy_id=str(policy_id), tenant_id=str(tenant.tenant_id))
        return _policy_to_response(policy)

    async def evaluate_policy(
        self,
        policy_id: uuid.UUID,
        input_data: dict[str, Any],
        tenant: TenantContext,
        actor_id: uuid.UUID,
        correlation_id: str | None = None,
    ) -> PolicyEvaluateResponse:
        """Evaluate a governance policy against structured input data.

        Args:
            policy_id: The policy UUID to evaluate.
            input_data: Structured JSON input for the Rego policy.
            tenant: The tenant context.
            actor_id: UUID of the caller.
            correlation_id: Optional request correlation ID.

        Returns:
            PolicyEvaluateResponse with allow decision and violations.

        Raises:
            NotFoundError: If the policy does not exist.
            ValidationError: If the policy is not active.
        """
        policy = await self._policy_repo.get_by_id(policy_id, tenant)

        if policy.status != "active":
            raise ValidationError(
                message=f"Cannot evaluate policy in status '{policy.status}'. Policy must be active.",
                field="status",
            )

        logger.info(
            "Evaluating policy",
            policy_id=str(policy_id),
            tenant_id=str(tenant.tenant_id),
        )

        start_time = time.monotonic()
        result = await self._opa_client.evaluate(policy_id=policy_id, input_data=input_data)
        latency_ms = (time.monotonic() - start_time) * 1000

        allowed: bool = result.get("allow", False)
        violations: list[str] = result.get("violations", [])

        await self._audit_service.record(
            tenant_id=tenant.tenant_id,
            event_type="governance.policy.evaluated",
            actor_id=actor_id,
            resource_type="governance_policy",
            resource_id=policy_id,
            action="evaluated",
            details={
                "allowed": allowed,
                "violations_count": len(violations),
                "latency_ms": round(latency_ms, 2),
            },
            correlation_id=correlation_id,
        )

        await self._event_publisher.publish_policy_evaluated(
            tenant_id=tenant.tenant_id,
            policy_id=policy_id,
            evaluation_result=allowed,
            latency_ms=latency_ms,
            correlation_id=correlation_id,
        )

        return PolicyEvaluateResponse(
            policy_id=policy_id,
            policy_name=policy.name,
            allowed=allowed,
            violations=violations,
            latency_ms=round(latency_ms, 2),
            evaluated_at=datetime.now(UTC),
        )


class ComplianceService:
    """Compliance workflow management and dashboard aggregation.

    Manages the lifecycle of compliance assessments across multiple regulations.
    Integrates with AuditService to record all state transitions.

    Args:
        workflow_repo: Repository for ComplianceWorkflow persistence.
        audit_service: Service for writing audit trail entries.
        event_publisher: Kafka event publisher.
    """

    def __init__(
        self,
        workflow_repo: IComplianceWorkflowRepository,
        audit_service: "AuditService",
        event_publisher: IGovernanceEventPublisher,
    ) -> None:
        """Initialize ComplianceService with injected dependencies.

        Args:
            workflow_repo: Repository implementing IComplianceWorkflowRepository.
            audit_service: AuditService for writing audit trail entries.
            event_publisher: Publisher implementing IGovernanceEventPublisher.
        """
        self._workflow_repo = workflow_repo
        self._audit_service = audit_service
        self._event_publisher = event_publisher

    async def create_workflow(
        self,
        tenant: TenantContext,
        regulation: str,
        name: str,
        next_due: datetime | None,
        assigned_to: uuid.UUID | None,
        notes: str | None,
        actor_id: uuid.UUID,
        correlation_id: str | None = None,
    ) -> ComplianceWorkflowResponse:
        """Create a new compliance workflow.

        Args:
            tenant: The tenant context.
            regulation: Regulation code.
            name: Workflow name.
            next_due: Optional due date.
            assigned_to: Optional responsible user UUID.
            notes: Optional notes.
            actor_id: UUID of the user creating the workflow.
            correlation_id: Optional request correlation ID.

        Returns:
            The created ComplianceWorkflowResponse.

        Raises:
            ValidationError: If the regulation code is not supported.
        """
        supported_codes = {r["code"] for r in _SUPPORTED_REGULATIONS}
        if regulation not in supported_codes:
            raise ValidationError(
                message=f"Unsupported regulation '{regulation}'. Supported: {sorted(supported_codes)}",
                field="regulation",
            )

        logger.info(
            "Creating compliance workflow",
            tenant_id=str(tenant.tenant_id),
            regulation=regulation,
            name=name,
        )

        workflow = await self._workflow_repo.create(
            tenant=tenant,
            regulation=regulation,
            name=name,
            next_due=next_due,
            assigned_to=assigned_to,
            notes=notes,
        )

        await self._audit_service.record(
            tenant_id=tenant.tenant_id,
            event_type="governance.compliance.workflow.created",
            actor_id=actor_id,
            resource_type="compliance_workflow",
            resource_id=workflow.id,
            action="created",
            details={"regulation": regulation, "name": name},
            correlation_id=correlation_id,
        )

        await self._event_publisher.publish_workflow_status_changed(
            tenant_id=tenant.tenant_id,
            workflow_id=workflow.id,
            regulation=regulation,
            old_status="",
            new_status="initiated",
            correlation_id=correlation_id,
        )

        return _workflow_to_response(workflow)

    async def get_workflow(
        self,
        workflow_id: uuid.UUID,
        tenant: TenantContext,
    ) -> ComplianceWorkflowResponse:
        """Get a compliance workflow by ID.

        Args:
            workflow_id: The workflow UUID.
            tenant: The tenant context.

        Returns:
            The ComplianceWorkflowResponse.
        """
        workflow = await self._workflow_repo.get_by_id(workflow_id, tenant)
        return _workflow_to_response(workflow)

    async def list_workflows(
        self,
        tenant: TenantContext,
        regulation_filter: str | None = None,
        status_filter: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> list[ComplianceWorkflowResponse]:
        """List compliance workflows for a tenant.

        Args:
            tenant: The tenant context.
            regulation_filter: Optional regulation code filter.
            status_filter: Optional status filter.
            page: Page number.
            page_size: Records per page.

        Returns:
            List of ComplianceWorkflowResponse.
        """
        workflows = await self._workflow_repo.list_all(
            tenant, regulation_filter, status_filter, page, page_size
        )
        return [_workflow_to_response(w) for w in workflows]

    async def get_dashboard(self, tenant: TenantContext) -> ComplianceDashboardResponse:
        """Build compliance dashboard summary across all regulations.

        Args:
            tenant: The tenant context.

        Returns:
            ComplianceDashboardResponse with per-regulation summaries.
        """
        raw_summaries = await self._workflow_repo.get_dashboard_summary(tenant)

        summaries: list[ComplianceDashboardRegulationSummary] = []
        for row in raw_summaries:
            summaries.append(
                ComplianceDashboardRegulationSummary(
                    regulation=row["regulation"],
                    total_workflows=row.get("total_workflows", 0),
                    attested_workflows=row.get("attested_workflows", 0),
                    in_progress_workflows=row.get("in_progress_workflows", 0),
                    total_evidence=row.get("total_evidence", 0),
                    compliance_score=row.get("compliance_score", 0.0),
                    last_assessment=row.get("last_assessment"),
                    next_due=row.get("next_due"),
                )
            )

        return ComplianceDashboardResponse(
            tenant_id=tenant.tenant_id,
            generated_at=datetime.now(UTC),
            regulations=summaries,
        )


class AuditService:
    """Immutable audit trail write orchestration.

    The single point of entry for all audit trail writes. Delegates to
    IAuditTrailRepository, which connects exclusively to the separate
    Audit Wall PostgreSQL instance.

    IMPORTANT: This service contains NO update or delete operations.
    The audit trail is append-only. If an entry must be corrected,
    write a compensating entry.

    Args:
        audit_repo: Repository for AuditTrailEntry persistence (Audit Wall DB).
    """

    def __init__(self, audit_repo: IAuditTrailRepository) -> None:
        """Initialize AuditService with injected audit repository.

        Args:
            audit_repo: Repository implementing IAuditTrailRepository (Audit Wall DB).
        """
        self._audit_repo = audit_repo

    async def record(
        self,
        tenant_id: uuid.UUID,
        event_type: str,
        actor_id: uuid.UUID,
        resource_type: str,
        resource_id: uuid.UUID,
        action: str,
        details: dict[str, Any],
        correlation_id: str | None = None,
    ) -> AuditTrailEntry:
        """Append an immutable audit trail entry to the Audit Wall.

        Args:
            tenant_id: The owning tenant UUID.
            event_type: Dot-notation event type.
            actor_id: UUID of the actor performing the action.
            resource_type: Type of the affected resource.
            resource_id: UUID of the affected resource.
            action: Short action verb.
            details: Structured event-specific payload.
            correlation_id: Optional request correlation ID.

        Returns:
            The persisted AuditTrailEntry (from the Audit Wall DB).
        """
        timestamp = datetime.now(UTC)
        logger.info(
            "Writing audit trail entry",
            event_type=event_type,
            tenant_id=str(tenant_id),
            resource_type=resource_type,
            resource_id=str(resource_id),
            action=action,
        )

        entry = await self._audit_repo.append(
            tenant_id=tenant_id,
            event_type=event_type,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            details=details,
            timestamp=timestamp,
            correlation_id=correlation_id,
        )

        return entry

    async def query_trail(
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
        """Query the immutable audit trail.

        Args:
            tenant: The tenant context.
            event_type_filter: Optional event type prefix.
            resource_type_filter: Optional resource type.
            resource_id_filter: Optional specific resource UUID.
            actor_id_filter: Optional actor UUID.
            start_time: Optional start of time range.
            end_time: Optional end of time range.
            page: Page number.
            page_size: Records per page.

        Returns:
            List of AuditTrailEntry records (read-only).
        """
        return await self._audit_repo.query(
            tenant=tenant,
            event_type_filter=event_type_filter,
            resource_type_filter=resource_type_filter,
            resource_id_filter=resource_id_filter,
            actor_id_filter=actor_id_filter,
            start_time=start_time,
            end_time=end_time,
            page=page,
            page_size=page_size,
        )


class EvidenceService:
    """Evidence record submission and retrieval.

    Manages compliance evidence artifacts that link workflow controls to
    proof materials. After submitting evidence, writes an audit entry and
    increments the denormalized evidence count on the workflow.

    Args:
        evidence_repo: Repository for EvidenceRecord persistence.
        workflow_repo: Repository for ComplianceWorkflow (for count increment).
        audit_service: Service for writing audit trail entries.
        event_publisher: Kafka event publisher.
    """

    def __init__(
        self,
        evidence_repo: IEvidenceRepository,
        workflow_repo: IComplianceWorkflowRepository,
        audit_service: AuditService,
        event_publisher: IGovernanceEventPublisher,
    ) -> None:
        """Initialize EvidenceService with injected dependencies.

        Args:
            evidence_repo: Repository implementing IEvidenceRepository.
            workflow_repo: Repository implementing IComplianceWorkflowRepository.
            audit_service: AuditService for writing audit trail entries.
            event_publisher: Publisher implementing IGovernanceEventPublisher.
        """
        self._evidence_repo = evidence_repo
        self._workflow_repo = workflow_repo
        self._audit_service = audit_service
        self._event_publisher = event_publisher

    async def submit_evidence(
        self,
        tenant: TenantContext,
        workflow_id: uuid.UUID,
        evidence_type: str,
        title: str,
        description: str,
        artifact_uri: str | None,
        collector: str,
        control_ids: list[str],
        actor_id: uuid.UUID,
        correlation_id: str | None = None,
    ) -> EvidenceRecordResponse:
        """Submit a new evidence record.

        Validates the workflow exists, creates the evidence record, increments
        the workflow evidence count, writes an audit trail entry, and publishes
        a Kafka event.

        Args:
            tenant: The tenant context.
            workflow_id: The workflow to attach evidence to.
            evidence_type: Evidence type classification.
            title: Short evidence title.
            description: Detailed description.
            artifact_uri: Optional storage URI.
            collector: auto or manual.
            control_ids: Control IDs satisfied by this evidence.
            actor_id: UUID of the submitter.
            correlation_id: Optional request correlation ID.

        Returns:
            The created EvidenceRecordResponse.

        Raises:
            NotFoundError: If the workflow does not exist.
        """
        # Validate workflow exists (raises NotFoundError if not)
        await self._workflow_repo.get_by_id(workflow_id, tenant)

        collected_at = datetime.now(UTC)
        evidence = await self._evidence_repo.create(
            tenant=tenant,
            workflow_id=workflow_id,
            evidence_type=evidence_type,
            title=title,
            description=description,
            artifact_uri=artifact_uri,
            collected_at=collected_at,
            collector=collector,
            control_ids=control_ids,
        )

        # Atomically increment denormalized count
        await self._workflow_repo.increment_evidence_count(workflow_id, tenant)

        await self._audit_service.record(
            tenant_id=tenant.tenant_id,
            event_type="governance.evidence.submitted",
            actor_id=actor_id,
            resource_type="evidence_record",
            resource_id=evidence.id,
            action="submitted",
            details={
                "workflow_id": str(workflow_id),
                "evidence_type": evidence_type,
                "collector": collector,
                "control_ids": control_ids,
            },
            correlation_id=correlation_id,
        )

        await self._event_publisher.publish_evidence_submitted(
            tenant_id=tenant.tenant_id,
            evidence_id=evidence.id,
            workflow_id=workflow_id,
            evidence_type=evidence_type,
            collector=collector,
            correlation_id=correlation_id,
        )

        logger.info(
            "Evidence submitted",
            evidence_id=str(evidence.id),
            workflow_id=str(workflow_id),
            tenant_id=str(tenant.tenant_id),
        )

        return _evidence_to_response(evidence)

    async def list_evidence(
        self,
        workflow_id: uuid.UUID,
        tenant: TenantContext,
        page: int = 1,
        page_size: int = 20,
    ) -> list[EvidenceRecordResponse]:
        """List evidence records for a workflow.

        Args:
            workflow_id: The workflow UUID.
            tenant: The tenant context.
            page: Page number.
            page_size: Records per page.

        Returns:
            List of EvidenceRecordResponse.
        """
        records = await self._evidence_repo.list_by_workflow(workflow_id, tenant, page, page_size)
        return [_evidence_to_response(r) for r in records]


class RegulationMapperService:
    """Regulation-to-control mapping engine and static regulation metadata.

    Provides the authoritative list of supported regulations and their
    technical control mappings. Combines a static baseline (embedded here)
    with database-stored mappings (which may be extended by tenants).

    Args:
        mapping_repo: Repository for RegulationMapping persistence.
    """

    def __init__(self, mapping_repo: IRegulationMappingRepository) -> None:
        """Initialize RegulationMapperService with injected repository.

        Args:
            mapping_repo: Repository implementing IRegulationMappingRepository.
        """
        self._mapping_repo = mapping_repo

    def list_regulations(self) -> RegulationListResponse:
        """Return the list of all supported regulations.

        Returns:
            RegulationListResponse with metadata for each supported regulation.
        """
        return RegulationListResponse(
            regulations=[
                {
                    "code": r["code"],
                    "name": r["name"],
                    "full_name": r["full_name"],
                    "issuing_body": r["issuing_body"],
                    "scope": r["scope"],
                    "ai_specific": r["ai_specific"],
                }
                for r in _SUPPORTED_REGULATIONS
            ]
        )

    async def get_controls(
        self,
        regulation: str,
        tenant: TenantContext,
        automated_only: bool = False,
    ) -> list[RegulationControlResponse]:
        """Get control mappings for a regulation.

        Fetches from the database first. Falls back to the static baseline
        if the database has no rows for this regulation (before seed migration runs).

        Args:
            regulation: The regulation code.
            tenant: The tenant context.
            automated_only: If True, return only auto-assessable controls.

        Returns:
            List of RegulationControlResponse.

        Raises:
            ValidationError: If the regulation code is not supported.
        """
        supported_codes = {r["code"] for r in _SUPPORTED_REGULATIONS}
        if regulation not in supported_codes:
            raise ValidationError(
                message=f"Unsupported regulation '{regulation}'. Supported: {sorted(supported_codes)}",
                field="regulation",
            )

        db_mappings = await self._mapping_repo.list_by_regulation(
            regulation=regulation,
            tenant=tenant,
            automated_only=automated_only,
        )

        if db_mappings:
            return [
                RegulationControlResponse(
                    regulation=m.regulation,
                    article_ref=m.article_ref,
                    requirement_text=m.requirement_text,
                    control_ids=m.control_ids,
                    automated=m.automated,
                    notes=m.notes,
                )
                for m in db_mappings
            ]

        # Fallback to static baseline
        static_controls = _STATIC_CONTROL_SAMPLES.get(regulation, [])
        if automated_only:
            static_controls = [c for c in static_controls if c["automated"]]

        return [
            RegulationControlResponse(
                regulation=regulation,
                article_ref=c["article_ref"],
                requirement_text=c["requirement_text"],
                control_ids=c["control_ids"],
                automated=c["automated"],
                notes=None,
            )
            for c in static_controls
        ]


class ConsentService:
    """Data subject consent lifecycle management.

    Records, verifies, and withdraws consent decisions. All consent operations
    are delegated to the IConsentManager adapter, which maintains an immutable
    append-only consent history. After every state-changing operation, an
    AuditTrailEntry is written.

    Args:
        consent_manager: Adapter implementing IConsentManager.
        audit_service: Service for writing immutable audit trail entries.
    """

    def __init__(
        self,
        consent_manager: IConsentManager,
        audit_service: AuditService,
    ) -> None:
        """Initialize ConsentService with injected dependencies.

        Args:
            consent_manager: Adapter implementing IConsentManager.
            audit_service: AuditService for writing audit trail entries.
        """
        self._consent_manager = consent_manager
        self._audit_service = audit_service

    async def record_consent(
        self,
        tenant: TenantContext,
        subject_id: str,
        purpose: str,
        legal_basis: str,
        granted: bool,
        expiry_days: int | None,
        actor_id: uuid.UUID,
        metadata: dict[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Record a consent decision for a data subject.

        Args:
            tenant: The tenant context.
            subject_id: Opaque data subject identifier.
            purpose: Processing purpose.
            legal_basis: GDPR legal basis.
            granted: True if consent given, False if withdrawn.
            expiry_days: Optional days until expiry.
            actor_id: UUID of the user recording the consent.
            metadata: Additional consent context.
            correlation_id: Optional request correlation ID.

        Returns:
            Consent record dict with id, tenant_id, subject_id, purpose,
            granted, captured_at, and expires_at.
        """
        logger.info(
            "Recording consent decision",
            tenant_id=str(tenant.tenant_id),
            purpose=purpose,
            granted=granted,
            legal_basis=legal_basis,
        )

        consent_record = await self._consent_manager.record_consent(
            tenant_id=tenant.tenant_id,
            subject_id=subject_id,
            purpose=purpose,
            legal_basis=legal_basis,
            granted=granted,
            expiry_days=expiry_days,
            metadata=metadata or {},
        )

        await self._audit_service.record(
            tenant_id=tenant.tenant_id,
            event_type="governance.consent.recorded",
            actor_id=actor_id,
            resource_type="consent_record",
            resource_id=uuid.UUID(str(consent_record.get("id", uuid.uuid4()))),
            action="recorded" if granted else "withdrawn",
            details={
                "purpose": purpose,
                "legal_basis": legal_basis,
                "granted": granted,
                "expiry_days": expiry_days,
            },
            correlation_id=correlation_id,
        )

        return consent_record

    async def verify_consent(
        self,
        tenant: TenantContext,
        subject_id: str,
        purpose: str,
    ) -> dict[str, Any]:
        """Verify whether a data subject has active consent for a purpose.

        Args:
            tenant: The tenant context.
            subject_id: Opaque data subject identifier.
            purpose: Processing purpose to verify.

        Returns:
            Verification dict with has_consent, granted_at, expires_at,
            withdrawal_at, and legal_basis.
        """
        return await self._consent_manager.verify_consent(
            tenant_id=tenant.tenant_id,
            subject_id=subject_id,
            purpose=purpose,
        )

    async def withdraw_consent(
        self,
        tenant: TenantContext,
        subject_id: str,
        purpose: str,
        actor_id: uuid.UUID,
        reason: str | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Record a consent withdrawal and write an audit trail entry.

        Args:
            tenant: The tenant context.
            subject_id: Opaque data subject identifier.
            purpose: Processing purpose to withdraw consent from.
            actor_id: UUID of the user recording the withdrawal.
            reason: Optional reason for withdrawal.
            correlation_id: Optional request correlation ID.

        Returns:
            Updated consent record dict with withdrawal_at populated.
        """
        logger.info(
            "Recording consent withdrawal",
            tenant_id=str(tenant.tenant_id),
            purpose=purpose,
        )

        consent_record = await self._consent_manager.withdraw_consent(
            tenant_id=tenant.tenant_id,
            subject_id=subject_id,
            purpose=purpose,
            reason=reason,
        )

        await self._audit_service.record(
            tenant_id=tenant.tenant_id,
            event_type="governance.consent.withdrawn",
            actor_id=actor_id,
            resource_type="consent_record",
            resource_id=uuid.UUID(str(consent_record.get("id", uuid.uuid4()))),
            action="withdrawn",
            details={"purpose": purpose, "reason": reason},
            correlation_id=correlation_id,
        )

        return consent_record

    async def get_audit_trail(
        self,
        tenant: TenantContext,
        subject_id: str,
    ) -> list[dict[str, Any]]:
        """Retrieve the full consent history for a data subject.

        Args:
            tenant: The tenant context.
            subject_id: Opaque data subject identifier.

        Returns:
            List of consent event dicts ordered by captured_at descending.
        """
        return await self._consent_manager.get_audit_trail(
            tenant_id=tenant.tenant_id,
            subject_id=subject_id,
        )


# ---------------------------------------------------------------------------
# Settings accessor (Gap 201 — used by router for Jira/ServiceNow config)
# ---------------------------------------------------------------------------


def get_governance_settings() -> Any:
    """Get the governance engine settings singleton.

    Lazily imports and instantiates the Settings class to avoid circular
    imports. The router uses this to retrieve Jira/ServiceNow credentials
    for external evidence import.

    Returns:
        The Settings instance (cached by pydantic-settings).
    """
    from aumos_governance_engine.settings import Settings

    return Settings()


class DataResidencyService:
    """Data residency policy evaluation and enforcement.

    Evaluates cross-border data movement requests against tenant-configured
    residency policies and jurisdiction-specific legal restrictions.

    Args:
        residency_enforcer: Adapter implementing IDataResidencyEnforcer.
    """

    def __init__(self, residency_enforcer: IDataResidencyEnforcer) -> None:
        """Initialize DataResidencyService with injected adapter.

        Args:
            residency_enforcer: Adapter implementing IDataResidencyEnforcer.
        """
        self._enforcer = residency_enforcer

    async def check_transfer(
        self,
        tenant: TenantContext,
        source_region: str,
        destination_region: str,
        data_classification: str,
        data_categories: list[str],
    ) -> dict[str, Any]:
        """Check whether a data transfer complies with residency policy.

        Args:
            tenant: The tenant context.
            source_region: ISO 3166-1 alpha-2 country or region code of origin.
            destination_region: ISO 3166-1 alpha-2 destination country or region.
            data_classification: Data sensitivity classification.
            data_categories: List of data type labels or GDPR special categories.

        Returns:
            Dict with allowed, transfer_mechanism, blocking_restrictions,
            required_safeguards, and jurisdiction_requirements.
        """
        logger.info(
            "Checking data transfer residency compliance",
            tenant_id=str(tenant.tenant_id),
            source_region=source_region,
            destination_region=destination_region,
            data_classification=data_classification,
        )

        return await self._enforcer.check_transfer(
            tenant_id=tenant.tenant_id,
            source_region=source_region,
            destination_region=destination_region,
            data_classification=data_classification,
            data_categories=data_categories,
        )

    async def get_policy(self, tenant: TenantContext) -> dict[str, Any]:
        """Retrieve the data residency policy for a tenant.

        Args:
            tenant: The tenant context.

        Returns:
            Policy dict with allowed_regions, restricted_regions, and
            default_transfer_mechanism.
        """
        return await self._enforcer.get_policy(tenant_id=tenant.tenant_id)

    async def validate_storage_location(
        self,
        tenant: TenantContext,
        region: str,
        data_classification: str,
    ) -> dict[str, Any]:
        """Validate that a storage region complies with tenant policy.

        Args:
            tenant: The tenant context.
            region: Proposed storage region code.
            data_classification: Classification of the data to store.

        Returns:
            Dict with compliant (bool), violations, and recommended_alternatives.
        """
        return await self._enforcer.validate_storage_location(
            tenant_id=tenant.tenant_id,
            region=region,
            data_classification=data_classification,
        )


class ComplianceReportService:
    """Compliance report generation and control status aggregation.

    Generates structured compliance status reports for auditor and regulatory
    submissions. Delegates rendering to the IComplianceReporter adapter.

    Args:
        compliance_reporter: Adapter implementing IComplianceReporter.
    """

    def __init__(self, compliance_reporter: IComplianceReporter) -> None:
        """Initialize ComplianceReportService with injected adapter.

        Args:
            compliance_reporter: Adapter implementing IComplianceReporter.
        """
        self._reporter = compliance_reporter

    async def generate_report(
        self,
        tenant: TenantContext,
        regulation: str,
        workflow_ids: list[uuid.UUID],
        report_format: str = "json",
        include_evidence: bool = True,
    ) -> dict[str, Any]:
        """Generate a compliance status report for a regulation.

        Args:
            tenant: The tenant context.
            regulation: Regulation code (soc2, iso27001, hipaa, iso42001,
                eu_ai_act, fedramp).
            workflow_ids: Specific workflow UUIDs to include. Empty = all.
            report_format: Output format ('json', 'pdf', 'csv').
            include_evidence: Whether to embed evidence artifact links.

        Returns:
            Report dict with regulation, generated_at, summary, controls,
            evidence_count, compliance_score, and download_uri.
        """
        logger.info(
            "Generating compliance report",
            tenant_id=str(tenant.tenant_id),
            regulation=regulation,
            report_format=report_format,
            workflow_count=len(workflow_ids),
        )

        return await self._reporter.generate_report(
            tenant_id=tenant.tenant_id,
            regulation=regulation,
            workflow_ids=workflow_ids,
            report_format=report_format,
            include_evidence=include_evidence,
        )

    async def get_control_status(
        self,
        tenant: TenantContext,
        regulation: str,
        control_id: str,
    ) -> dict[str, Any]:
        """Get the current status of a specific compliance control.

        Args:
            tenant: The tenant context.
            regulation: Regulation code.
            control_id: Control identifier (e.g., 'CC6.1', 'AC-2').

        Returns:
            Dict with control_id, status (passed/failed/not_assessed),
            evidence_count, last_assessed, and automated.
        """
        return await self._reporter.get_control_status(
            tenant_id=tenant.tenant_id,
            regulation=regulation,
            control_id=control_id,
        )

    async def get_readiness_score(
        self,
        tenant: TenantContext,
        regulation: str,
    ) -> dict[str, Any]:
        """Compute an overall compliance readiness score for a regulation.

        Args:
            tenant: The tenant context.
            regulation: Regulation code.

        Returns:
            Dict with regulation, score (0.0-1.0), breakdown_by_domain,
            blocking_gaps, and recommendations.
        """
        logger.info(
            "Computing compliance readiness score",
            tenant_id=str(tenant.tenant_id),
            regulation=regulation,
        )

        return await self._reporter.get_readiness_score(
            tenant_id=tenant.tenant_id,
            regulation=regulation,
        )


# ---------------------------------------------------------------------------
# Private response mappers — ORM model → Pydantic response schema
# ---------------------------------------------------------------------------


def _policy_to_response(policy: GovernancePolicy) -> GovernancePolicyResponse:
    """Convert a GovernancePolicy ORM model to a response schema.

    Args:
        policy: The GovernancePolicy ORM instance.

    Returns:
        GovernancePolicyResponse Pydantic model.
    """
    return GovernancePolicyResponse(
        id=policy.id,
        tenant_id=policy.tenant_id,
        name=policy.name,
        policy_type=policy.policy_type,
        rego_content=policy.rego_content,
        version=policy.version,
        status=policy.status,
        regulation_refs=policy.regulation_refs,
        description=policy.description,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


def _workflow_to_response(workflow: ComplianceWorkflow) -> ComplianceWorkflowResponse:
    """Convert a ComplianceWorkflow ORM model to a response schema.

    Args:
        workflow: The ComplianceWorkflow ORM instance.

    Returns:
        ComplianceWorkflowResponse Pydantic model.
    """
    return ComplianceWorkflowResponse(
        id=workflow.id,
        tenant_id=workflow.tenant_id,
        regulation=workflow.regulation,
        name=workflow.name,
        status=workflow.status,
        evidence_count=workflow.evidence_count,
        last_assessment=workflow.last_assessment,
        next_due=workflow.next_due,
        assigned_to=workflow.assigned_to,
        notes=workflow.notes,
        created_at=workflow.created_at,
        updated_at=workflow.updated_at,
    )


def _evidence_to_response(evidence: EvidenceRecord) -> EvidenceRecordResponse:
    """Convert an EvidenceRecord ORM model to a response schema.

    Args:
        evidence: The EvidenceRecord ORM instance.

    Returns:
        EvidenceRecordResponse Pydantic model.
    """
    return EvidenceRecordResponse(
        id=evidence.id,
        tenant_id=evidence.tenant_id,
        workflow_id=evidence.workflow_id,
        evidence_type=evidence.evidence_type,
        title=evidence.title,
        description=evidence.description,
        artifact_uri=evidence.artifact_uri,
        collected_at=evidence.collected_at,
        collector=evidence.collector,
        control_ids=evidence.control_ids,
        status=evidence.status,
        reviewed_by=evidence.reviewed_by,
        reviewed_at=evidence.reviewed_at,
        created_at=evidence.created_at,
        updated_at=evidence.updated_at,
    )
