"""API router for aumos-governance-engine.

All governance engine endpoints are registered here and included in main.py
under the /api/v1 prefix. Routes are thin — all business logic lives in the
service layer.

Endpoints:
- POST/GET    /policies                          — CRUD governance policies
- GET         /policies/{id}                     — Get policy by ID
- POST        /policies/{id}/activate            — Activate policy (push to OPA)
- POST        /policies/{id}/evaluate            — Evaluate policy against input
- POST/GET    /compliance/workflows              — CRUD compliance workflows
- GET         /compliance/workflows/{id}         — Get workflow by ID
- GET         /compliance/dashboard              — Compliance dashboard
- GET         /audit-trail                       — Query immutable audit trail
- POST        /evidence                          — Submit evidence record
- GET         /evidence                          — List evidence (filter by workflow)
- GET         /regulations                       — List supported regulations
- GET         /regulations/{regulation}/controls — Get regulation control mappings
"""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.auth import TenantContext, get_current_user
from aumos_common.database import get_db_session
from aumos_common.observability import get_logger

from aumos_governance_engine.adapters.audit_wall import get_audit_db_session
from aumos_governance_engine.adapters.kafka import GovernanceEventPublisher
from aumos_governance_engine.adapters.opa_client import OPAClient
from aumos_governance_engine.adapters.repositories import (
    AuditTrailRepository,
    ComplianceWorkflowRepository,
    EvidenceRepository,
    PolicyRepository,
    RegulationMappingRepository,
)
from aumos_governance_engine.api.schemas import (
    AuditTrailEntryResponse,
    ComplianceDashboardResponse,
    ComplianceWorkflowCreateRequest,
    ComplianceWorkflowResponse,
    EvidenceRecordResponse,
    EvidenceSubmitRequest,
    GovernancePolicyCreateRequest,
    GovernancePolicyResponse,
    PolicyEvaluateRequest,
    PolicyEvaluateResponse,
    RegulationControlResponse,
    RegulationListResponse,
)
from aumos_governance_engine.core.services import (
    AuditService,
    ComplianceService,
    EvidenceService,
    PolicyService,
    RegulationMapperService,
)

logger = get_logger(__name__)

router = APIRouter(tags=["governance"])


# ---------------------------------------------------------------------------
# Dependency factories — wire repositories, services, and clients together
# ---------------------------------------------------------------------------


def get_policy_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    audit_session: Annotated[AsyncSession, Depends(get_audit_db_session)],
) -> PolicyService:
    """Construct PolicyService with injected repositories.

    Args:
        session: Primary DB session.
        audit_session: Audit Wall DB session.

    Returns:
        Fully wired PolicyService instance.
    """
    policy_repo = PolicyRepository(session)
    audit_repo = AuditTrailRepository(audit_session)
    audit_service = AuditService(audit_repo)
    opa_client = OPAClient()
    event_publisher = GovernanceEventPublisher()
    return PolicyService(
        policy_repo=policy_repo,
        audit_service=audit_service,
        opa_client=opa_client,
        event_publisher=event_publisher,
    )


def get_compliance_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    audit_session: Annotated[AsyncSession, Depends(get_audit_db_session)],
) -> ComplianceService:
    """Construct ComplianceService with injected repositories.

    Args:
        session: Primary DB session.
        audit_session: Audit Wall DB session.

    Returns:
        Fully wired ComplianceService instance.
    """
    workflow_repo = ComplianceWorkflowRepository(session)
    audit_repo = AuditTrailRepository(audit_session)
    audit_service = AuditService(audit_repo)
    event_publisher = GovernanceEventPublisher()
    return ComplianceService(
        workflow_repo=workflow_repo,
        audit_service=audit_service,
        event_publisher=event_publisher,
    )


def get_audit_service(
    audit_session: Annotated[AsyncSession, Depends(get_audit_db_session)],
) -> AuditService:
    """Construct AuditService with injected audit repository.

    Args:
        audit_session: Audit Wall DB session.

    Returns:
        Fully wired AuditService instance.
    """
    audit_repo = AuditTrailRepository(audit_session)
    return AuditService(audit_repo)


def get_evidence_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    audit_session: Annotated[AsyncSession, Depends(get_audit_db_session)],
) -> EvidenceService:
    """Construct EvidenceService with injected repositories.

    Args:
        session: Primary DB session.
        audit_session: Audit Wall DB session.

    Returns:
        Fully wired EvidenceService instance.
    """
    evidence_repo = EvidenceRepository(session)
    workflow_repo = ComplianceWorkflowRepository(session)
    audit_repo = AuditTrailRepository(audit_session)
    audit_service = AuditService(audit_repo)
    event_publisher = GovernanceEventPublisher()
    return EvidenceService(
        evidence_repo=evidence_repo,
        workflow_repo=workflow_repo,
        audit_service=audit_service,
        event_publisher=event_publisher,
    )


def get_regulation_mapper_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> RegulationMapperService:
    """Construct RegulationMapperService with injected repository.

    Args:
        session: Primary DB session.

    Returns:
        Fully wired RegulationMapperService instance.
    """
    mapping_repo = RegulationMappingRepository(session)
    return RegulationMapperService(mapping_repo=mapping_repo)


# ---------------------------------------------------------------------------
# Policy endpoints
# ---------------------------------------------------------------------------


@router.post("/policies", response_model=GovernancePolicyResponse, status_code=201)
async def create_policy(
    request: GovernancePolicyCreateRequest,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    service: Annotated[PolicyService, Depends(get_policy_service)],
) -> GovernancePolicyResponse:
    """Create a new governance policy.

    Creates a policy in draft status. To activate it and push to OPA,
    use the POST /policies/{id}/activate endpoint.

    Args:
        request: Policy creation request body.
        tenant: Tenant context from auth middleware.
        service: Injected PolicyService.

    Returns:
        The created governance policy in draft status.
    """
    logger.info("POST /policies", tenant_id=str(tenant.tenant_id), policy_name=request.name)
    return await service.create_policy(
        tenant=tenant,
        name=request.name,
        policy_type=request.policy_type,
        rego_content=request.rego_content,
        description=request.description,
        regulation_refs=request.regulation_refs,
        actor_id=tenant.user_id,
    )


@router.get("/policies", response_model=list[GovernancePolicyResponse])
async def list_policies(
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    service: Annotated[PolicyService, Depends(get_policy_service)],
    status: str | None = Query(default=None, description="Filter by status: draft|active|deprecated|archived"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> list[GovernancePolicyResponse]:
    """List governance policies for the current tenant.

    Args:
        tenant: Tenant context from auth middleware.
        service: Injected PolicyService.
        status: Optional status filter.
        page: Page number.
        page_size: Records per page.

    Returns:
        List of governance policies.
    """
    return await service.list_policies(tenant, status_filter=status, page=page, page_size=page_size)


@router.get("/policies/{policy_id}", response_model=GovernancePolicyResponse)
async def get_policy(
    policy_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    service: Annotated[PolicyService, Depends(get_policy_service)],
) -> GovernancePolicyResponse:
    """Get a governance policy by ID.

    Args:
        policy_id: The policy UUID.
        tenant: Tenant context from auth middleware.
        service: Injected PolicyService.

    Returns:
        The governance policy.
    """
    return await service.get_policy(policy_id=policy_id, tenant=tenant)


@router.post("/policies/{policy_id}/activate", response_model=GovernancePolicyResponse)
async def activate_policy(
    policy_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    service: Annotated[PolicyService, Depends(get_policy_service)],
) -> GovernancePolicyResponse:
    """Activate a policy — uploads Rego bundle to OPA.

    Transitions the policy from draft or deprecated to active status,
    and pushes the Rego content to OPA as an evaluatable bundle.

    Args:
        policy_id: The policy UUID to activate.
        tenant: Tenant context from auth middleware.
        service: Injected PolicyService.

    Returns:
        The updated policy with active status.
    """
    return await service.activate_policy(
        policy_id=policy_id,
        tenant=tenant,
        actor_id=tenant.user_id,
    )


@router.post("/policies/{policy_id}/evaluate", response_model=PolicyEvaluateResponse)
async def evaluate_policy(
    policy_id: uuid.UUID,
    request: PolicyEvaluateRequest,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    service: Annotated[PolicyService, Depends(get_policy_service)],
) -> PolicyEvaluateResponse:
    """Evaluate a governance policy against structured input data.

    Sends the input to OPA for evaluation against the policy's Rego rules.
    Returns an allow/deny decision and any violations found.

    Args:
        policy_id: The active policy UUID to evaluate.
        request: Evaluation request with input data.
        tenant: Tenant context from auth middleware.
        service: Injected PolicyService.

    Returns:
        Policy evaluation result with allow flag and violations.
    """
    return await service.evaluate_policy(
        policy_id=policy_id,
        input_data=request.input,
        tenant=tenant,
        actor_id=tenant.user_id,
    )


# ---------------------------------------------------------------------------
# Compliance workflow endpoints
# ---------------------------------------------------------------------------


@router.post("/compliance/workflows", response_model=ComplianceWorkflowResponse, status_code=201)
async def create_compliance_workflow(
    request: ComplianceWorkflowCreateRequest,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    service: Annotated[ComplianceService, Depends(get_compliance_service)],
) -> ComplianceWorkflowResponse:
    """Create a new compliance workflow.

    Args:
        request: Workflow creation request.
        tenant: Tenant context from auth middleware.
        service: Injected ComplianceService.

    Returns:
        The created compliance workflow in initiated status.
    """
    logger.info(
        "POST /compliance/workflows",
        tenant_id=str(tenant.tenant_id),
        regulation=request.regulation,
    )
    return await service.create_workflow(
        tenant=tenant,
        regulation=request.regulation,
        name=request.name,
        next_due=request.next_due,
        assigned_to=request.assigned_to,
        notes=request.notes,
        actor_id=tenant.user_id,
    )


@router.get("/compliance/workflows", response_model=list[ComplianceWorkflowResponse])
async def list_compliance_workflows(
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    service: Annotated[ComplianceService, Depends(get_compliance_service)],
    regulation: str | None = Query(default=None, description="Filter by regulation code"),
    status: str | None = Query(default=None, description="Filter by workflow status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> list[ComplianceWorkflowResponse]:
    """List compliance workflows for the current tenant.

    Args:
        tenant: Tenant context from auth middleware.
        service: Injected ComplianceService.
        regulation: Optional regulation filter.
        status: Optional status filter.
        page: Page number.
        page_size: Records per page.

    Returns:
        List of compliance workflows.
    """
    return await service.list_workflows(
        tenant,
        regulation_filter=regulation,
        status_filter=status,
        page=page,
        page_size=page_size,
    )


@router.get("/compliance/workflows/{workflow_id}", response_model=ComplianceWorkflowResponse)
async def get_compliance_workflow(
    workflow_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    service: Annotated[ComplianceService, Depends(get_compliance_service)],
) -> ComplianceWorkflowResponse:
    """Get a compliance workflow by ID.

    Args:
        workflow_id: The workflow UUID.
        tenant: Tenant context from auth middleware.
        service: Injected ComplianceService.

    Returns:
        The compliance workflow.
    """
    return await service.get_workflow(workflow_id=workflow_id, tenant=tenant)


@router.get("/compliance/dashboard", response_model=ComplianceDashboardResponse)
async def get_compliance_dashboard(
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    service: Annotated[ComplianceService, Depends(get_compliance_service)],
) -> ComplianceDashboardResponse:
    """Get compliance dashboard summary across all regulations.

    Returns aggregated compliance status for each regulation the tenant
    has workflows for, including compliance scores and evidence counts.

    Args:
        tenant: Tenant context from auth middleware.
        service: Injected ComplianceService.

    Returns:
        Compliance dashboard with per-regulation summaries.
    """
    return await service.get_dashboard(tenant=tenant)


# ---------------------------------------------------------------------------
# Audit trail endpoint
# ---------------------------------------------------------------------------


@router.get("/audit-trail", response_model=list[AuditTrailEntryResponse])
async def query_audit_trail(
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    service: Annotated[AuditService, Depends(get_audit_service)],
    event_type: str | None = Query(default=None, description="Filter by event type prefix"),
    resource_type: str | None = Query(default=None, description="Filter by resource type"),
    resource_id: uuid.UUID | None = Query(default=None, description="Filter by resource UUID"),
    actor_id: uuid.UUID | None = Query(default=None, description="Filter by actor UUID"),
    start_time: datetime | None = Query(default=None, description="Start of time range (UTC)"),
    end_time: datetime | None = Query(default=None, description="End of time range (UTC)"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> list[AuditTrailEntryResponse]:
    """Query the immutable audit trail.

    The audit trail is stored on a separate, write-protected database (Audit Wall).
    All entries are permanent — no UPDATE or DELETE operations exist on this data.

    Args:
        tenant: Tenant context from auth middleware.
        service: Injected AuditService.
        event_type: Optional event type prefix filter.
        resource_type: Optional resource type filter.
        resource_id: Optional resource UUID filter.
        actor_id: Optional actor UUID filter.
        start_time: Optional time range start.
        end_time: Optional time range end.
        page: Page number.
        page_size: Records per page (max 200).

    Returns:
        List of immutable audit trail entries.
    """
    entries = await service.query_trail(
        tenant=tenant,
        event_type_filter=event_type,
        resource_type_filter=resource_type,
        resource_id_filter=resource_id,
        actor_id_filter=actor_id,
        start_time=start_time,
        end_time=end_time,
        page=page,
        page_size=page_size,
    )
    return [
        AuditTrailEntryResponse(
            id=e.id,
            tenant_id=e.tenant_id,
            event_type=e.event_type,
            actor_id=e.actor_id,
            resource_type=e.resource_type,
            resource_id=e.resource_id,
            action=e.action,
            details=e.details,
            timestamp=e.timestamp,
            source_service=e.source_service,
            correlation_id=e.correlation_id,
        )
        for e in entries
    ]


# ---------------------------------------------------------------------------
# Evidence endpoints
# ---------------------------------------------------------------------------


@router.post("/evidence", response_model=EvidenceRecordResponse, status_code=201)
async def submit_evidence(
    request: EvidenceSubmitRequest,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    service: Annotated[EvidenceService, Depends(get_evidence_service)],
) -> EvidenceRecordResponse:
    """Submit a compliance evidence record.

    Attaches evidence to a compliance workflow. Can be submitted by users (manual)
    or by automated collection jobs (auto). An audit trail entry is always written
    for every evidence submission.

    Args:
        request: Evidence submission request.
        tenant: Tenant context from auth middleware.
        service: Injected EvidenceService.

    Returns:
        The created evidence record.
    """
    logger.info(
        "POST /evidence",
        tenant_id=str(tenant.tenant_id),
        workflow_id=str(request.workflow_id),
    )
    return await service.submit_evidence(
        tenant=tenant,
        workflow_id=request.workflow_id,
        evidence_type=request.evidence_type,
        title=request.title,
        description=request.description,
        artifact_uri=request.artifact_uri,
        collector=request.collector,
        control_ids=request.control_ids,
        actor_id=tenant.user_id,
    )


@router.get("/evidence", response_model=list[EvidenceRecordResponse])
async def list_evidence(
    workflow_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    service: Annotated[EvidenceService, Depends(get_evidence_service)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> list[EvidenceRecordResponse]:
    """List evidence records for a compliance workflow.

    Args:
        workflow_id: The workflow UUID (required query param).
        tenant: Tenant context from auth middleware.
        service: Injected EvidenceService.
        page: Page number.
        page_size: Records per page.

    Returns:
        List of evidence records for the specified workflow.
    """
    return await service.list_evidence(
        workflow_id=workflow_id,
        tenant=tenant,
        page=page,
        page_size=page_size,
    )


# ---------------------------------------------------------------------------
# Regulation endpoints
# ---------------------------------------------------------------------------


@router.get("/regulations", response_model=RegulationListResponse)
async def list_regulations(
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    service: Annotated[RegulationMapperService, Depends(get_regulation_mapper_service)],
) -> RegulationListResponse:
    """List all supported regulations.

    Returns metadata for all six supported regulations: SOC 2, ISO 27001,
    HIPAA, ISO 42001, EU AI Act, and FedRAMP Moderate.

    Args:
        tenant: Tenant context from auth middleware.
        service: Injected RegulationMapperService.

    Returns:
        List of regulation metadata.
    """
    return service.list_regulations()


@router.get("/regulations/{regulation}/controls", response_model=list[RegulationControlResponse])
async def get_regulation_controls(
    regulation: str,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    service: Annotated[RegulationMapperService, Depends(get_regulation_mapper_service)],
    automated_only: bool = Query(default=False, description="Return only automatically-assessable controls"),
) -> list[RegulationControlResponse]:
    """Get control mappings for a specific regulation.

    Returns the mapping from regulation article references to technical
    control IDs, with automation status for each control.

    Args:
        regulation: The regulation code (soc2, iso27001, hipaa, iso42001, eu_ai_act, fedramp).
        tenant: Tenant context from auth middleware.
        service: Injected RegulationMapperService.
        automated_only: If True, return only auto-assessable controls.

    Returns:
        List of regulation control mappings.
    """
    return await service.get_controls(
        regulation=regulation,
        tenant=tenant,
        automated_only=automated_only,
    )
