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
from typing import Annotated, Any

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
    BundleStatusResponse,
    ComplianceDashboardResponse,
    ComplianceWorkflowCreateRequest,
    ComplianceWorkflowResponse,
    DecisionSummaryResponse,
    EvidenceRecordResponse,
    EvidenceSubmitRequest,
    ExternalEvidenceImportResponse,
    GovernancePolicyCreateRequest,
    GovernancePolicyResponse,
    JiraEvidenceImportRequest,
    LatencyPercentilesResponse,
    PolicyEvaluateRequest,
    PolicyEvaluateResponse,
    PolicyRollbackRequest,
    PolicySimulationRequest,
    WorkflowFromTemplateRequest,
    WorkflowTemplateListResponse,
    WorkflowTemplateSummary,
    PolicySimulationResponse,
    PolicyTestCaseCreateRequest,
    PolicyTestCaseResponse,
    PolicyTestRunRequest,
    PolicyTestRunResponse,
    PolicyVersionResponse,
    RegoValidationRequest,
    RegoValidationResponse,
    RegulationControlResponse,
    RegulationListResponse,
    ServiceNowEvidenceImportRequest,
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


# ---------------------------------------------------------------------------
# Gap 194 — Policy Test Cases and Runs
# ---------------------------------------------------------------------------


@router.post(
    "/policies/{policy_id}/tests",
    response_model=PolicyTestCaseResponse,
    status_code=201,
)
async def create_policy_test_case(
    policy_id: uuid.UUID,
    request: PolicyTestCaseCreateRequest,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> PolicyTestCaseResponse:
    """Create a test case for a governance policy.

    Test cases define expected OPA evaluation outcomes for specific inputs,
    enabling CI/CD-style regression testing of policy changes.

    Args:
        policy_id: The policy UUID.
        request: Test case creation request.
        tenant: Tenant context from auth middleware.
        db: Database session.

    Returns:
        The created PolicyTestCase.
    """
    from aumos_governance_engine.adapters.policy_testing import PolicyTestCaseRepository

    repo = PolicyTestCaseRepository(db)
    tc = await repo.create(
        tenant=tenant,
        policy_id=policy_id,
        name=request.name,
        input_data=request.input_data,
        expected_allow=request.expected_allow,
        description=request.description,
        expected_violations=request.expected_violations,
        tags=request.tags,
    )
    return PolicyTestCaseResponse(
        id=tc.id,
        tenant_id=tc.tenant_id,
        policy_id=tc.policy_id,
        name=tc.name,
        description=tc.description,
        input_data=tc.input_data,
        expected_allow=tc.expected_allow,
        expected_violations=tc.expected_violations,
        tags=tc.tags,
        created_at=tc.created_at,
        updated_at=tc.updated_at,
    )


@router.get("/policies/{policy_id}/tests", response_model=list[PolicyTestCaseResponse])
async def list_policy_test_cases(
    policy_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> list[PolicyTestCaseResponse]:
    """List test cases for a governance policy.

    Args:
        policy_id: The policy UUID.
        tenant: Tenant context from auth middleware.
        db: Database session.
        page: Page number.
        page_size: Records per page.

    Returns:
        List of policy test cases.
    """
    from aumos_governance_engine.adapters.policy_testing import PolicyTestCaseRepository

    repo = PolicyTestCaseRepository(db)
    test_cases = await repo.list_by_policy(
        policy_id=policy_id,
        tenant=tenant,
        page=page,
        page_size=page_size,
    )
    return [
        PolicyTestCaseResponse(
            id=tc.id,
            tenant_id=tc.tenant_id,
            policy_id=tc.policy_id,
            name=tc.name,
            description=tc.description,
            input_data=tc.input_data,
            expected_allow=tc.expected_allow,
            expected_violations=tc.expected_violations,
            tags=tc.tags,
            created_at=tc.created_at,
            updated_at=tc.updated_at,
        )
        for tc in test_cases
    ]


@router.post(
    "/policies/{policy_id}/tests/run",
    response_model=PolicyTestRunResponse,
    status_code=201,
)
async def run_policy_tests(
    policy_id: uuid.UUID,
    request: PolicyTestRunRequest,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    audit_db: Annotated[AsyncSession, Depends(get_audit_db_session)],
    opa_client: Annotated[OPAClient, Depends(lambda: OPAClient())],
) -> PolicyTestRunResponse:
    """Execute a test suite for a governance policy.

    Runs all selected test cases in parallel against a temporary OPA
    policy upload. Writes the run result to the Audit Wall.

    Args:
        policy_id: The policy UUID.
        request: Test run configuration.
        tenant: Tenant context from auth middleware.
        db: Primary database session.
        audit_db: Audit Wall database session.
        opa_client: OPA REST API client.

    Returns:
        The completed test run record.
    """
    from aumos_governance_engine.adapters.audit_wall import AuditTrailRepository
    from aumos_governance_engine.adapters.policy_testing import (
        PolicyTestCaseRepository,
        PolicyTestRunRepository,
        PolicyTestService,
    )

    # Fetch the policy to get its Rego content
    policy_repo = PolicyRepository(db)
    policy = await policy_repo.get_by_id(policy_id, tenant)

    tc_repo = PolicyTestCaseRepository(db)
    run_repo = PolicyTestRunRepository(db)
    audit_repo = AuditTrailRepository(audit_db)
    svc = PolicyTestService(
        test_case_repo=tc_repo,
        test_run_repo=run_repo,
        opa_client=opa_client,
        audit_trail_repo=audit_repo,
    )

    run = await svc.run_tests(
        tenant=tenant,
        policy_id=policy_id,
        rego_content=policy.rego_content or "",
        actor_id=tenant.user_id,
        test_case_ids=request.test_case_ids,
    )

    return PolicyTestRunResponse(
        id=run.id,
        tenant_id=run.tenant_id,
        policy_id=run.policy_id,
        status=run.status,
        total_cases=run.total_cases,
        passed_cases=run.passed_cases,
        failed_cases=run.failed_cases,
        error_cases=run.error_cases,
        results=run.results,
        started_at=run.started_at,
        completed_at=run.completed_at,
        duration_ms=run.duration_ms,
        created_at=run.created_at,
    )


# ---------------------------------------------------------------------------
# Gap 195 — Policy Simulation
# ---------------------------------------------------------------------------


@router.post(
    "/policies/{policy_id}/simulate",
    response_model=PolicySimulationResponse,
    status_code=201,
)
async def simulate_policy(
    policy_id: uuid.UUID,
    request: PolicySimulationRequest,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    opa_client: Annotated[OPAClient, Depends(lambda: OPAClient())],
) -> PolicySimulationResponse:
    """Run a dry-run simulation for a governance policy.

    Evaluates the policy (or a provided Rego override) against a dataset
    of inputs without affecting production state. Useful for what-if analysis.

    Args:
        policy_id: The policy UUID.
        request: Simulation configuration with input dataset.
        tenant: Tenant context from auth middleware.
        db: Database session.
        opa_client: OPA REST API client.

    Returns:
        The completed simulation record.
    """
    from aumos_governance_engine.adapters.policy_simulation import (
        PolicySimulationRepository,
        PolicySimulationService,
    )

    policy_repo = PolicyRepository(db)
    policy = await policy_repo.get_by_id(policy_id, tenant)
    rego_content = request.rego_override or policy.rego_content or ""

    sim_repo = PolicySimulationRepository(db)
    svc = PolicySimulationService(sim_repo=sim_repo, opa_client=opa_client)
    sim = await svc.simulate(
        tenant=tenant,
        policy_id=policy_id,
        rego_content=rego_content,
        scenario_name=request.scenario_name,
        input_dataset=request.input_dataset,
        triggered_by=tenant.user_id,
    )

    return PolicySimulationResponse(
        id=sim.id,
        tenant_id=sim.tenant_id,
        policy_id=sim.policy_id,
        scenario_name=sim.scenario_name,
        allow_count=sim.allow_count,
        deny_count=sim.deny_count,
        results=sim.results,
        completed_at=sim.completed_at,
        duration_ms=sim.duration_ms,
        created_at=sim.created_at,
    )


# ---------------------------------------------------------------------------
# Gap 196 — Policy Versioning
# ---------------------------------------------------------------------------


@router.get(
    "/policies/{policy_id}/versions",
    response_model=list[PolicyVersionResponse],
)
async def list_policy_versions(
    policy_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> list[PolicyVersionResponse]:
    """List version history for a governance policy.

    Returns all version snapshots ordered newest first, including SHA-256
    hash for tamper detection.

    Args:
        policy_id: The policy UUID.
        tenant: Tenant context from auth middleware.
        db: Database session.
        page: Page number.
        page_size: Records per page.

    Returns:
        List of policy version records.
    """
    from aumos_governance_engine.adapters.policy_versioning import PolicyVersionRepository

    repo = PolicyVersionRepository(db)
    versions = await repo.list_by_policy(
        policy_id=policy_id,
        tenant=tenant,
        page=page,
        page_size=page_size,
    )
    return [
        PolicyVersionResponse(
            id=v.id,
            tenant_id=v.tenant_id,
            policy_id=v.policy_id,
            version_number=v.version_number,
            rego_content=v.rego_content,
            sha256_hash=v.sha256_hash,
            change_description=v.change_description,
            authored_by=v.authored_by,
            activated_at=v.activated_at,
            is_current=v.is_current,
            created_at=v.created_at,
        )
        for v in versions
    ]


@router.post(
    "/policies/{policy_id}/rollback",
    response_model=PolicyVersionResponse,
    status_code=201,
)
async def rollback_policy(
    policy_id: uuid.UUID,
    request: PolicyRollbackRequest,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    audit_db: Annotated[AsyncSession, Depends(get_audit_db_session)],
    opa_client: Annotated[OPAClient, Depends(lambda: OPAClient())],
) -> PolicyVersionResponse:
    """Roll back a governance policy to a previous version.

    Creates a new version record that restores the Rego content from the
    target version and re-uploads it to OPA. The rollback is written to
    the Audit Wall for compliance traceability.

    Args:
        policy_id: The policy UUID.
        request: Rollback request with target version number.
        tenant: Tenant context from auth middleware.
        db: Primary database session.
        audit_db: Audit Wall database session.
        opa_client: OPA REST API client.

    Returns:
        The newly created version record (rollback snapshot).
    """
    from aumos_governance_engine.adapters.audit_wall import AuditTrailRepository
    from aumos_governance_engine.adapters.policy_versioning import (
        PolicyVersionRepository,
        PolicyVersionService,
    )

    version_repo = PolicyVersionRepository(db)
    audit_repo = AuditTrailRepository(audit_db)
    svc = PolicyVersionService(
        version_repo=version_repo,
        opa_client=opa_client,
        audit_trail_repo=audit_repo,
    )

    new_version = await svc.rollback_to_version(
        tenant=tenant,
        policy_id=policy_id,
        target_version_number=request.target_version_number,
        rolled_back_by=tenant.user_id,
    )

    return PolicyVersionResponse(
        id=new_version.id,
        tenant_id=new_version.tenant_id,
        policy_id=new_version.policy_id,
        version_number=new_version.version_number,
        rego_content=new_version.rego_content,
        sha256_hash=new_version.sha256_hash,
        change_description=new_version.change_description,
        authored_by=new_version.authored_by,
        activated_at=new_version.activated_at,
        is_current=new_version.is_current,
        created_at=new_version.created_at,
    )


# ---------------------------------------------------------------------------
# Gap 197 — Decision Analytics
# ---------------------------------------------------------------------------


@router.get(
    "/policies/{policy_id}/analytics/summary",
    response_model=DecisionSummaryResponse,
)
async def get_decision_summary(
    policy_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> DecisionSummaryResponse:
    """Get aggregated decision analytics for a policy.

    Returns total evaluations, allow/deny counts, allow rate, and average
    latency over the past 7 days.

    Args:
        policy_id: The policy UUID.
        tenant: Tenant context from auth middleware.
        db: Database session.

    Returns:
        Decision analytics summary.
    """
    from aumos_governance_engine.adapters.decision_analytics import (
        DecisionAnalyticsService,
        PolicyEvaluationLogRepository,
    )

    log_repo = PolicyEvaluationLogRepository(db)
    svc = DecisionAnalyticsService(eval_log_repo=log_repo)
    summary = await svc.get_decision_summary(tenant=tenant, policy_id=policy_id)
    return DecisionSummaryResponse(**summary)


@router.get(
    "/policies/{policy_id}/analytics/latency",
    response_model=LatencyPercentilesResponse,
)
async def get_latency_percentiles(
    policy_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> LatencyPercentilesResponse:
    """Get P50/P95/P99 evaluation latency percentiles for a policy.

    Args:
        policy_id: The policy UUID.
        tenant: Tenant context from auth middleware.
        db: Database session.

    Returns:
        Latency percentiles in milliseconds.
    """
    from aumos_governance_engine.adapters.decision_analytics import (
        DecisionAnalyticsService,
        PolicyEvaluationLogRepository,
    )

    log_repo = PolicyEvaluationLogRepository(db)
    svc = DecisionAnalyticsService(eval_log_repo=log_repo)
    percentiles = await svc.get_latency_percentiles(tenant=tenant, policy_id=policy_id)
    return LatencyPercentilesResponse(**percentiles)


# ---------------------------------------------------------------------------
# Gap 198 — Rego Authoring UI (validation backend)
# ---------------------------------------------------------------------------


@router.post("/policies/validate-rego", response_model=RegoValidationResponse)
async def validate_rego(
    request: RegoValidationRequest,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    opa_client: Annotated[OPAClient, Depends(lambda: OPAClient())],
) -> RegoValidationResponse:
    """Validate Rego source code without saving or activating it.

    Sends the Rego to OPA's parse endpoint to check for syntax errors.
    Returns the parsed package name and rule names for the authoring UI.

    Args:
        request: Rego validation request with source content.
        tenant: Tenant context from auth middleware.
        opa_client: OPA REST API client.

    Returns:
        Validation result with errors, warnings, package name, and rules.
    """
    try:
        parse_result = await opa_client.parse_module(request.rego_content)
        return RegoValidationResponse(
            valid=True,
            errors=[],
            warnings=[],
            package_name=parse_result.get("package_name"),
            rules=parse_result.get("rules", []),
        )
    except Exception as err:
        return RegoValidationResponse(
            valid=False,
            errors=[str(err)],
            warnings=[],
            package_name=None,
            rules=[],
        )


# ---------------------------------------------------------------------------
# Gap 199 — OPA Bundle Distribution
# ---------------------------------------------------------------------------


@router.get("/bundles/status", response_model=BundleStatusResponse)
async def get_bundle_status(
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> BundleStatusResponse:
    """Get OPA bundle distribution status for all sidecars.

    Returns the current bundle ETag and status for all registered
    OPA sidecar instances, indicating which are up-to-date.

    Args:
        tenant: Tenant context from auth middleware.
        db: Database session.

    Returns:
        Bundle status report.
    """
    from aumos_governance_engine.adapters.bundle_service import (
        BundleService,
        OPASidecarStatusRepository,
    )

    sidecar_repo = OPASidecarStatusRepository(db)
    svc = BundleService(policy_session=db, sidecar_repo=sidecar_repo)
    status = await svc.get_bundle_status(tenant=tenant)
    return BundleStatusResponse(**status)


@router.get("/bundles/download")
async def download_bundle(
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    if_none_match: str | None = None,
) -> Any:
    """Download the current OPA policy bundle as a .tar.gz archive.

    Supports ETag-based version negotiation via the If-None-Match header.
    Returns 304 Not Modified if the bundle has not changed since the
    client's last download.

    Args:
        tenant: Tenant context from auth middleware.
        db: Database session.
        if_none_match: Optional ETag from client for version negotiation.

    Returns:
        The .tar.gz bundle as a streaming response, or 304 if up-to-date.
    """
    from fastapi import Response
    from fastapi.responses import Response as FastAPIResponse
    from aumos_governance_engine.adapters.bundle_service import (
        BundleService,
        OPASidecarStatusRepository,
    )

    sidecar_repo = OPASidecarStatusRepository(db)
    svc = BundleService(policy_session=db, sidecar_repo=sidecar_repo)
    bundle_bytes, etag = await svc.build_bundle(tenant=tenant)

    if if_none_match and if_none_match == etag:
        return FastAPIResponse(status_code=304)

    return FastAPIResponse(
        content=bundle_bytes,
        media_type="application/gzip",
        headers={
            "Content-Disposition": "attachment; filename=aumos-opa-bundle.tar.gz",
            "ETag": etag,
        },
    )


# ---------------------------------------------------------------------------
# Gap 201 — External Evidence Import
# ---------------------------------------------------------------------------


@router.post(
    "/evidence/import/jira",
    response_model=ExternalEvidenceImportResponse,
    status_code=201,
)
async def import_jira_evidence(
    request: JiraEvidenceImportRequest,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> ExternalEvidenceImportResponse:
    """Import a Jira issue as a compliance evidence record.

    Fetches the Jira issue via the REST API and creates an EvidenceRecord
    linked to the specified compliance workflow.

    Args:
        request: Jira import request with issue key and workflow ID.
        tenant: Tenant context from auth middleware.
        db: Database session.

    Returns:
        Import result with evidence record ID and status.
    """
    from aumos_governance_engine.adapters.external_evidence import (
        ExternalEvidenceImportRepository,
        JiraEvidenceAdapter,
    )
    from aumos_governance_engine.adapters.repositories import EvidenceRepository
    from aumos_governance_engine.core.services import get_governance_settings

    settings = get_governance_settings()
    import_repo = ExternalEvidenceImportRepository(db)
    evidence_repo = EvidenceRepository(db)
    adapter = JiraEvidenceAdapter(
        jira_base_url=settings.jira_base_url,
        jira_email=settings.jira_email,
        jira_api_token=settings.jira_api_token,
        import_repo=import_repo,
        evidence_repo=evidence_repo,
    )
    result = await adapter.import_issue(
        tenant=tenant,
        workflow_id=request.workflow_id,
        issue_key=request.issue_key,
        control_ids=request.control_ids,
    )
    return ExternalEvidenceImportResponse(**result)


@router.post(
    "/evidence/import/servicenow",
    response_model=ExternalEvidenceImportResponse,
    status_code=201,
)
async def import_servicenow_evidence(
    request: ServiceNowEvidenceImportRequest,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> ExternalEvidenceImportResponse:
    """Import a ServiceNow ticket as a compliance evidence record.

    Fetches the ServiceNow record via the Table API and creates an
    EvidenceRecord linked to the specified compliance workflow.

    Args:
        request: ServiceNow import request with table, sys_id, and workflow ID.
        tenant: Tenant context from auth middleware.
        db: Database session.

    Returns:
        Import result with evidence record ID and status.
    """
    from aumos_governance_engine.adapters.external_evidence import (
        ExternalEvidenceImportRepository,
        ServiceNowAdapter,
    )
    from aumos_governance_engine.adapters.repositories import EvidenceRepository
    from aumos_governance_engine.core.services import get_governance_settings

    settings = get_governance_settings()
    import_repo = ExternalEvidenceImportRepository(db)
    evidence_repo = EvidenceRepository(db)
    adapter = ServiceNowAdapter(
        snow_instance_url=settings.servicenow_instance_url,
        snow_username=settings.servicenow_username,
        snow_password=settings.servicenow_password,
        import_repo=import_repo,
        evidence_repo=evidence_repo,
    )
    result = await adapter.import_ticket(
        tenant=tenant,
        workflow_id=request.workflow_id,
        table=request.table,
        sys_id=request.sys_id,
        control_ids=request.control_ids,
    )
    return ExternalEvidenceImportResponse(**result)


# ---------------------------------------------------------------------------
# Gap 200 — Compliance Workflow Templates
# ---------------------------------------------------------------------------


@router.get("/compliance/templates", response_model=WorkflowTemplateListResponse)
async def list_compliance_templates(
    tenant: Annotated[TenantContext, Depends(get_current_user)],
) -> WorkflowTemplateListResponse:
    """List all available compliance workflow templates.

    Returns summary metadata for all pre-built regulation templates
    (SOC 2, ISO 27001, HIPAA, ISO 42001, EU AI Act, FedRAMP Moderate).
    Templates can be instantiated using POST /compliance/workflows/from-template.

    Args:
        tenant: Tenant context from auth middleware.

    Returns:
        List of template summaries with control and milestone counts.
    """
    from aumos_governance_engine.core.template_service import WorkflowTemplate, _TEMPLATE_DIR

    summaries = []
    if _TEMPLATE_DIR.exists():
        import yaml as _yaml

        for yaml_file in sorted(_TEMPLATE_DIR.glob("*.yaml")):
            try:
                raw = _yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                template = WorkflowTemplate(raw)
                summaries.append(WorkflowTemplateSummary(**template.to_summary_dict()))
            except Exception:
                pass

    return WorkflowTemplateListResponse(templates=summaries)


@router.post(
    "/compliance/workflows/from-template",
    response_model=ComplianceWorkflowResponse,
    status_code=201,
)
async def create_workflow_from_template(
    request: WorkflowFromTemplateRequest,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    audit_db: Annotated[AsyncSession, Depends(get_audit_db_session)],
) -> ComplianceWorkflowResponse:
    """Instantiate a compliance workflow from a pre-built regulation template.

    Creates a new ComplianceWorkflow pre-populated with the control IDs,
    required evidence types, and review milestones defined in the template.
    Writes an Audit Wall entry for the instantiation.

    Args:
        request: Template instantiation request with regulation code and name.
        tenant: Tenant context from auth middleware.
        db: Primary database session.
        audit_db: Audit Wall database session.

    Returns:
        The newly created compliance workflow.

    Raises:
        404: If the specified regulation code does not have a template.
        422: If the workflow name is invalid.
    """
    from aumos_governance_engine.adapters.audit_wall import AuditTrailRepository as _AuditTrailRepo
    from aumos_governance_engine.core.template_service import ComplianceTemplateService

    workflow_repo = ComplianceWorkflowRepository(db)
    audit_repo = _AuditTrailRepo(audit_db)

    svc = ComplianceTemplateService(
        workflow_repo=workflow_repo,
        audit_repo=audit_repo,
    )

    workflow = await svc.instantiate_from_template(
        tenant=tenant,
        regulation_code=request.regulation_code,
        workflow_name=request.name,
        actor_id=tenant.user_id,
        assigned_to=request.assigned_to,
        notes=request.notes,
        duration_days=request.duration_days,
    )

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
