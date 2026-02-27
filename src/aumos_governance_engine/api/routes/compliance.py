"""P1.1 Compliance-as-Code API routes.

FastAPI endpoints for the compliance evaluation engine:
- POST /api/v1/compliance/evaluate             — evaluate a model against regulations
- GET  /api/v1/compliance/evaluations/{id}     — get evaluation results
- GET  /api/v1/compliance/evaluations/{id}/evidence-package — download ZIP
- GET  /api/v1/compliance/policies             — list active compliance policies
- POST /api/v1/compliance/policies/{id}/evaluate-impact — impact assessment
- GET  /api/v1/compliance/dashboard/{tenant_id} — compliance dashboard

Routes are thin: business logic lives in ComplianceAsCodeService.
"""

import io
import json
import uuid
import zipfile
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.auth import TenantContext, get_current_user
from aumos_common.database import get_db_session
from aumos_common.observability import get_logger

from aumos_governance_engine.compliance_as_code.engine import (
    ComplianceEngine,
    ComplianceEvaluationResult,
    MockOPAEvaluator,
    create_default_engine,
)
from aumos_governance_engine.compliance_as_code.evidence_mapper import (
    compute_regulation_compliance_score,
)
from aumos_governance_engine.compliance_as_code.policy_registry import PolicyRegistry
from aumos_governance_engine.compliance_as_code.regulatory_inventory import (
    build_regulation_metadata,
    list_regulations,
)
from aumos_governance_engine.core.models import (
    ComplianceEvaluation,
    ComplianceEvidenceItem,
    CompliancePolicyVersion,
)

logger = get_logger(__name__)

compliance_router = APIRouter(prefix="/compliance", tags=["compliance-as-code"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class ComplianceEvaluateRequest(BaseModel):
    """Request body for POST /compliance/evaluate."""

    model_id: str = Field(
        description="Identifier of the AI model to evaluate",
        min_length=1,
        max_length=255,
    )
    regulations: list[str] = Field(
        description="List of regulation codes to evaluate against",
        min_length=1,
    )
    input_data: dict[str, Any] = Field(
        description=(
            "Structured input describing the AI system. "
            "Must include 'implemented_controls' (list[str]) at minimum. "
            "Optional: 'risk_tier' (str), 'audit_log_references' (list[str])."
        ),
    )
    triggered_by: str = Field(
        default="api",
        description="What triggered this evaluation: api | scheduled | ci_cd | manual",
    )
    article_filter: list[str] | None = Field(
        default=None,
        description="Optional list of article refs to evaluate (evaluates all if omitted)",
    )


class ArticleResultSchema(BaseModel):
    """Schema for a per-article evaluation result."""

    regulation: str
    article_ref: str
    article_title: str
    status: str
    implemented_controls: list[str]
    missing_controls: list[str]
    violations: list[str]
    score: float
    weight: float


class ComplianceEvaluateResponse(BaseModel):
    """Response schema for POST /compliance/evaluate."""

    evaluation_id: uuid.UUID
    model_id: str
    tenant_id: uuid.UUID
    triggered_by: str
    regulations_evaluated: list[str]
    overall_compliant: bool
    compliant_count: int
    non_compliant_count: int
    partial_count: int
    not_applicable_count: int
    compliance_scores: dict[str, float]
    overall_score: float
    article_results: list[ArticleResultSchema]
    evaluated_at: datetime
    evaluation_duration_ms: float


class CompliancePolicyResponse(BaseModel):
    """Response schema for a compliance policy listing."""

    policy_id: str
    regulation: str
    article: str
    version: int
    content_hash: str
    legal_review_status: str
    effective_date: datetime | None


class ComplianceDashboardRegulation(BaseModel):
    """Per-regulation summary for the compliance dashboard."""

    regulation: str
    regulation_name: str
    total_evaluations: int
    last_evaluation_at: datetime | None
    overall_compliant: bool | None
    compliance_score: float | None
    non_compliant_count: int
    partial_count: int


class ComplianceDashboardResponse(BaseModel):
    """Response schema for GET /compliance/dashboard/{tenant_id}."""

    tenant_id: uuid.UUID
    generated_at: datetime
    total_evaluations: int
    regulations: list[ComplianceDashboardRegulation]


class ImpactAssessmentRequest(BaseModel):
    """Request body for POST /compliance/policies/{id}/evaluate-impact."""

    regulation: str = Field(description="Regulation code")
    article_ref: str = Field(description="Article reference to assess")
    current_state: dict[str, Any] = Field(description="Current system state")
    proposed_changes: dict[str, Any] = Field(description="Proposed changes to assess")


class ImpactAssessmentResponse(BaseModel):
    """Response schema for impact assessment."""

    policy_id: uuid.UUID
    regulation: str
    article_ref: str
    impact: str  # positive | negative | neutral
    current_status: str
    proposed_status: str
    current_violations: list[str]
    proposed_violations: list[str]
    new_violations: list[str]
    resolved_violations: list[str]


# ---------------------------------------------------------------------------
# Dependency factories
# ---------------------------------------------------------------------------


def get_compliance_engine() -> ComplianceEngine:
    """Create a ComplianceEngine instance for request handling.

    Returns:
        A ComplianceEngine with mock OPA evaluator.
    """
    return create_default_engine()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@compliance_router.post(
    "/evaluate",
    response_model=ComplianceEvaluateResponse,
    status_code=200,
    summary="Evaluate model compliance",
)
async def evaluate_compliance(
    request: ComplianceEvaluateRequest,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    engine: Annotated[ComplianceEngine, Depends(get_compliance_engine)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> ComplianceEvaluateResponse:
    """Evaluate an AI model against specified regulatory frameworks.

    Runs policy evaluation for each article in each specified regulation
    and returns compliance status with evidence. Guaranteed to complete
    within 60 seconds.

    Args:
        request: Evaluation request with model ID, regulations, and input data.
        tenant: Authenticated tenant context.
        engine: Injected ComplianceEngine.
        session: Database session for persisting evaluation results.

    Returns:
        Compliance evaluation result with per-article status and scores.
    """
    logger.info(
        "POST /compliance/evaluate",
        tenant_id=str(tenant.tenant_id),
        model_id=request.model_id,
        regulations=request.regulations,
    )

    result = await engine.evaluate(
        model_id=request.model_id,
        tenant_id=tenant.tenant_id,
        regulations=request.regulations,
        input_data=request.input_data,
        triggered_by=request.triggered_by,
        article_filter=request.article_filter,
    )

    # Persist evaluation to database
    await _persist_evaluation(session, result, tenant.tenant_id)

    return ComplianceEvaluateResponse(
        evaluation_id=result.evaluation_id,
        model_id=result.model_id,
        tenant_id=result.tenant_id,
        triggered_by=result.triggered_by,
        regulations_evaluated=result.regulations_evaluated,
        overall_compliant=result.overall_compliant,
        compliant_count=result.compliant_count,
        non_compliant_count=result.non_compliant_count,
        partial_count=result.partial_count,
        not_applicable_count=result.not_applicable_count,
        compliance_scores=result.compliance_scores,
        overall_score=result.overall_score,
        article_results=[
            ArticleResultSchema(
                regulation=r.regulation,
                article_ref=r.article_ref,
                article_title=r.article_title,
                status=r.status,
                implemented_controls=r.implemented_controls,
                missing_controls=r.missing_controls,
                violations=r.violations,
                score=r.score,
                weight=r.weight,
            )
            for r in result.article_results
        ],
        evaluated_at=result.evaluated_at,
        evaluation_duration_ms=result.evaluation_duration_ms,
    )


@compliance_router.get(
    "/evaluations/{evaluation_id}",
    response_model=ComplianceEvaluateResponse,
    summary="Get evaluation results",
)
async def get_evaluation(
    evaluation_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> ComplianceEvaluateResponse:
    """Retrieve a previously run compliance evaluation by ID.

    Args:
        evaluation_id: The evaluation UUID.
        tenant: Authenticated tenant context.
        session: Database session.

    Returns:
        The compliance evaluation result.

    Raises:
        HTTPException 404: If the evaluation is not found.
    """
    from sqlalchemy import select

    stmt = select(ComplianceEvaluation).where(
        ComplianceEvaluation.id == evaluation_id,
        ComplianceEvaluation.tenant_id == tenant.tenant_id,
    )
    db_result = await session.execute(stmt)
    evaluation = db_result.scalar_one_or_none()

    if evaluation is None:
        raise HTTPException(
            status_code=404,
            detail=f"Evaluation {evaluation_id} not found",
        )

    results_data: dict[str, Any] = evaluation.results or {}
    article_results = [
        ArticleResultSchema(
            regulation=r.get("regulation", ""),
            article_ref=r.get("article_ref", ""),
            article_title=r.get("article_title", r.get("article_ref", "")),
            status=r.get("status", "unknown"),
            implemented_controls=r.get("implemented_controls", []),
            missing_controls=r.get("missing_controls", []),
            violations=r.get("violations", []),
            score=float(r.get("score", 0.0)),
            weight=float(r.get("weight", 1.0)),
        )
        for r in results_data.get("article_results", [])
    ]

    return ComplianceEvaluateResponse(
        evaluation_id=evaluation.id,
        model_id=evaluation.model_id,
        tenant_id=evaluation.tenant_id,
        triggered_by=evaluation.triggered_by,
        regulations_evaluated=evaluation.regulations_evaluated,
        overall_compliant=evaluation.overall_compliant,
        compliant_count=evaluation.compliant_count,
        non_compliant_count=evaluation.non_compliant_count,
        partial_count=evaluation.partial_count,
        not_applicable_count=evaluation.not_applicable_count,
        compliance_scores=results_data.get("compliance_scores", {}),
        overall_score=float(results_data.get("overall_score", 0.0)),
        article_results=article_results,
        evaluated_at=evaluation.evaluated_at,
        evaluation_duration_ms=float(evaluation.evaluation_duration_ms),
    )


@compliance_router.get(
    "/evaluations/{evaluation_id}/evidence-package",
    summary="Download evidence package",
    response_class=StreamingResponse,
)
async def download_evidence_package(
    evaluation_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> StreamingResponse:
    """Download a ZIP evidence package for a compliance evaluation.

    The ZIP contains:
    - manifest.json: Package summary and metadata
    - evidence_items.json: All collected evidence items
    - per_article_results.json: Detailed per-article evaluation results

    Args:
        evaluation_id: The evaluation UUID.
        tenant: Authenticated tenant context.
        session: Database session.

    Returns:
        StreamingResponse with ZIP content.

    Raises:
        HTTPException 404: If the evaluation is not found.
    """
    from sqlalchemy import select

    stmt = select(ComplianceEvaluation).where(
        ComplianceEvaluation.id == evaluation_id,
        ComplianceEvaluation.tenant_id == tenant.tenant_id,
    )
    db_result = await session.execute(stmt)
    evaluation = db_result.scalar_one_or_none()

    if evaluation is None:
        raise HTTPException(
            status_code=404,
            detail=f"Evaluation {evaluation_id} not found",
        )

    # Fetch evidence items
    evidence_stmt = select(ComplianceEvidenceItem).where(
        ComplianceEvidenceItem.evaluation_id == evaluation_id,
        ComplianceEvidenceItem.tenant_id == tenant.tenant_id,
    )
    evidence_result = await session.execute(evidence_stmt)
    evidence_items = evidence_result.scalars().all()

    # Build ZIP in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zip_file:
        # manifest.json
        manifest = {
            "package_version": "1.0",
            "evaluation_id": str(evaluation_id),
            "tenant_id": str(tenant.tenant_id),
            "model_id": evaluation.model_id,
            "generated_at": datetime.now(UTC).isoformat(),
            "regulations_evaluated": evaluation.regulations_evaluated,
            "overall_compliant": evaluation.overall_compliant,
            "compliant_count": evaluation.compliant_count,
            "non_compliant_count": evaluation.non_compliant_count,
        }
        zip_file.writestr("manifest.json", json.dumps(manifest, indent=2))

        # evidence_items.json
        evidence_data = [
            {
                "id": str(item.id),
                "regulation": item.regulation,
                "article": item.article,
                "requirement": item.requirement,
                "evidence_type": item.evidence_type,
                "evidence_ref": item.evidence_ref,
                "collected_at": item.collected_at.isoformat(),
                "expires_at": item.expires_at.isoformat() if item.expires_at else None,
            }
            for item in evidence_items
        ]
        zip_file.writestr("evidence_items.json", json.dumps(evidence_data, indent=2))

        # per_article_results.json
        results_data = evaluation.results or {}
        zip_file.writestr(
            "per_article_results.json",
            json.dumps(results_data, indent=2),
        )

    zip_buffer.seek(0)
    filename = f"compliance_evidence_{evaluation_id}.zip"

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@compliance_router.get(
    "/policies",
    response_model=list[CompliancePolicyResponse],
    summary="List active compliance policies",
)
async def list_compliance_policies(
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    regulation: str | None = Query(default=None, description="Filter by regulation code"),
) -> list[CompliancePolicyResponse]:
    """List active compliance policies for the tenant.

    Returns all compliance policy versions that are in approved status.
    Policies represent the versioned Rego/Python rules used to evaluate
    AI systems against regulatory requirements.

    Args:
        tenant: Authenticated tenant context.
        session: Database session.
        regulation: Optional regulation code filter.

    Returns:
        List of active compliance policies.
    """
    from sqlalchemy import select

    stmt = select(CompliancePolicyVersion).where(
        CompliancePolicyVersion.tenant_id == tenant.tenant_id,
        CompliancePolicyVersion.legal_review_status == "approved",
    )
    if regulation:
        stmt = stmt.where(CompliancePolicyVersion.regulation == regulation)

    result = await session.execute(stmt)
    policies = result.scalars().all()

    return [
        CompliancePolicyResponse(
            policy_id=p.policy_id,
            regulation=p.regulation,
            article=p.article,
            version=p.version,
            content_hash=p.content_hash,
            legal_review_status=p.legal_review_status,
            effective_date=p.effective_date,
        )
        for p in policies
    ]


@compliance_router.post(
    "/policies/{policy_id}/evaluate-impact",
    response_model=ImpactAssessmentResponse,
    summary="Evaluate policy change impact",
)
async def evaluate_policy_impact(
    policy_id: uuid.UUID,
    request: ImpactAssessmentRequest,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    engine: Annotated[ComplianceEngine, Depends(get_compliance_engine)],
) -> ImpactAssessmentResponse:
    """Assess the compliance impact of proposed system changes.

    Evaluates both current and proposed state and returns a diff showing
    how the changes would affect compliance posture for a specific article.

    Args:
        policy_id: The compliance policy UUID being assessed.
        request: Impact assessment request with current and proposed state.
        tenant: Authenticated tenant context.
        engine: Injected ComplianceEngine.

    Returns:
        Impact assessment showing before/after compliance comparison.
    """
    logger.info(
        "POST /compliance/policies/{policy_id}/evaluate-impact",
        tenant_id=str(tenant.tenant_id),
        policy_id=str(policy_id),
        regulation=request.regulation,
        article_ref=request.article_ref,
    )

    impact_result = await engine.evaluate_impact(
        policy_id=policy_id,
        regulation=request.regulation,
        article_ref=request.article_ref,
        proposed_changes=request.proposed_changes,
        current_state=request.current_state,
    )

    return ImpactAssessmentResponse(
        policy_id=policy_id,
        regulation=impact_result["regulation"],
        article_ref=impact_result["article_ref"],
        impact=impact_result["impact"],
        current_status=impact_result["current_status"],
        proposed_status=impact_result["proposed_status"],
        current_violations=impact_result["current_violations"],
        proposed_violations=impact_result["proposed_violations"],
        new_violations=impact_result["new_violations"],
        resolved_violations=impact_result["resolved_violations"],
    )


@compliance_router.get(
    "/dashboard/{tenant_id}",
    response_model=ComplianceDashboardResponse,
    summary="Get compliance dashboard",
)
async def get_compliance_dashboard(
    tenant_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> ComplianceDashboardResponse:
    """Get the compliance dashboard for a tenant.

    Aggregates compliance evaluation results across all regulations for
    the specified tenant. Shows current compliance posture, scores, and
    trends.

    Args:
        tenant_id: The tenant UUID to get dashboard for.
        tenant: Authenticated tenant context (must match tenant_id).
        session: Database session.

    Returns:
        Compliance dashboard with per-regulation summaries.

    Raises:
        HTTPException 403: If tenant_id does not match authenticated tenant.
    """
    if tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=403,
            detail="Cannot access dashboard for a different tenant",
        )

    from sqlalchemy import func, select

    # Get all evaluations for this tenant
    stmt = (
        select(ComplianceEvaluation)
        .where(ComplianceEvaluation.tenant_id == tenant_id)
        .order_by(ComplianceEvaluation.evaluated_at.desc())
    )
    result = await session.execute(stmt)
    evaluations = result.scalars().all()

    # Build per-regulation summaries
    reg_data: dict[str, dict[str, Any]] = {}

    all_regulations = {r.code for r in list_regulations()}
    for evaluation in evaluations:
        for reg_code in evaluation.regulations_evaluated:
            if reg_code not in reg_data:
                reg_data[reg_code] = {
                    "total_evaluations": 0,
                    "last_evaluation_at": None,
                    "overall_compliant": None,
                    "compliance_score": None,
                    "non_compliant_count": 0,
                    "partial_count": 0,
                }

            data = reg_data[reg_code]
            data["total_evaluations"] += 1

            if data["last_evaluation_at"] is None or (
                evaluation.evaluated_at > data["last_evaluation_at"]
            ):
                data["last_evaluation_at"] = evaluation.evaluated_at
                data["overall_compliant"] = evaluation.overall_compliant
                data["non_compliant_count"] = evaluation.non_compliant_count
                data["partial_count"] = evaluation.partial_count

                results = evaluation.results or {}
                scores = results.get("compliance_scores", {})
                if reg_code in scores:
                    data["compliance_score"] = float(scores[reg_code])

    # Build response
    reg_metadata = {r.code: r for r in list_regulations()}
    regulation_summaries = [
        ComplianceDashboardRegulation(
            regulation=code,
            regulation_name=reg_metadata[code].name if code in reg_metadata else code,
            total_evaluations=data["total_evaluations"],
            last_evaluation_at=data["last_evaluation_at"],
            overall_compliant=data["overall_compliant"],
            compliance_score=data["compliance_score"],
            non_compliant_count=data["non_compliant_count"],
            partial_count=data["partial_count"],
        )
        for code, data in reg_data.items()
    ]

    return ComplianceDashboardResponse(
        tenant_id=tenant_id,
        generated_at=datetime.now(UTC),
        total_evaluations=len(evaluations),
        regulations=regulation_summaries,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


async def _persist_evaluation(
    session: AsyncSession,
    result: ComplianceEvaluationResult,
    tenant_id: uuid.UUID,
) -> None:
    """Persist a compliance evaluation result to the database.

    Args:
        session: Database session.
        result: The evaluation result to persist.
        tenant_id: Owning tenant UUID.
    """
    evaluation = ComplianceEvaluation(
        id=result.evaluation_id,
        tenant_id=tenant_id,
        model_id=result.model_id,
        triggered_by=result.triggered_by,
        regulations_evaluated=result.regulations_evaluated,
        results={
            "article_results": [
                {
                    "regulation": r.regulation,
                    "article_ref": r.article_ref,
                    "article_title": r.article_title,
                    "status": r.status,
                    "implemented_controls": r.implemented_controls,
                    "missing_controls": r.missing_controls,
                    "violations": r.violations,
                    "score": r.score,
                    "weight": r.weight,
                }
                for r in result.article_results
            ],
            "compliance_scores": result.compliance_scores,
            "overall_score": result.overall_score,
            "package_manifest": result.package_manifest,
        },
        overall_compliant=result.overall_compliant,
        compliant_count=result.compliant_count,
        non_compliant_count=result.non_compliant_count,
        partial_count=result.partial_count,
        not_applicable_count=result.not_applicable_count,
        evaluated_at=result.evaluated_at,
        evaluation_duration_ms=int(result.evaluation_duration_ms),
    )
    session.add(evaluation)

    # Persist evidence items
    for item in result.evidence_items:
        evidence = ComplianceEvidenceItem(
            id=item.evidence_id,
            tenant_id=tenant_id,
            evaluation_id=result.evaluation_id,
            regulation=item.regulation,
            article=item.article_ref,
            requirement=item.requirement_summary,
            evidence_type=item.evidence_type,
            evidence_ref=item.evidence_data,
            collected_at=item.collected_at,
            expires_at=item.expires_at,
        )
        session.add(evidence)

    try:
        await session.commit()
    except Exception:
        await session.rollback()
        logger.error(
            "Failed to persist compliance evaluation",
            evaluation_id=str(result.evaluation_id),
        )
        raise
