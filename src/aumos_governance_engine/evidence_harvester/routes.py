"""FastAPI routes for the Autonomous Compliance Evidence Harvester API.

All endpoints require a valid tenant JWT (via get_current_tenant from
aumos-common) and never trust tenant_id from request bodies. Tenant context
is always extracted from the authenticated token.

Routes:
    GET  /evidence/harvest-status          — coverage metrics and gaps per regulation
    POST /evidence/packages/generate       — generate an evidence package
    GET  /evidence/packages/{package_id}   — get package generation status
    GET  /evidence/by-control              — query evidence by regulation and control
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict, Field

from aumos_common.auth import TenantContext, get_current_tenant

from aumos_governance_engine.evidence_harvester.agent import (
    EvidenceHarvesterAgent,
    RuleStore,
)
from aumos_governance_engine.evidence_harvester.evidence_store import EvidenceStore
from aumos_governance_engine.evidence_harvester.packager import EvidencePackager

router = APIRouter(prefix="/evidence", tags=["Evidence Harvester"])

# ---------------------------------------------------------------------------
# Shared singletons (in production these would be injected via FastAPI deps)
# ---------------------------------------------------------------------------

_shared_rule_store = RuleStore()
_shared_evidence_store = EvidenceStore()
_shared_agent = EvidenceHarvesterAgent(
    rule_store=_shared_rule_store,
    evidence_store=_shared_evidence_store,
)
_shared_packager = EvidencePackager(evidence_store=_shared_evidence_store)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class ControlCoverageItem(BaseModel):
    """Coverage status for a single control.

    Attributes:
        control_id: The control identifier.
        covered: Whether at least one evidence item exists for this control.
        evidence_count: Number of evidence items for this control.
    """

    model_config = ConfigDict(frozen=True)

    control_id: str
    covered: bool
    evidence_count: int


class RegulationCoverageItem(BaseModel):
    """Coverage summary for a regulation.

    Attributes:
        regulation: The regulation code.
        overall_coverage: Fraction of required controls covered (0.0–1.0).
        total_required_controls: Total number of required controls.
        covered_controls: Number of controls with evidence.
        missing_controls: Control IDs with no evidence.
    """

    model_config = ConfigDict(frozen=True)

    regulation: str
    overall_coverage: float
    total_required_controls: int
    covered_controls: int
    missing_controls: list[str]


class HarvestStatusResponse(BaseModel):
    """Response containing coverage metrics across all queried regulations.

    Attributes:
        tenant_id: The authenticated tenant.
        as_of: Timestamp when coverage was computed.
        regulations: Per-regulation coverage summaries.
    """

    model_config = ConfigDict(frozen=True)

    tenant_id: str
    as_of: datetime
    regulations: list[RegulationCoverageItem]


class GeneratePackageRequest(BaseModel):
    """Request body for evidence package generation.

    Attributes:
        regulations: List of regulation codes to include.
        period_start: Start of the evidence collection period.
        period_end: End of the evidence collection period.
    """

    model_config = ConfigDict(frozen=True)

    regulations: list[str] = Field(
        ..., min_length=1, description="List of regulation codes (e.g., ['SOC2', 'HIPAA'])"
    )
    period_start: datetime = Field(
        ..., description="Start of the evidence period (ISO 8601, timezone-aware)"
    )
    period_end: datetime = Field(
        ..., description="End of the evidence period (ISO 8601, timezone-aware)"
    )


class PackageManifest(BaseModel):
    """Package manifest containing evidence hashes and totals.

    Attributes:
        total_evidence_items: Total number of evidence items in the package.
        evidence_hashes: Sorted list of SHA-256 hashes of all evidence payloads.
        manifest_hash: SHA-256 hash of the sorted evidence_hashes list.
    """

    model_config = ConfigDict(frozen=True)

    total_evidence_items: int
    evidence_hashes: list[str]
    manifest_hash: str


class GeneratePackageResponse(BaseModel):
    """Response containing a generated evidence package.

    Attributes:
        package_id: Unique identifier for this package.
        tenant_id: The authenticated tenant.
        generated_at: When the package was generated.
        period_start: Start of the evidence period.
        period_end: End of the evidence period.
        regulations: Regulations included.
        evidence_by_regulation: Nested dict: regulation → control → evidence_items.
        manifest: Package manifest for integrity verification.
        coverage_summary: Per-regulation coverage metrics.
    """

    model_config = ConfigDict(frozen=True)

    package_id: str
    tenant_id: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    regulations: list[str]
    evidence_by_regulation: dict[str, dict[str, list[dict[str, Any]]]]
    manifest: PackageManifest
    coverage_summary: dict[str, dict[str, Any]]


class EvidenceItem(BaseModel):
    """A single evidence item returned by by-control queries.

    Attributes:
        evidence_id: Unique identifier.
        regulation: Regulation code.
        control_id: Control identifier.
        evidence_type: Evidence classification.
        evidence_description: Human-readable description.
        source_event_id: The triggering event ID.
        collected_at: When collected.
        evidence_hash: SHA-256 of the evidence payload.
        retention_until: Mandatory retention deadline.
    """

    model_config = ConfigDict(frozen=True)

    evidence_id: str
    regulation: str
    control_id: str
    evidence_type: str
    evidence_description: str
    source_event_id: str
    collected_at: datetime
    evidence_hash: str
    retention_until: datetime


class EvidenceByControlResponse(BaseModel):
    """Paginated evidence records for a specific regulation/control.

    Attributes:
        tenant_id: The authenticated tenant.
        regulation: The queried regulation.
        control_id: The queried control (if filtered).
        items: Evidence records.
        total: Total count before pagination.
        page: Current page number.
        page_size: Records per page.
    """

    model_config = ConfigDict(frozen=True)

    tenant_id: str
    regulation: str | None
    control_id: str | None
    items: list[EvidenceItem]
    total: int
    page: int
    page_size: int


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


@router.get(
    "/harvest-status",
    response_model=HarvestStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get evidence coverage status and gaps per regulation",
)
async def get_harvest_status(
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    regulations: Annotated[
        list[str],
        Query(description="Regulation codes to include in coverage report"),
    ] = ["SOC2", "EU_AI_ACT", "HIPAA"],
) -> HarvestStatusResponse:
    """Return evidence coverage metrics and gaps for the authenticated tenant.

    For each requested regulation, computes what fraction of required controls
    have at least one evidence item collected. Returns a list of covered and
    missing controls to help teams identify compliance gaps.

    Args:
        tenant: The authenticated tenant context (from JWT).
        regulations: Regulation codes to report on. Defaults to SOC2, EU_AI_ACT, HIPAA.

    Returns:
        HarvestStatusResponse with per-regulation coverage summaries.
    """
    tenant_id = str(tenant.tenant_id)
    regulation_summaries: list[RegulationCoverageItem] = []

    for regulation in regulations:
        coverage = await _shared_evidence_store.get_coverage(
            tenant_id=tenant_id,
            regulation=regulation,
        )
        regulation_summaries.append(
            RegulationCoverageItem(
                regulation=regulation,
                overall_coverage=coverage["overall"],
                total_required_controls=coverage["total_required"],
                covered_controls=coverage["total_covered"],
                missing_controls=coverage["missing_controls"],
            )
        )

    return HarvestStatusResponse(
        tenant_id=tenant_id,
        as_of=datetime.now(timezone.utc),
        regulations=regulation_summaries,
    )


@router.post(
    "/packages/generate",
    response_model=GeneratePackageResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate an evidence package for auditors",
)
async def generate_package(
    body: GeneratePackageRequest,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
) -> GeneratePackageResponse:
    """Generate a complete evidence package organized by regulation and control.

    The package is generated synchronously and returned in the response body.
    It includes all evidence items collected within the specified period,
    a cryptographic manifest for integrity verification, and coverage metrics.

    Args:
        body: The package generation request.
        tenant: The authenticated tenant context (from JWT).

    Returns:
        GeneratePackageResponse with the complete evidence package.
    """
    package = await _shared_packager.generate_package(
        tenant_id=str(tenant.tenant_id),
        regulations=body.regulations,
        period_start=body.period_start,
        period_end=body.period_end,
    )

    manifest_data = package["manifest"]

    return GeneratePackageResponse(
        package_id=package["package_id"],
        tenant_id=package["tenant_id"],
        generated_at=datetime.fromisoformat(package["generated_at"]),
        period_start=datetime.fromisoformat(package["period_start"]),
        period_end=datetime.fromisoformat(package["period_end"]),
        regulations=package["regulations"],
        evidence_by_regulation=package["evidence_by_regulation"],
        manifest=PackageManifest(
            total_evidence_items=manifest_data["total_evidence_items"],
            evidence_hashes=manifest_data["evidence_hashes"],
            manifest_hash=manifest_data["manifest_hash"],
        ),
        coverage_summary=package["coverage_summary"],
    )


@router.get(
    "/packages/{package_id}",
    status_code=status.HTTP_200_OK,
    summary="Get package generation status",
)
async def get_package_status(
    package_id: str,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
) -> dict[str, Any]:
    """Return the status of a previously generated evidence package.

    In the current implementation, packages are not persisted after generation.
    This endpoint returns a status indicating the package must be regenerated.

    Args:
        package_id: The UUID returned when the package was generated.
        tenant: The authenticated tenant context (from JWT).

    Returns:
        Dict with package_id, status, and message.
    """
    return await _shared_packager.get_package_status(
        package_id=package_id,
        tenant_id=str(tenant.tenant_id),
    )


@router.get(
    "/by-control",
    response_model=EvidenceByControlResponse,
    status_code=status.HTTP_200_OK,
    summary="Query evidence by regulation and control",
)
async def get_evidence_by_control(
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    regulation: Annotated[
        str | None,
        Query(description="Filter by regulation code (e.g., SOC2, HIPAA)"),
    ] = None,
    control_id: Annotated[
        str | None,
        Query(description="Filter by control ID (e.g., CC6.1, Art.10)"),
    ] = None,
    evidence_type: Annotated[
        str | None,
        Query(description="Filter by evidence type (log, configuration, attestation, artifact)"),
    ] = None,
    start_date: Annotated[
        datetime | None,
        Query(description="Filter by collected_at >= start_date"),
    ] = None,
    end_date: Annotated[
        datetime | None,
        Query(description="Filter by collected_at <= end_date"),
    ] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> EvidenceByControlResponse:
    """Query evidence records for the authenticated tenant with optional filters.

    Filters are ANDed together. Results are paginated and sorted by
    collected_at descending (most recent first).

    Args:
        tenant: The authenticated tenant context (from JWT).
        regulation: Optional regulation code filter.
        control_id: Optional control ID filter.
        evidence_type: Optional evidence type filter.
        start_date: Optional lower bound for collected_at.
        end_date: Optional upper bound for collected_at.
        page: Page number (1-indexed).
        page_size: Items per page (max 200).

    Returns:
        EvidenceByControlResponse with paginated evidence items.
    """
    tenant_id = str(tenant.tenant_id)

    records = await _shared_evidence_store.query(
        tenant_id=tenant_id,
        regulation=regulation,
        control_id=control_id,
        evidence_type=evidence_type,
        start_date=start_date,
        end_date=end_date,
        page=page,
        page_size=page_size,
    )

    # Get total count without pagination for the response metadata
    all_records = await _shared_evidence_store.query(
        tenant_id=tenant_id,
        regulation=regulation,
        control_id=control_id,
        evidence_type=evidence_type,
        start_date=start_date,
        end_date=end_date,
        page=1,
        page_size=100_000,
    )
    total = len(all_records)

    items = [
        EvidenceItem(
            evidence_id=r.evidence_id,
            regulation=r.regulation,
            control_id=r.control_id,
            evidence_type=r.evidence_type,
            evidence_description=r.evidence_description,
            source_event_id=r.source_event_id,
            collected_at=r.collected_at,
            evidence_hash=r.evidence_hash,
            retention_until=r.retention_until,
        )
        for r in records
    ]

    return EvidenceByControlResponse(
        tenant_id=tenant_id,
        regulation=regulation,
        control_id=control_id,
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )
