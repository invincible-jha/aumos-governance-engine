"""FastAPI routes for the Compliance Time Machine API.

All endpoints require a valid tenant JWT (via get_current_tenant from
aumos-common) and never trust tenant_id from request bodies. Tenant
context is always extracted from the authenticated token.

Routes:
    POST /time-machine/reconstruct       — reconstruct state at a timestamp
    GET  /time-machine/reconstructions/{id} — get cached reconstruction result
    GET  /time-machine/diff              — diff between two timestamps
    GET  /time-machine/audit-trail       — query audit trail for an entity
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from aumos_common.auth import TenantContext, get_current_tenant

from aumos_governance_engine.time_machine.event_store import StateChangeEventStore
from aumos_governance_engine.time_machine.reconstructor import SystemStateReconstructor

router = APIRouter(prefix="/time-machine", tags=["Compliance Time Machine"])

# ---------------------------------------------------------------------------
# Shared in-memory store and reconstructor (singleton for this module).
# In production these would be injected via FastAPI dependency providers.
# ---------------------------------------------------------------------------

_shared_store = StateChangeEventStore()
_shared_reconstructor = SystemStateReconstructor(_shared_store)

# In-memory cache for reconstruction results keyed by reconstruction_id
_reconstruction_cache: dict[str, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class ReconstructRequest(BaseModel):
    """Request body for state reconstruction.

    Attributes:
        target_timestamp: ISO 8601 datetime string specifying the point in
            time to reconstruct state at. Must be timezone-aware.
        entity_types: Optional list of entity types to include in the result.
            If omitted, all entity types are included.
    """

    model_config = ConfigDict(frozen=True)

    target_timestamp: datetime = Field(
        ..., description="Point in time to reconstruct state at (ISO 8601, timezone-aware)"
    )
    entity_types: list[str] | None = Field(
        default=None,
        description="Optional allow-list of entity types (MODEL, POLICY, etc.)",
    )


class ReconstructResponse(BaseModel):
    """Response containing a scheduled reconstruction job.

    Attributes:
        reconstruction_id: UUID to poll with GET /reconstructions/{id}.
        tenant_id: The tenant for whom state was reconstructed.
        target_timestamp: The target timestamp used.
        state: The reconstructed state keyed by entity_type then entity_id.
        reconstructed_at: When the reconstruction was performed.
    """

    model_config = ConfigDict(frozen=True)

    reconstruction_id: str = Field(..., description="UUID for this reconstruction result")
    tenant_id: str = Field(..., description="The tenant for whom state was reconstructed")
    target_timestamp: datetime = Field(..., description="The target timestamp used")
    state: dict[str, dict[str, Any]] = Field(
        ..., description="Reconstructed state: {entity_type: {entity_id: state}}"
    )
    reconstructed_at: datetime = Field(..., description="When the reconstruction was performed")


class DiffResponse(BaseModel):
    """Response containing the state diff between two timestamps.

    Attributes:
        tenant_id: The tenant for whom the diff was computed.
        from_timestamp: The earlier timestamp.
        to_timestamp: The later timestamp.
        added: Entities added between the two timestamps.
        modified: Entities modified between the two timestamps.
        deleted: Entities deleted between the two timestamps.
    """

    model_config = ConfigDict(frozen=True)

    tenant_id: str = Field(..., description="The tenant for whom the diff was computed")
    from_timestamp: datetime = Field(..., description="The earlier timestamp")
    to_timestamp: datetime = Field(..., description="The later timestamp")
    added: list[dict[str, Any]] = Field(..., description="Entities added in the window")
    modified: list[dict[str, Any]] = Field(..., description="Entities modified in the window")
    deleted: list[dict[str, Any]] = Field(..., description="Entities deleted in the window")


class AuditTrailEntry(BaseModel):
    """A single audit trail event record.

    Attributes:
        event_id: The unique event identifier.
        timestamp_ms: Unix epoch milliseconds when the event occurred.
        entity_type: The type of entity that changed.
        entity_id: The entity identifier.
        entity_version: The entity version at the time of the event.
        change_type: The nature of the change.
        actor_id: The actor who made the change.
        actor_type: The actor classification.
        source_service: The originating service.
        correlation_id: The request correlation ID.
    """

    model_config = ConfigDict(frozen=True)

    event_id: str
    timestamp_ms: int
    entity_type: str
    entity_id: str
    entity_version: str
    change_type: str
    actor_id: str
    actor_type: str
    source_service: str
    correlation_id: str


class AuditTrailResponse(BaseModel):
    """Response containing paginated audit trail entries.

    Attributes:
        tenant_id: The queried tenant.
        entity_type: Filtered entity type (if provided).
        entity_id: Filtered entity ID (if provided).
        entries: The matching audit trail entries.
        total: Total number of matching entries.
    """

    model_config = ConfigDict(frozen=True)

    tenant_id: str
    entity_type: str | None = None
    entity_id: str | None = None
    entries: list[AuditTrailEntry]
    total: int


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


@router.post(
    "/reconstruct",
    response_model=ReconstructResponse,
    status_code=status.HTTP_200_OK,
    summary="Reconstruct system state at a historical timestamp",
)
async def reconstruct_state(
    body: ReconstructRequest,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
) -> ReconstructResponse:
    """Reconstruct the governance system state at a historical timestamp.

    Returns the complete state of all (or filtered) governance entities
    as they were at the specified point in time. The tenant_id is taken
    from the authenticated JWT — body-supplied tenant_id is never trusted.

    Args:
        body: The reconstruction request containing target_timestamp and
            optional entity_types filter.
        tenant: The authenticated tenant context (from JWT).

    Returns:
        ReconstructResponse with the reconstructed state and a
        reconstruction_id for subsequent polling.
    """
    state = await _shared_reconstructor.reconstruct_at(
        tenant_id=str(tenant.tenant_id),
        target_timestamp=body.target_timestamp,
        entity_types=body.entity_types,
    )

    reconstruction_id = str(uuid.uuid4())
    reconstructed_at = datetime.now(timezone.utc)

    result: dict[str, Any] = {
        "reconstruction_id": reconstruction_id,
        "tenant_id": str(tenant.tenant_id),
        "target_timestamp": body.target_timestamp.isoformat(),
        "state": state,
        "reconstructed_at": reconstructed_at.isoformat(),
    }
    _reconstruction_cache[reconstruction_id] = result

    return ReconstructResponse(
        reconstruction_id=reconstruction_id,
        tenant_id=str(tenant.tenant_id),
        target_timestamp=body.target_timestamp,
        state=state,
        reconstructed_at=reconstructed_at,
    )


@router.get(
    "/reconstructions/{reconstruction_id}",
    response_model=ReconstructResponse,
    status_code=status.HTTP_200_OK,
    summary="Get a cached reconstruction result",
)
async def get_reconstruction(
    reconstruction_id: str,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
) -> ReconstructResponse:
    """Retrieve a previously computed reconstruction result.

    Looks up the cached reconstruction by its ID. Only returns results
    belonging to the authenticated tenant.

    Args:
        reconstruction_id: The UUID returned by POST /reconstruct.
        tenant: The authenticated tenant context (from JWT).

    Returns:
        The cached ReconstructResponse.

    Raises:
        HTTPException 404: If the reconstruction_id is not found or
            belongs to a different tenant.
    """
    cached = _reconstruction_cache.get(reconstruction_id)
    if cached is None or cached["tenant_id"] != str(tenant.tenant_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Reconstruction {reconstruction_id} not found",
        )

    return ReconstructResponse(
        reconstruction_id=cached["reconstruction_id"],
        tenant_id=cached["tenant_id"],
        target_timestamp=datetime.fromisoformat(cached["target_timestamp"]),
        state=cached["state"],
        reconstructed_at=datetime.fromisoformat(cached["reconstructed_at"]),
    )


@router.get(
    "/diff",
    response_model=DiffResponse,
    status_code=status.HTTP_200_OK,
    summary="Diff governance state between two timestamps",
)
async def diff_state(
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    from_timestamp: Annotated[
        datetime,
        Query(description="Start of diff window (ISO 8601, timezone-aware)"),
    ],
    to_timestamp: Annotated[
        datetime,
        Query(description="End of diff window (ISO 8601, timezone-aware)"),
    ],
) -> DiffResponse:
    """Compute what changed in governance state between two timestamps.

    Returns entities that were added, modified, or deleted between
    from_timestamp and to_timestamp for the authenticated tenant.

    Args:
        tenant: The authenticated tenant context (from JWT).
        from_timestamp: The earlier bound of the diff window.
        to_timestamp: The later bound of the diff window.

    Returns:
        DiffResponse with added, modified, and deleted entity lists.

    Raises:
        HTTPException 400: If from_timestamp is not before to_timestamp.
    """
    if from_timestamp >= to_timestamp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="from_timestamp must be earlier than to_timestamp",
        )

    diff = await _shared_reconstructor.diff(
        tenant_id=str(tenant.tenant_id),
        from_ts=from_timestamp,
        to_ts=to_timestamp,
    )

    return DiffResponse(
        tenant_id=str(tenant.tenant_id),
        from_timestamp=from_timestamp,
        to_timestamp=to_timestamp,
        added=diff["added"],
        modified=diff["modified"],
        deleted=diff["deleted"],
    )


@router.get(
    "/audit-trail",
    response_model=AuditTrailResponse,
    status_code=status.HTTP_200_OK,
    summary="Query audit trail for a specific entity",
)
async def get_audit_trail(
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    entity_type: Annotated[str | None, Query(description="Filter by entity type")] = None,
    entity_id: Annotated[str | None, Query(description="Filter by entity ID")] = None,
    start_timestamp: Annotated[
        datetime | None,
        Query(description="Start of time range (ISO 8601, timezone-aware)"),
    ] = None,
    end_timestamp: Annotated[
        datetime | None,
        Query(description="End of time range (ISO 8601, timezone-aware)"),
    ] = None,
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=200, description="Items per page")] = 50,
) -> AuditTrailResponse:
    """Query the audit trail for a specific entity or time range.

    Returns all state change events matching the provided filters for the
    authenticated tenant. Results are sorted by timestamp ascending.

    Args:
        tenant: The authenticated tenant context (from JWT).
        entity_type: Optional entity type filter.
        entity_id: Optional entity ID filter (requires entity_type).
        start_timestamp: Optional lower bound for the time range.
        end_timestamp: Optional upper bound for the time range.
        page: Page number (1-indexed).
        page_size: Number of items per page (max 200).

    Returns:
        AuditTrailResponse with matching events and total count.
    """
    start_ms = int(start_timestamp.timestamp() * 1000) if start_timestamp else 0
    end_ms = (
        int(end_timestamp.timestamp() * 1000)
        if end_timestamp
        else int(datetime.now(timezone.utc).timestamp() * 1000)
    )

    entity_types_filter = [entity_type] if entity_type else None
    all_events = _shared_store.query_range(
        tenant_id=str(tenant.tenant_id),
        start_ts=start_ms,
        end_ts=end_ms,
        entity_types=entity_types_filter,
    )

    # Apply entity_id filter if specified
    if entity_id is not None:
        all_events = [e for e in all_events if e.entity_id == entity_id]

    total = len(all_events)

    # Apply pagination
    offset = (page - 1) * page_size
    page_events = all_events[offset : offset + page_size]

    entries = [
        AuditTrailEntry(
            event_id=e.event_id,
            timestamp_ms=e.timestamp_ms,
            entity_type=e.entity_type,
            entity_id=e.entity_id,
            entity_version=e.entity_version,
            change_type=e.change_type,
            actor_id=e.actor_id,
            actor_type=e.actor_type,
            source_service=e.source_service,
            correlation_id=e.correlation_id,
        )
        for e in page_events
    ]

    return AuditTrailResponse(
        tenant_id=str(tenant.tenant_id),
        entity_type=entity_type,
        entity_id=entity_id,
        entries=entries,
        total=total,
    )
