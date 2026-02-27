"""State change event schema for the Compliance Time Machine.

All governance entity mutations are captured as immutable StateChangeEvent
instances and appended to the event store. The event carries both a snapshot
of the previous state and the new state (as compressed JSON bytes), enabling
reconstruction of system state at any point in time.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StateChangeEvent(BaseModel):
    """Immutable record of a governance entity state change.

    Carries complete before/after snapshots so state can be reconstructed
    at any historical timestamp without replaying derived fields.

    Attributes:
        event_id: UUID v4 string — globally unique event identifier.
        tenant_id: Owning tenant identifier.
        timestamp_ms: Unix epoch milliseconds (UTC) when the change occurred.
        entity_type: Category of the changed governance entity.
        entity_id: Identifier of the specific entity that changed.
        entity_version: Monotonically increasing version string of the entity.
        change_type: The nature of the state change.
        previous_state_snapshot: zlib-compressed JSON bytes of state before
            change. None for CREATED events.
        new_state_snapshot: zlib-compressed JSON bytes of state after change.
            None for DELETED events.
        actor_id: Identifier of the human user, pipeline, agent, or system
            that triggered the change.
        actor_type: Classification of the actor.
        source_service: Name of the AumOS service that emitted the event.
        correlation_id: Request correlation ID for tracing across services.
    """

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(..., description="UUID v4 string — globally unique event identifier")
    tenant_id: str = Field(..., description="Owning tenant identifier")
    timestamp_ms: int = Field(..., description="Unix epoch milliseconds (UTC)")
    entity_type: Literal[
        "MODEL",
        "POLICY",
        "CONFIGURATION",
        "PERMISSION",
        "DATA_SCHEMA",
        "DEPLOYMENT",
        "AGENT",
        "INTEGRATION",
    ] = Field(..., description="Category of the changed governance entity")
    entity_id: str = Field(..., description="Identifier of the specific entity that changed")
    entity_version: str = Field(
        ..., description="Monotonically increasing version string of the entity"
    )
    change_type: Literal[
        "CREATED",
        "UPDATED",
        "DELETED",
        "ACTIVATED",
        "DEACTIVATED",
        "APPROVED",
        "REJECTED",
    ] = Field(..., description="The nature of the state change")
    previous_state_snapshot: bytes | None = Field(
        default=None,
        description="zlib-compressed JSON bytes of state before change. None for CREATED events.",
    )
    new_state_snapshot: bytes | None = Field(
        default=None,
        description="zlib-compressed JSON bytes of state after change. None for DELETED events.",
    )
    actor_id: str = Field(
        ..., description="Identifier of the human, pipeline, agent, or system that triggered the change"
    )
    actor_type: Literal["human", "pipeline", "agent", "system"] = Field(
        ..., description="Classification of the actor"
    )
    source_service: str = Field(
        ..., description="Name of the AumOS service that emitted the event"
    )
    correlation_id: str = Field(
        ..., description="Request correlation ID for tracing across services"
    )
