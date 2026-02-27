"""State change publisher for the Compliance Time Machine.

Provides a dependency-injected helper that services use to record
governance entity mutations to the append-only event store. Handles
UUID generation, timestamp calculation, state compression, and
correlation ID defaulting so callers only supply business-level data.
"""

from __future__ import annotations

import json
import uuid
import zlib
from datetime import datetime, timezone
from typing import Any

from aumos_governance_engine.time_machine.event_store import StateChangeEventStore
from aumos_governance_engine.time_machine.events import StateChangeEvent


def _compress_state(state: dict[str, Any]) -> bytes:
    """Serialize and zlib-compress a state dict.

    Args:
        state: The Python dict representing entity state.

    Returns:
        zlib-compressed UTF-8 encoded JSON bytes.
    """
    raw = json.dumps(state, default=str, separators=(",", ":")).encode("utf-8")
    return zlib.compress(raw, level=6)


class StateChangePublisher:
    """Publishes governance entity state changes to the event store.

    Used as a dependency-injected collaborator in services that mutate
    governance entities. Callers provide plain Python dicts for previous
    and new state; this class handles serialization and event construction.

    Args:
        event_store: The append-only StateChangeEventStore to write to.
    """

    def __init__(self, event_store: StateChangeEventStore) -> None:
        """Initialize with an event store.

        Args:
            event_store: The append-only store that receives published events.
        """
        self._store = event_store

    async def publish_state_change(
        self,
        tenant_id: str,
        entity_type: str,
        entity_id: str,
        entity_version: str,
        change_type: str,
        previous_state: dict[str, Any] | None,
        new_state: dict[str, Any] | None,
        actor_id: str,
        actor_type: str,
        source_service: str,
        correlation_id: str | None = None,
    ) -> str:
        """Publish a state change event and return the generated event_id.

        Compresses previous and new state dicts (if provided) and appends
        a StateChangeEvent to the store. Generates a correlation_id if one
        is not supplied.

        Args:
            tenant_id: The owning tenant identifier.
            entity_type: One of the supported entity type literals
                (MODEL, POLICY, CONFIGURATION, etc.).
            entity_id: The identifier of the specific entity that changed.
            entity_version: The version string of the entity after the change.
            change_type: One of the supported change type literals
                (CREATED, UPDATED, DELETED, etc.).
            previous_state: Dict of the entity state before the change.
                Pass None for CREATED events.
            new_state: Dict of the entity state after the change.
                Pass None for DELETED events.
            actor_id: Identifier of the actor who triggered the change.
            actor_type: Classification of the actor
                (human, pipeline, agent, system).
            source_service: Name of the AumOS service publishing this event.
            correlation_id: Optional request correlation ID. Auto-generated
                as a UUID v4 string if not provided.

        Returns:
            The event_id of the newly published StateChangeEvent.

        Raises:
            ValueError: If entity_type or change_type are not valid literals.
        """
        event_id = str(uuid.uuid4())
        effective_correlation_id = correlation_id or str(uuid.uuid4())
        timestamp_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

        previous_snapshot: bytes | None = (
            _compress_state(previous_state) if previous_state is not None else None
        )
        new_snapshot: bytes | None = (
            _compress_state(new_state) if new_state is not None else None
        )

        event = StateChangeEvent(
            event_id=event_id,
            tenant_id=tenant_id,
            timestamp_ms=timestamp_ms,
            entity_type=entity_type,  # type: ignore[arg-type]
            entity_id=entity_id,
            entity_version=entity_version,
            change_type=change_type,  # type: ignore[arg-type]
            previous_state_snapshot=previous_snapshot,
            new_state_snapshot=new_snapshot,
            actor_id=actor_id,
            actor_type=actor_type,  # type: ignore[arg-type]
            source_service=source_service,
            correlation_id=effective_correlation_id,
        )

        self._store.append(event)
        return event_id
