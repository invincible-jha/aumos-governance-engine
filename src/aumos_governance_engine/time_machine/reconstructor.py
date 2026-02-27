"""System state reconstructor for the Compliance Time Machine.

Given an append-only log of StateChangeEvents, reconstructs the exact
state of all governance entities at any historical timestamp. Also provides
diff capabilities to show what changed between two timestamps.

State snapshots are stored as zlib-compressed JSON bytes. The reconstructor
decompresses and parses them using the standard library only.
"""

from __future__ import annotations

import json
import zlib
from datetime import datetime, timezone
from typing import Any

from aumos_governance_engine.time_machine.event_store import StateChangeEventStore


def _ts_ms(dt: datetime) -> int:
    """Convert a datetime to Unix epoch milliseconds.

    Args:
        dt: A timezone-aware datetime. If naive, treated as UTC.

    Returns:
        Unix epoch milliseconds as an integer.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _decompress_snapshot(snapshot: bytes) -> dict[str, Any]:
    """Decompress a zlib-compressed JSON snapshot to a dict.

    Args:
        snapshot: zlib-compressed UTF-8 encoded JSON bytes.

    Returns:
        The decompressed Python dict.

    Raises:
        ValueError: If decompression or JSON parsing fails.
    """
    try:
        raw = zlib.decompress(snapshot)
        return json.loads(raw.decode("utf-8"))
    except (zlib.error, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Failed to decompress state snapshot: {exc}") from exc


class SystemStateReconstructor:
    """Reconstructs exact system state at any historical timestamp.

    Queries the event store for all events up to a target timestamp,
    groups them by (entity_type, entity_id), applies events in chronological
    order, and returns the resulting state for each live entity.

    Args:
        event_store: The StateChangeEventStore providing the event log.
    """

    def __init__(self, event_store: StateChangeEventStore) -> None:
        """Initialize with an event store.

        Args:
            event_store: The append-only event store to query.
        """
        self._store = event_store

    async def reconstruct_at(
        self,
        tenant_id: str,
        target_timestamp: datetime,
        entity_types: list[str] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Reconstruct the full system state at a historical timestamp.

        Fetches all events for the tenant up to target_timestamp, then for
        each (entity_type, entity_id) pair applies events in chronological
        order to derive the final state. Entities that were DELETED by the
        target timestamp are excluded from the result.

        Args:
            tenant_id: The tenant whose state to reconstruct.
            target_timestamp: The point in time to reconstruct state at.
            entity_types: Optional allow-list of entity_type strings to include.
                If None, all entity types are returned.

        Returns:
            A dict of {entity_type: {entity_id: state_dict}} representing
            all live entities at the target timestamp. Deleted entities are
            not included.
        """
        target_ms = _ts_ms(target_timestamp)

        # Fetch all events up to and including target_ms
        events = self._store.query_range(
            tenant_id=tenant_id,
            start_ts=0,
            end_ts=target_ms,
            entity_types=entity_types,
        )

        # Build state: { entity_type: { entity_id: state_dict | None } }
        # None means the entity was deleted
        raw_state: dict[str, dict[str, dict[str, Any] | None]] = {}

        for event in events:
            entity_type = event.entity_type
            entity_id = event.entity_id

            if entity_type not in raw_state:
                raw_state[entity_type] = {}

            if event.change_type == "DELETED":
                raw_state[entity_type][entity_id] = None
            elif event.new_state_snapshot is not None:
                state = _decompress_snapshot(event.new_state_snapshot)
                raw_state[entity_type][entity_id] = state
            else:
                # Event has no snapshot — record entity existence with minimal metadata
                if entity_id not in raw_state[entity_type]:
                    raw_state[entity_type][entity_id] = {
                        "entity_id": entity_id,
                        "entity_type": entity_type,
                        "change_type": event.change_type,
                    }

        # Filter out deleted entities (None values) and build final result
        result: dict[str, dict[str, Any]] = {}
        for entity_type, entities in raw_state.items():
            live_entities = {
                entity_id: state
                for entity_id, state in entities.items()
                if state is not None
            }
            if live_entities:
                result[entity_type] = live_entities

        return result

    async def diff(
        self,
        tenant_id: str,
        from_ts: datetime,
        to_ts: datetime,
    ) -> dict[str, list[dict[str, Any]]]:
        """Return what changed between two timestamps.

        Reconstructs state at both timestamps and computes the delta.
        Entities present in to_ts but not from_ts are "added".
        Entities present in from_ts but not to_ts are "deleted".
        Entities present in both but with different state are "modified".

        Args:
            tenant_id: The tenant whose state diff to compute.
            from_ts: The earlier timestamp (start of diff window).
            to_ts: The later timestamp (end of diff window).

        Returns:
            A dict with keys "added", "modified", "deleted", each containing
            a list of dicts describing the changed entities.
        """
        from_state = await self.reconstruct_at(tenant_id=tenant_id, target_timestamp=from_ts)
        to_state = await self.reconstruct_at(tenant_id=tenant_id, target_timestamp=to_ts)

        added: list[dict[str, Any]] = []
        modified: list[dict[str, Any]] = []
        deleted: list[dict[str, Any]] = []

        # Build flat key sets: (entity_type, entity_id) -> state
        flat_from: dict[tuple[str, str], dict[str, Any]] = {}
        for entity_type, entities in from_state.items():
            for entity_id, state in entities.items():
                flat_from[(entity_type, entity_id)] = state

        flat_to: dict[tuple[str, str], dict[str, Any]] = {}
        for entity_type, entities in to_state.items():
            for entity_id, state in entities.items():
                flat_to[(entity_type, entity_id)] = state

        # Added: present in to_state, absent in from_state
        for key, state in flat_to.items():
            if key not in flat_from:
                added.append(
                    {
                        "entity_type": key[0],
                        "entity_id": key[1],
                        "new_state": state,
                    }
                )

        # Deleted: present in from_state, absent in to_state
        for key, state in flat_from.items():
            if key not in flat_to:
                deleted.append(
                    {
                        "entity_type": key[0],
                        "entity_id": key[1],
                        "previous_state": state,
                    }
                )

        # Modified: present in both but state differs
        for key in flat_from.keys() & flat_to.keys():
            if flat_from[key] != flat_to[key]:
                modified.append(
                    {
                        "entity_type": key[0],
                        "entity_id": key[1],
                        "previous_state": flat_from[key],
                        "new_state": flat_to[key],
                    }
                )

        return {"added": added, "modified": modified, "deleted": deleted}
