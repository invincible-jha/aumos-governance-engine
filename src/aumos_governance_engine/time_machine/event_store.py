"""Append-only in-memory event store for the Compliance Time Machine.

Stores StateChangeEvent instances keyed by tenant_id with events sorted
by timestamp_ms. All write operations are append-only — no updates or
deletes are permitted.

In production this would be backed by PostgreSQL with a time-series
partition strategy, but the in-memory implementation is sufficient for
the current phase and makes tests hermetic without database infrastructure.
"""

from __future__ import annotations

import bisect
from typing import Any

from aumos_governance_engine.time_machine.events import StateChangeEvent


class StateChangeEventStore:
    """Append-only event store for StateChangeEvent instances.

    Maintains per-tenant event lists sorted by timestamp_ms. Provides
    efficient range queries and snapshot lookups without requiring a
    full table scan.

    All methods are synchronous because in-memory access does not block.
    Production adapters wrapping PostgreSQL would make these async.
    """

    def __init__(self) -> None:
        """Initialize an empty event store."""
        # { tenant_id: list[StateChangeEvent] } sorted by timestamp_ms ascending
        self._events: dict[str, list[StateChangeEvent]] = {}
        # Parallel list of timestamp_ms ints for bisect operations
        self._timestamps: dict[str, list[int]] = {}

    def append(self, event: StateChangeEvent) -> None:
        """Append a StateChangeEvent to the store.

        Uses bisect to maintain sort order by timestamp_ms so that
        range queries remain O(log n) + O(k) where k is result size.

        Args:
            event: The immutable StateChangeEvent to store. Must not already
                exist (event_id uniqueness is the caller's responsibility).
        """
        tenant_id = event.tenant_id
        if tenant_id not in self._events:
            self._events[tenant_id] = []
            self._timestamps[tenant_id] = []

        # Insert at sorted position by timestamp_ms
        index = bisect.bisect_right(self._timestamps[tenant_id], event.timestamp_ms)
        self._events[tenant_id].insert(index, event)
        self._timestamps[tenant_id].insert(index, event.timestamp_ms)

    def query_range(
        self,
        tenant_id: str,
        start_ts: int,
        end_ts: int,
        entity_types: list[str] | None = None,
    ) -> list[StateChangeEvent]:
        """Return events for a tenant within [start_ts, end_ts] (inclusive).

        Args:
            tenant_id: The tenant whose events to query.
            start_ts: Lower bound timestamp in milliseconds (inclusive).
            end_ts: Upper bound timestamp in milliseconds (inclusive).
            entity_types: Optional allow-list of entity_type values. If None,
                all entity types are returned.

        Returns:
            List of StateChangeEvent sorted by timestamp_ms ascending.
        """
        if tenant_id not in self._timestamps:
            return []

        timestamps = self._timestamps[tenant_id]
        events = self._events[tenant_id]

        low = bisect.bisect_left(timestamps, start_ts)
        high = bisect.bisect_right(timestamps, end_ts)

        result: list[StateChangeEvent] = events[low:high]

        if entity_types is not None:
            entity_type_set: set[str] = set(entity_types)
            result = [e for e in result if e.entity_type in entity_type_set]

        return result

    def get_latest_snapshot_before(
        self,
        tenant_id: str,
        timestamp_ms: int,
        entity_type: str,
        entity_id: str,
    ) -> bytes | None:
        """Return the most recent new_state_snapshot before a given timestamp.

        Scans backwards from timestamp_ms to find the last event for the
        specified entity that carried a non-None new_state_snapshot.

        Args:
            tenant_id: The owning tenant.
            timestamp_ms: Upper bound (exclusive) timestamp in milliseconds.
            entity_type: The entity type to match.
            entity_id: The specific entity identifier.

        Returns:
            The most recent new_state_snapshot bytes, or None if no snapshot
            exists before the given timestamp.
        """
        if tenant_id not in self._timestamps:
            return None

        timestamps = self._timestamps[tenant_id]
        events = self._events[tenant_id]

        # Find all events strictly before timestamp_ms
        high = bisect.bisect_left(timestamps, timestamp_ms)

        # Walk backwards to find the last snapshot for this entity
        for index in range(high - 1, -1, -1):
            event = events[index]
            if (
                event.entity_type == entity_type
                and event.entity_id == entity_id
                and event.new_state_snapshot is not None
            ):
                return event.new_state_snapshot

        return None

    def count(self, tenant_id: str) -> int:
        """Return the total number of events stored for a tenant.

        Args:
            tenant_id: The owning tenant.

        Returns:
            Number of events for the tenant (0 if tenant has no events).
        """
        return len(self._events.get(tenant_id, []))

    def get_all_events(self, tenant_id: str) -> list[StateChangeEvent]:
        """Return all events for a tenant in timestamp ascending order.

        Args:
            tenant_id: The owning tenant.

        Returns:
            All events, sorted by timestamp_ms ascending.
        """
        return list(self._events.get(tenant_id, []))
