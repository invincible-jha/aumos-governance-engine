"""Tests for the P1.3 Compliance Time Machine.

Covers: StateChangeEvent validation, StateChangeEventStore, SystemStateReconstructor,
StateChangePublisher, and tenant isolation properties.

Run with: pytest tests/test_time_machine.py -v
"""

from __future__ import annotations

import json
import zlib
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, AsyncMock
import pytest

from aumos_governance_engine.time_machine.events import StateChangeEvent
from aumos_governance_engine.time_machine.event_store import StateChangeEventStore
from aumos_governance_engine.time_machine.reconstructor import (
    SystemStateReconstructor,
    _compress_snapshot,
    _decompress_snapshot,
    _ts_ms,
)
from aumos_governance_engine.time_machine.publisher import (
    StateChangePublisher,
    _compress_state,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_event(
    tenant_id: str = "tenant-a",
    entity_type: str = "POLICY",
    entity_id: str = "policy-1",
    entity_version: str = "1",
    change_type: str = "CREATED",
    timestamp_ms: int = 1_000_000,
    new_state: dict | None = None,
    previous_state: dict | None = None,
    actor_id: str = "user-1",
) -> StateChangeEvent:
    """Build a minimal StateChangeEvent for tests."""
    new_snapshot = _compress_state(new_state) if new_state else None
    prev_snapshot = _compress_state(previous_state) if previous_state else None
    return StateChangeEvent(
        event_id=f"evt-{entity_id}-{change_type}-{timestamp_ms}",
        tenant_id=tenant_id,
        timestamp_ms=timestamp_ms,
        entity_type=entity_type,  # type: ignore[arg-type]
        entity_id=entity_id,
        entity_version=entity_version,
        change_type=change_type,  # type: ignore[arg-type]
        previous_state_snapshot=prev_snapshot,
        new_state_snapshot=new_snapshot,
        actor_id=actor_id,
        actor_type="human",
        source_service="aumos-governance-engine",
        correlation_id="corr-123",
    )


def _compress_state(state: dict) -> bytes:
    """Compress a state dict to zlib bytes."""
    raw = json.dumps(state, default=str, separators=(",", ":")).encode("utf-8")
    return zlib.compress(raw, level=6)


async def run(coro):
    """Run a coroutine — pytest-asyncio not required."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Test 1: StateChangeEvent — valid creation
# ---------------------------------------------------------------------------

def test_state_change_event_created_with_valid_fields():
    event = make_event(
        entity_type="MODEL",
        change_type="CREATED",
        new_state={"name": "gpt-4o", "version": "1.0"},
    )
    assert event.entity_type == "MODEL"
    assert event.change_type == "CREATED"
    assert event.new_state_snapshot is not None
    assert event.previous_state_snapshot is None


# ---------------------------------------------------------------------------
# Test 2: StateChangeEvent — frozen (immutable)
# ---------------------------------------------------------------------------

def test_state_change_event_is_immutable():
    event = make_event()
    with pytest.raises(Exception):
        object.__setattr__(event, "tenant_id", "hacked")


# ---------------------------------------------------------------------------
# Test 3: StateChangeEvent — invalid entity_type raises
# ---------------------------------------------------------------------------

def test_state_change_event_rejects_invalid_entity_type():
    from pydantic import ValidationError as PydanticValidationError
    with pytest.raises(PydanticValidationError):
        StateChangeEvent(
            event_id="evt-1",
            tenant_id="tenant-a",
            timestamp_ms=1000,
            entity_type="INVALID_TYPE",  # type: ignore[arg-type]
            entity_id="e-1",
            entity_version="1",
            change_type="CREATED",
            actor_id="user-1",
            actor_type="human",
            source_service="test",
            correlation_id="corr-1",
        )


# ---------------------------------------------------------------------------
# Test 4: EventStore — append and count
# ---------------------------------------------------------------------------

def test_event_store_append_and_count():
    store = StateChangeEventStore()
    event = make_event(tenant_id="t1", timestamp_ms=1000)
    store.append(event)
    assert store.count("t1") == 1
    assert store.count("t2") == 0


# ---------------------------------------------------------------------------
# Test 5: EventStore — events stored in timestamp order
# ---------------------------------------------------------------------------

def test_event_store_maintains_timestamp_order():
    store = StateChangeEventStore()
    # Insert out of order
    store.append(make_event(timestamp_ms=3000, entity_id="p3"))
    store.append(make_event(timestamp_ms=1000, entity_id="p1"))
    store.append(make_event(timestamp_ms=2000, entity_id="p2"))

    events = store.get_all_events("tenant-a")
    timestamps = [e.timestamp_ms for e in events]
    assert timestamps == [1000, 2000, 3000]


# ---------------------------------------------------------------------------
# Test 6: EventStore — query_range returns events in window
# ---------------------------------------------------------------------------

def test_event_store_query_range_returns_events_in_window():
    store = StateChangeEventStore()
    for ts in [1000, 2000, 3000, 4000]:
        store.append(make_event(timestamp_ms=ts, entity_id=f"e-{ts}"))

    result = store.query_range("tenant-a", start_ts=2000, end_ts=3000)
    assert len(result) == 2
    assert all(2000 <= e.timestamp_ms <= 3000 for e in result)


# ---------------------------------------------------------------------------
# Test 7: EventStore — entity_types filter
# ---------------------------------------------------------------------------

def test_event_store_query_range_filters_entity_types():
    store = StateChangeEventStore()
    store.append(make_event(entity_type="POLICY", entity_id="p1", timestamp_ms=1000))
    store.append(make_event(entity_type="MODEL", entity_id="m1", timestamp_ms=2000))
    store.append(make_event(entity_type="POLICY", entity_id="p2", timestamp_ms=3000))

    result = store.query_range("tenant-a", 0, 9999, entity_types=["MODEL"])
    assert len(result) == 1
    assert result[0].entity_id == "m1"


# ---------------------------------------------------------------------------
# Test 8: EventStore — get_latest_snapshot_before
# ---------------------------------------------------------------------------

def test_event_store_get_latest_snapshot_before():
    store = StateChangeEventStore()
    state1 = {"name": "v1"}
    state2 = {"name": "v2"}
    store.append(make_event(timestamp_ms=1000, entity_id="p1", new_state=state1))
    store.append(make_event(timestamp_ms=2000, entity_id="p1", new_state=state2, change_type="UPDATED"))

    snapshot = store.get_latest_snapshot_before("tenant-a", 1500, "POLICY", "p1")
    assert snapshot is not None
    decoded = json.loads(zlib.decompress(snapshot).decode("utf-8"))
    assert decoded["name"] == "v1"


# ---------------------------------------------------------------------------
# Test 9: EventStore — tenant isolation
# ---------------------------------------------------------------------------

def test_event_store_tenant_isolation():
    store = StateChangeEventStore()
    store.append(make_event(tenant_id="tenant-a", entity_id="p1"))
    store.append(make_event(tenant_id="tenant-b", entity_id="p2"))

    assert store.count("tenant-a") == 1
    assert store.count("tenant-b") == 1
    events_a = store.get_all_events("tenant-a")
    assert all(e.entity_id == "p1" for e in events_a)


# ---------------------------------------------------------------------------
# Test 10: Reconstructor — empty store returns empty dict
# ---------------------------------------------------------------------------

def test_reconstructor_empty_store_returns_empty():
    store = StateChangeEventStore()
    reconstructor = SystemStateReconstructor(store)
    target = datetime(2024, 1, 1, tzinfo=timezone.utc)

    result = asyncio.get_event_loop().run_until_complete(
        reconstructor.reconstruct_at("tenant-a", target)
    )
    assert result == {}


# ---------------------------------------------------------------------------
# Test 11: Reconstructor — single CREATE returns that entity
# ---------------------------------------------------------------------------

def test_reconstructor_single_create_returns_entity():
    store = StateChangeEventStore()
    state = {"name": "gpt-4o", "status": "active"}
    store.append(make_event(
        entity_type="MODEL",
        entity_id="model-1",
        change_type="CREATED",
        timestamp_ms=1_000_000,
        new_state=state,
    ))

    reconstructor = SystemStateReconstructor(store)
    target = datetime(2030, 1, 1, tzinfo=timezone.utc)

    result = asyncio.get_event_loop().run_until_complete(
        reconstructor.reconstruct_at("tenant-a", target)
    )
    assert "MODEL" in result
    assert "model-1" in result["MODEL"]
    assert result["MODEL"]["model-1"]["name"] == "gpt-4o"


# ---------------------------------------------------------------------------
# Test 12: Reconstructor — CREATE + UPDATE returns updated state
# ---------------------------------------------------------------------------

def test_reconstructor_create_then_update_returns_updated_state():
    store = StateChangeEventStore()
    store.append(make_event(
        entity_id="policy-1",
        change_type="CREATED",
        timestamp_ms=1_000,
        new_state={"status": "draft", "version": "1"},
    ))
    store.append(make_event(
        entity_id="policy-1",
        change_type="UPDATED",
        timestamp_ms=2_000,
        new_state={"status": "active", "version": "2"},
        previous_state={"status": "draft", "version": "1"},
    ))

    reconstructor = SystemStateReconstructor(store)
    target = datetime(2030, 1, 1, tzinfo=timezone.utc)

    result = asyncio.get_event_loop().run_until_complete(
        reconstructor.reconstruct_at("tenant-a", target)
    )
    assert result["POLICY"]["policy-1"]["status"] == "active"
    assert result["POLICY"]["policy-1"]["version"] == "2"


# ---------------------------------------------------------------------------
# Test 13: Reconstructor — CREATE + DELETE returns empty (entity removed)
# ---------------------------------------------------------------------------

def test_reconstructor_create_then_delete_returns_no_entity():
    store = StateChangeEventStore()
    store.append(make_event(
        entity_id="model-1",
        entity_type="MODEL",
        change_type="CREATED",
        timestamp_ms=1_000,
        new_state={"name": "old-model"},
    ))
    store.append(make_event(
        entity_id="model-1",
        entity_type="MODEL",
        change_type="DELETED",
        timestamp_ms=2_000,
    ))

    reconstructor = SystemStateReconstructor(store)
    target = datetime(2030, 1, 1, tzinfo=timezone.utc)

    result = asyncio.get_event_loop().run_until_complete(
        reconstructor.reconstruct_at("tenant-a", target)
    )
    # MODEL type should have no live entities
    assert "MODEL" not in result or "model-1" not in result.get("MODEL", {})


# ---------------------------------------------------------------------------
# Test 14: Reconstructor — intermediate state at timestamp between events
# ---------------------------------------------------------------------------

def test_reconstructor_intermediate_state_between_events():
    store = StateChangeEventStore()
    store.append(make_event(
        entity_id="policy-1",
        change_type="CREATED",
        timestamp_ms=1_000,
        new_state={"status": "draft"},
    ))
    store.append(make_event(
        entity_id="policy-1",
        change_type="UPDATED",
        timestamp_ms=3_000,
        new_state={"status": "active"},
    ))

    reconstructor = SystemStateReconstructor(store)
    # Target at ts=2000 — after CREATE but before UPDATE
    target_ms = 2_000
    target = datetime.fromtimestamp(target_ms / 1000, tz=timezone.utc)

    result = asyncio.get_event_loop().run_until_complete(
        reconstructor.reconstruct_at("tenant-a", target)
    )
    assert result["POLICY"]["policy-1"]["status"] == "draft"


# ---------------------------------------------------------------------------
# Test 15: Reconstructor — entity_types filter
# ---------------------------------------------------------------------------

def test_reconstructor_entity_types_filter():
    store = StateChangeEventStore()
    store.append(make_event(
        entity_type="POLICY",
        entity_id="p1",
        timestamp_ms=1_000,
        new_state={"type": "policy"},
    ))
    store.append(make_event(
        entity_type="MODEL",
        entity_id="m1",
        timestamp_ms=1_000,
        new_state={"type": "model"},
    ))

    reconstructor = SystemStateReconstructor(store)
    target = datetime(2030, 1, 1, tzinfo=timezone.utc)

    result = asyncio.get_event_loop().run_until_complete(
        reconstructor.reconstruct_at("tenant-a", target, entity_types=["POLICY"])
    )
    assert "POLICY" in result
    assert "MODEL" not in result


# ---------------------------------------------------------------------------
# Test 16: Reconstructor — tenant A events invisible to tenant B
# ---------------------------------------------------------------------------

def test_reconstructor_tenant_isolation():
    store = StateChangeEventStore()
    store.append(make_event(
        tenant_id="tenant-a",
        entity_id="policy-a",
        new_state={"owner": "tenant-a"},
        timestamp_ms=1_000,
    ))
    store.append(make_event(
        tenant_id="tenant-b",
        entity_id="policy-b",
        new_state={"owner": "tenant-b"},
        timestamp_ms=1_000,
    ))

    reconstructor = SystemStateReconstructor(store)
    target = datetime(2030, 1, 1, tzinfo=timezone.utc)

    result_a = asyncio.get_event_loop().run_until_complete(
        reconstructor.reconstruct_at("tenant-a", target)
    )
    result_b = asyncio.get_event_loop().run_until_complete(
        reconstructor.reconstruct_at("tenant-b", target)
    )

    assert "policy-a" in result_a.get("POLICY", {})
    assert "policy-b" not in result_a.get("POLICY", {})
    assert "policy-b" in result_b.get("POLICY", {})
    assert "policy-a" not in result_b.get("POLICY", {})


# ---------------------------------------------------------------------------
# Test 17: Reconstructor — diff shows added/modified/deleted
# ---------------------------------------------------------------------------

def test_reconstructor_diff_shows_added_modified_deleted():
    store = StateChangeEventStore()

    ts_before = 1_000
    ts_after = 5_000

    # Entity present before and after (modified)
    store.append(make_event(
        entity_id="p1",
        change_type="CREATED",
        timestamp_ms=500,
        new_state={"status": "draft"},
    ))
    store.append(make_event(
        entity_id="p1",
        change_type="UPDATED",
        timestamp_ms=3_000,
        new_state={"status": "active"},
    ))

    # Entity added after from_ts
    store.append(make_event(
        entity_id="p2",
        change_type="CREATED",
        timestamp_ms=4_000,
        new_state={"status": "draft"},
    ))

    # Entity deleted after from_ts
    store.append(make_event(
        entity_id="p3",
        change_type="CREATED",
        timestamp_ms=500,
        new_state={"status": "active"},
    ))
    store.append(make_event(
        entity_id="p3",
        change_type="DELETED",
        timestamp_ms=2_000,
    ))

    reconstructor = SystemStateReconstructor(store)
    from_dt = datetime.fromtimestamp(ts_before / 1000, tz=timezone.utc)
    to_dt = datetime.fromtimestamp(ts_after / 1000, tz=timezone.utc)

    diff = asyncio.get_event_loop().run_until_complete(
        reconstructor.diff("tenant-a", from_dt, to_dt)
    )

    added_ids = [item["entity_id"] for item in diff["added"]]
    modified_ids = [item["entity_id"] for item in diff["modified"]]
    deleted_ids = [item["entity_id"] for item in diff["deleted"]]

    assert "p2" in added_ids
    assert "p1" in modified_ids
    assert "p3" in deleted_ids


# ---------------------------------------------------------------------------
# Test 18: Snapshot round-trip — compress/decompress
# ---------------------------------------------------------------------------

def test_snapshot_round_trip():
    from aumos_governance_engine.time_machine.reconstructor import (
        _decompress_snapshot,
    )
    state = {"entity_id": "abc", "name": "test-model", "nested": {"key": "value"}}
    compressed = _compress_state(state)
    decompressed = _decompress_snapshot(compressed)
    assert decompressed == state


# ---------------------------------------------------------------------------
# Test 19: Publisher — creates valid StateChangeEvent and stores it
# ---------------------------------------------------------------------------

def test_publisher_creates_valid_event():
    store = StateChangeEventStore()
    publisher = StateChangePublisher(store)

    event_id = asyncio.get_event_loop().run_until_complete(
        publisher.publish_state_change(
            tenant_id="tenant-a",
            entity_type="POLICY",
            entity_id="pol-1",
            entity_version="1",
            change_type="CREATED",
            previous_state=None,
            new_state={"name": "test-policy", "status": "draft"},
            actor_id="user-1",
            actor_type="human",
            source_service="aumos-governance-engine",
        )
    )

    assert store.count("tenant-a") == 1
    events = store.get_all_events("tenant-a")
    assert events[0].event_id == event_id
    assert events[0].entity_type == "POLICY"
    assert events[0].change_type == "CREATED"
    assert events[0].new_state_snapshot is not None
    assert events[0].previous_state_snapshot is None


# ---------------------------------------------------------------------------
# Test 20: Publisher — generates correlation_id if not provided
# ---------------------------------------------------------------------------

def test_publisher_generates_correlation_id_when_absent():
    store = StateChangeEventStore()
    publisher = StateChangePublisher(store)

    asyncio.get_event_loop().run_until_complete(
        publisher.publish_state_change(
            tenant_id="tenant-a",
            entity_type="MODEL",
            entity_id="model-1",
            entity_version="1",
            change_type="CREATED",
            previous_state=None,
            new_state={"name": "model"},
            actor_id="pipeline-1",
            actor_type="pipeline",
            source_service="aumos-mlops-lifecycle",
            correlation_id=None,
        )
    )

    events = store.get_all_events("tenant-a")
    # Should have a non-empty UUID correlation_id
    assert len(events[0].correlation_id) == 36  # UUID format len


# ---------------------------------------------------------------------------
# Test 21: Publisher — compresses both previous and new state
# ---------------------------------------------------------------------------

def test_publisher_compresses_both_snapshots():
    store = StateChangeEventStore()
    publisher = StateChangePublisher(store)

    asyncio.get_event_loop().run_until_complete(
        publisher.publish_state_change(
            tenant_id="tenant-a",
            entity_type="POLICY",
            entity_id="pol-2",
            entity_version="2",
            change_type="UPDATED",
            previous_state={"status": "draft"},
            new_state={"status": "active"},
            actor_id="user-1",
            actor_type="human",
            source_service="svc",
        )
    )

    events = store.get_all_events("tenant-a")
    evt = events[0]
    assert evt.previous_state_snapshot is not None
    assert evt.new_state_snapshot is not None
    # Both should decompress to valid JSON
    prev = json.loads(zlib.decompress(evt.previous_state_snapshot).decode("utf-8"))
    new = json.loads(zlib.decompress(evt.new_state_snapshot).decode("utf-8"))
    assert prev["status"] == "draft"
    assert new["status"] == "active"


# ---------------------------------------------------------------------------
# Test 22: EventStore — query_range with no events in window returns empty
# ---------------------------------------------------------------------------

def test_event_store_query_range_empty_window():
    store = StateChangeEventStore()
    store.append(make_event(timestamp_ms=10_000))

    result = store.query_range("tenant-a", start_ts=1_000, end_ts=5_000)
    assert result == []


# ---------------------------------------------------------------------------
# Test 23: Reconstructor — multiple entity types, all present
# ---------------------------------------------------------------------------

def test_reconstructor_multiple_entity_types():
    store = StateChangeEventStore()
    for entity_type, entity_id in [
        ("MODEL", "m1"),
        ("POLICY", "p1"),
        ("AGENT", "a1"),
        ("DEPLOYMENT", "d1"),
    ]:
        store.append(make_event(
            entity_type=entity_type,  # type: ignore[arg-type]
            entity_id=entity_id,
            timestamp_ms=1_000,
            new_state={"type": entity_type},
        ))

    reconstructor = SystemStateReconstructor(store)
    target = datetime(2030, 1, 1, tzinfo=timezone.utc)

    result = asyncio.get_event_loop().run_until_complete(
        reconstructor.reconstruct_at("tenant-a", target)
    )
    assert "MODEL" in result
    assert "POLICY" in result
    assert "AGENT" in result
    assert "DEPLOYMENT" in result


# ---------------------------------------------------------------------------
# Test 24: EventStore — get_latest_snapshot_before returns None if no events
# ---------------------------------------------------------------------------

def test_event_store_get_latest_snapshot_before_no_events():
    store = StateChangeEventStore()
    snapshot = store.get_latest_snapshot_before("tenant-a", 99999, "POLICY", "p1")
    assert snapshot is None


# ---------------------------------------------------------------------------
# Test 25: Reconstructor — diff between identical timestamps returns empty
# ---------------------------------------------------------------------------

def test_reconstructor_diff_same_timestamps_empty():
    store = StateChangeEventStore()
    store.append(make_event(
        entity_id="p1",
        change_type="CREATED",
        timestamp_ms=1_000,
        new_state={"status": "active"},
    ))

    reconstructor = SystemStateReconstructor(store)
    ts = datetime(2024, 6, 1, tzinfo=timezone.utc)

    diff = asyncio.get_event_loop().run_until_complete(
        reconstructor.diff("tenant-a", ts, ts)
    )

    assert diff["added"] == []
    assert diff["modified"] == []
    assert diff["deleted"] == []
