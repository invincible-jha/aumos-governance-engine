"""Tests for the P1.4 Autonomous Compliance Evidence Harvester.

Covers: EvidenceMappingRule, RuleStore, EvidenceStore, EvidenceHarvesterAgent,
EvidencePackager, and built-in rules for SOC2, EU AI Act, HIPAA.

Run with: pytest tests/test_evidence_harvester.py -v
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from aumos_governance_engine.evidence_harvester.agent import (
    EvidenceHarvesterAgent,
    RuleStore,
    _compute_evidence_hash,
    _render_description,
)
from aumos_governance_engine.evidence_harvester.evidence_store import (
    EvidenceStore,
    HarvestedEvidence,
)
from aumos_governance_engine.evidence_harvester.mapping_rules import (
    BUILTIN_RULES,
    EvidenceMappingRule,
)
from aumos_governance_engine.evidence_harvester.packager import EvidencePackager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_evidence(
    tenant_id: str = "tenant-a",
    regulation: str = "SOC2",
    control_id: str = "CC6.1",
    evidence_type: str = "log",
    evidence_hash: str = "abc123",
    collected_at: datetime | None = None,
    retention_days: int = 365,
) -> HarvestedEvidence:
    """Build a minimal HarvestedEvidence for tests."""
    now = collected_at or datetime.now(timezone.utc)
    return HarvestedEvidence(
        evidence_id="ev-001",
        tenant_id=tenant_id,
        regulation=regulation,
        control_id=control_id,
        evidence_type=evidence_type,
        evidence_description="Test evidence",
        source_event_id="evt-001",
        source_event_topic="aumos.test",
        evidence_payload={"key": "value"},
        collected_at=now,
        evidence_hash=evidence_hash,
        retention_until=now + timedelta(days=retention_days),
    )


def auth_event(event_type: str = "login_success") -> dict:
    """Build a sample auth event dict."""
    return {
        "event_id": "evt-auth-001",
        "event_type": event_type,
        "user_id": "user-42",
        "source_ip": "192.168.1.1",
        "timestamp": "2024-01-01T00:00:00Z",
        "tenant_id": "tenant-a",
    }


async def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Test 1: EvidenceMappingRule — immutable (frozen dataclass)
# ---------------------------------------------------------------------------

def test_evidence_mapping_rule_is_frozen():
    rule = EvidenceMappingRule(
        rule_id="test-rule",
        source_event_topic="aumos.test",
        source_event_type="some_event",
        regulation="SOC2",
        control_id="CC6.1",
        control_description="Test control",
        evidence_type="log",
        evidence_description_template="Test {field}",
        retention_days=365,
    )
    with pytest.raises(Exception):
        object.__setattr__(rule, "rule_id", "hacked")


# ---------------------------------------------------------------------------
# Test 2: RuleStore — matching rule found by topic + event_type
# ---------------------------------------------------------------------------

def test_rule_store_finds_matching_rule():
    rule = EvidenceMappingRule(
        rule_id="test-match",
        source_event_topic="aumos.security.auth-events",
        source_event_type="login_success",
        regulation="SOC2",
        control_id="CC6.1",
        control_description="Access control",
        evidence_type="log",
        evidence_description_template="User {user_id} logged in",
        retention_days=365,
    )
    store = RuleStore(rules=[rule])
    matches = store.find_matching_rules("aumos.security.auth-events", "login_success")
    assert len(matches) == 1
    assert matches[0].rule_id == "test-match"


# ---------------------------------------------------------------------------
# Test 3: RuleStore — no match returns empty list
# ---------------------------------------------------------------------------

def test_rule_store_no_match_returns_empty():
    store = RuleStore(rules=[])
    matches = store.find_matching_rules("unknown.topic", "unknown_event")
    assert matches == []


# ---------------------------------------------------------------------------
# Test 4: RuleStore — inactive rules not returned
# ---------------------------------------------------------------------------

def test_rule_store_inactive_rule_not_returned():
    rule = EvidenceMappingRule(
        rule_id="inactive-rule",
        source_event_topic="aumos.test",
        source_event_type="test_event",
        regulation="SOC2",
        control_id="CC6.1",
        control_description="Test",
        evidence_type="log",
        evidence_description_template="Test",
        retention_days=365,
        is_active=False,
    )
    store = RuleStore(rules=[rule])
    matches = store.find_matching_rules("aumos.test", "test_event")
    assert matches == []


# ---------------------------------------------------------------------------
# Test 5: Evidence hash computed correctly (SHA-256 of JSON payload)
# ---------------------------------------------------------------------------

def test_evidence_hash_computed_correctly():
    payload = {"user_id": "user-42", "event_type": "login_success"}
    computed = _compute_evidence_hash(payload)

    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert computed == expected


# ---------------------------------------------------------------------------
# Test 6: Evidence hash is deterministic regardless of key order
# ---------------------------------------------------------------------------

def test_evidence_hash_deterministic():
    payload_a = {"b": 2, "a": 1}
    payload_b = {"a": 1, "b": 2}
    assert _compute_evidence_hash(payload_a) == _compute_evidence_hash(payload_b)


# ---------------------------------------------------------------------------
# Test 7: Description template renders with event fields
# ---------------------------------------------------------------------------

def test_description_template_renders():
    template = "User {user_id} logged in from {source_ip}"
    event = {"user_id": "user-42", "source_ip": "10.0.0.1"}
    result = _render_description(template, event)
    assert result == "User user-42 logged in from 10.0.0.1"


# ---------------------------------------------------------------------------
# Test 8: Description template handles missing keys gracefully
# ---------------------------------------------------------------------------

def test_description_template_missing_keys_show_placeholder():
    template = "User {user_id} logged in from {source_ip}"
    event = {"user_id": "user-42"}  # source_ip missing
    result = _render_description(template, event)
    assert "{source_ip}" not in result  # not the raw placeholder
    assert "<source_ip>" in result


# ---------------------------------------------------------------------------
# Test 9: Harvester — processes matching event and creates evidence
# ---------------------------------------------------------------------------

def test_harvester_processes_matching_event():
    rule_store = RuleStore(rules=BUILTIN_RULES)
    evidence_store = EvidenceStore()
    agent = EvidenceHarvesterAgent(rule_store, evidence_store)

    event = auth_event("login_success")
    created = asyncio.get_event_loop().run_until_complete(
        agent.process_event(
            topic="aumos.security.auth-events",
            event=event,
            tenant_id="tenant-a",
        )
    )

    assert len(created) >= 1
    assert any(e.regulation == "SOC2" and e.control_id == "CC6.1" for e in created)


# ---------------------------------------------------------------------------
# Test 10: Harvester — event with no matching rule returns empty list
# ---------------------------------------------------------------------------

def test_harvester_no_match_returns_empty():
    rule_store = RuleStore(rules=[])
    evidence_store = EvidenceStore()
    agent = EvidenceHarvesterAgent(rule_store, evidence_store)

    created = asyncio.get_event_loop().run_until_complete(
        agent.process_event(
            topic="unknown.topic",
            event={"event_type": "unknown_event"},
            tenant_id="tenant-a",
        )
    )
    assert created == []


# ---------------------------------------------------------------------------
# Test 11: Harvester — evidence deduplication prevents duplicate records
# ---------------------------------------------------------------------------

def test_harvester_deduplication():
    rule_store = RuleStore(rules=BUILTIN_RULES)
    evidence_store = EvidenceStore()
    agent = EvidenceHarvesterAgent(rule_store, evidence_store)

    event = auth_event("login_success")

    # Process same event twice
    first = asyncio.get_event_loop().run_until_complete(
        agent.process_event("aumos.security.auth-events", event, "tenant-a")
    )
    second = asyncio.get_event_loop().run_until_complete(
        agent.process_event("aumos.security.auth-events", event, "tenant-a")
    )

    # Second call should be all duplicates
    assert len(second) == 0
    # First call created evidence
    assert len(first) >= 1


# ---------------------------------------------------------------------------
# Test 12: Harvester — retention date calculated from rule retention_days
# ---------------------------------------------------------------------------

def test_harvester_retention_date_calculated_correctly():
    rule = EvidenceMappingRule(
        rule_id="retention-test",
        source_event_topic="aumos.test",
        source_event_type="test_event",
        regulation="SOC2",
        control_id="CC6.1",
        control_description="Test",
        evidence_type="log",
        evidence_description_template="Test {event_type}",
        retention_days=730,
    )
    rule_store = RuleStore(rules=[rule])
    evidence_store = EvidenceStore()
    agent = EvidenceHarvesterAgent(rule_store, evidence_store)

    before = datetime.now(timezone.utc)
    created = asyncio.get_event_loop().run_until_complete(
        agent.process_event(
            topic="aumos.test",
            event={"event_type": "test_event", "event_id": "ev-1"},
            tenant_id="tenant-a",
        )
    )
    after = datetime.now(timezone.utc)

    assert len(created) == 1
    delta = created[0].retention_until - created[0].collected_at
    # Should be approximately 730 days
    assert 729 <= delta.days <= 730


# ---------------------------------------------------------------------------
# Test 13: EvidenceStore — tenant isolation
# ---------------------------------------------------------------------------

def test_evidence_store_tenant_isolation():
    store = EvidenceStore()

    asyncio.get_event_loop().run_until_complete(
        store.save(make_evidence(tenant_id="tenant-a", evidence_hash="hash-a"))
    )
    asyncio.get_event_loop().run_until_complete(
        store.save(make_evidence(tenant_id="tenant-b", evidence_hash="hash-b"))
    )

    records_a = asyncio.get_event_loop().run_until_complete(
        store.query(tenant_id="tenant-a")
    )
    records_b = asyncio.get_event_loop().run_until_complete(
        store.query(tenant_id="tenant-b")
    )

    assert all(r.tenant_id == "tenant-a" for r in records_a)
    assert all(r.tenant_id == "tenant-b" for r in records_b)
    assert len(records_a) == 1
    assert len(records_b) == 1


# ---------------------------------------------------------------------------
# Test 14: EvidenceStore — coverage calculation 3/5 = 60%
# ---------------------------------------------------------------------------

def test_evidence_store_coverage_calculation():
    from aumos_governance_engine.evidence_harvester.evidence_store import (
        _REGULATION_REQUIRED_CONTROLS,
    )

    store = EvidenceStore()
    required = _REGULATION_REQUIRED_CONTROLS.get("SOC2", [])
    # Cover first 3 controls
    for i, control in enumerate(required[:3]):
        asyncio.get_event_loop().run_until_complete(
            store.save(make_evidence(
                tenant_id="tenant-a",
                regulation="SOC2",
                control_id=control,
                evidence_hash=f"hash-{i}",
            ))
        )

    coverage = asyncio.get_event_loop().run_until_complete(
        store.get_coverage("tenant-a", "SOC2")
    )

    total = len(required)
    covered = min(3, total)
    expected_fraction = covered / total if total > 0 else 0.0
    assert abs(coverage["overall"] - expected_fraction) < 0.01
    assert coverage["total_covered"] == covered


# ---------------------------------------------------------------------------
# Test 15: EvidenceStore — query filters by regulation
# ---------------------------------------------------------------------------

def test_evidence_store_query_filters_by_regulation():
    store = EvidenceStore()

    asyncio.get_event_loop().run_until_complete(
        store.save(make_evidence(regulation="SOC2", evidence_hash="h1"))
    )
    asyncio.get_event_loop().run_until_complete(
        store.save(make_evidence(regulation="HIPAA", evidence_hash="h2"))
    )

    results = asyncio.get_event_loop().run_until_complete(
        store.query("tenant-a", regulation="SOC2")
    )
    assert all(r.regulation == "SOC2" for r in results)
    assert len(results) == 1


# ---------------------------------------------------------------------------
# Test 16: EvidenceStore — query filters by control_id
# ---------------------------------------------------------------------------

def test_evidence_store_query_filters_by_control_id():
    store = EvidenceStore()

    asyncio.get_event_loop().run_until_complete(
        store.save(make_evidence(control_id="CC6.1", evidence_hash="h1"))
    )
    asyncio.get_event_loop().run_until_complete(
        store.save(make_evidence(control_id="CC7.2", evidence_hash="h2"))
    )

    results = asyncio.get_event_loop().run_until_complete(
        store.query("tenant-a", control_id="CC7.2")
    )
    assert len(results) == 1
    assert results[0].control_id == "CC7.2"


# ---------------------------------------------------------------------------
# Test 17: EvidencePackager — generates package with correct structure
# ---------------------------------------------------------------------------

def test_packager_generates_package_structure():
    evidence_store = EvidenceStore()
    packager = EvidencePackager(evidence_store)

    # Seed some evidence
    asyncio.get_event_loop().run_until_complete(
        evidence_store.save(make_evidence(
            tenant_id="tenant-a",
            regulation="SOC2",
            control_id="CC6.1",
            evidence_hash="hash-001",
        ))
    )

    period_start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    period_end = datetime(2024, 12, 31, tzinfo=timezone.utc)

    package = asyncio.get_event_loop().run_until_complete(
        packager.generate_package(
            tenant_id="tenant-a",
            regulations=["SOC2"],
            period_start=period_start,
            period_end=period_end,
        )
    )

    assert "package_id" in package
    assert "evidence_by_regulation" in package
    assert "SOC2" in package["evidence_by_regulation"]
    assert "manifest" in package
    assert "coverage_summary" in package


# ---------------------------------------------------------------------------
# Test 18: EvidencePackager — manifest contains all evidence hashes
# ---------------------------------------------------------------------------

def test_packager_manifest_contains_all_hashes():
    evidence_store = EvidenceStore()
    packager = EvidencePackager(evidence_store)

    hashes = [f"hash-{i}" for i in range(3)]
    for i, h in enumerate(hashes):
        asyncio.get_event_loop().run_until_complete(
            evidence_store.save(make_evidence(
                evidence_hash=h,
                control_id="CC6.1" if i < 2 else "CC7.2",
            ))
        )

    period_start = datetime(2020, 1, 1, tzinfo=timezone.utc)
    period_end = datetime(2030, 1, 1, tzinfo=timezone.utc)

    package = asyncio.get_event_loop().run_until_complete(
        packager.generate_package("tenant-a", ["SOC2"], period_start, period_end)
    )

    manifest_hashes = set(package["manifest"]["evidence_hashes"])
    for h in hashes:
        assert h in manifest_hashes


# ---------------------------------------------------------------------------
# Test 19: EvidencePackager — empty evidence set handled gracefully
# ---------------------------------------------------------------------------

def test_packager_handles_empty_evidence():
    evidence_store = EvidenceStore()
    packager = EvidencePackager(evidence_store)

    period_start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    period_end = datetime(2024, 12, 31, tzinfo=timezone.utc)

    package = asyncio.get_event_loop().run_until_complete(
        packager.generate_package(
            tenant_id="tenant-empty",
            regulations=["SOC2", "HIPAA"],
            period_start=period_start,
            period_end=period_end,
        )
    )

    assert package["manifest"]["total_evidence_items"] == 0
    assert package["manifest"]["evidence_hashes"] == []
    assert "SOC2" in package["evidence_by_regulation"]
    assert "HIPAA" in package["evidence_by_regulation"]


# ---------------------------------------------------------------------------
# Test 20: Built-in rules — SOC2 CC6.1 matches login_success
# ---------------------------------------------------------------------------

def test_builtin_soc2_cc61_matches_login_success():
    rule_store = RuleStore(rules=BUILTIN_RULES)
    matches = rule_store.find_matching_rules(
        "aumos.security.auth-events", "login_success"
    )
    soc2_rules = [r for r in matches if r.regulation == "SOC2" and r.control_id == "CC6.1"]
    assert len(soc2_rules) >= 1


# ---------------------------------------------------------------------------
# Test 21: Built-in rules — EU AI Act Art.10 matches dataset_registered
# ---------------------------------------------------------------------------

def test_builtin_eu_ai_act_art10_matches_dataset_registered():
    rule_store = RuleStore(rules=BUILTIN_RULES)
    matches = rule_store.find_matching_rules(
        "aumos.data.governance-events", "dataset_registered"
    )
    eu_rules = [r for r in matches if r.regulation == "EU_AI_ACT" and r.control_id == "Art.10"]
    assert len(eu_rules) >= 1


# ---------------------------------------------------------------------------
# Test 22: Built-in rules — HIPAA matches phi_data_accessed
# ---------------------------------------------------------------------------

def test_builtin_hipaa_matches_phi_data_accessed():
    rule_store = RuleStore(rules=BUILTIN_RULES)
    matches = rule_store.find_matching_rules(
        "aumos.data.access-events", "phi_data_accessed"
    )
    hipaa_rules = [r for r in matches if r.regulation == "HIPAA"]
    assert len(hipaa_rules) >= 1


# ---------------------------------------------------------------------------
# Test 23: Harvester — multiple rules for same event creates multiple evidence items
# ---------------------------------------------------------------------------

def test_harvester_multiple_matching_rules():
    # Create two rules for the same topic+event_type
    rule1 = EvidenceMappingRule(
        rule_id="rule-1",
        source_event_topic="aumos.test",
        source_event_type="multi_event",
        regulation="SOC2",
        control_id="CC6.1",
        control_description="Access control",
        evidence_type="log",
        evidence_description_template="Event {event_type}",
        retention_days=365,
    )
    rule2 = EvidenceMappingRule(
        rule_id="rule-2",
        source_event_topic="aumos.test",
        source_event_type="multi_event",
        regulation="HIPAA",
        control_id="164.312(b)",
        control_description="Audit controls",
        evidence_type="log",
        evidence_description_template="Event {event_type}",
        retention_days=365,
    )
    rule_store = RuleStore(rules=[rule1, rule2])
    evidence_store = EvidenceStore()
    agent = EvidenceHarvesterAgent(rule_store, evidence_store)

    created = asyncio.get_event_loop().run_until_complete(
        agent.process_event(
            topic="aumos.test",
            event={"event_type": "multi_event", "event_id": "e-1"},
            tenant_id="tenant-a",
        )
    )

    assert len(created) == 2
    regulations = {e.regulation for e in created}
    assert "SOC2" in regulations
    assert "HIPAA" in regulations


# ---------------------------------------------------------------------------
# Test 24: EvidenceStore — exists() returns True for duplicate
# ---------------------------------------------------------------------------

def test_evidence_store_exists_detects_duplicate():
    store = EvidenceStore()
    asyncio.get_event_loop().run_until_complete(
        store.save(make_evidence(evidence_hash="sha256-abc", regulation="SOC2", control_id="CC6.1"))
    )

    result = asyncio.get_event_loop().run_until_complete(
        store.exists("tenant-a", "sha256-abc", "SOC2", "CC6.1")
    )
    assert result is True


# ---------------------------------------------------------------------------
# Test 25: EvidenceStore — exists() returns False for non-existent hash
# ---------------------------------------------------------------------------

def test_evidence_store_exists_returns_false_when_missing():
    store = EvidenceStore()

    result = asyncio.get_event_loop().run_until_complete(
        store.exists("tenant-a", "nonexistent-hash", "SOC2", "CC6.1")
    )
    assert result is False


# ---------------------------------------------------------------------------
# Test 26: EvidenceStore — coverage for unknown regulation returns zero
# ---------------------------------------------------------------------------

def test_evidence_store_coverage_unknown_regulation():
    store = EvidenceStore()
    coverage = asyncio.get_event_loop().run_until_complete(
        store.get_coverage("tenant-a", "UNKNOWN_REG")
    )
    assert coverage["overall"] == 0.0
    assert coverage["total_required"] == 0


# ---------------------------------------------------------------------------
# Test 27: Built-in rules — at least 20 rules defined
# ---------------------------------------------------------------------------

def test_builtin_rules_count():
    assert len(BUILTIN_RULES) >= 20


# ---------------------------------------------------------------------------
# Test 28: Harvester — event without event_id gets auto-generated ID
# ---------------------------------------------------------------------------

def test_harvester_generates_event_id_when_absent():
    rule = EvidenceMappingRule(
        rule_id="no-id-test",
        source_event_topic="aumos.test",
        source_event_type="event_no_id",
        regulation="SOC2",
        control_id="CC6.1",
        control_description="Test",
        evidence_type="log",
        evidence_description_template="Event received",
        retention_days=365,
    )
    rule_store = RuleStore(rules=[rule])
    evidence_store = EvidenceStore()
    agent = EvidenceHarvesterAgent(rule_store, evidence_store)

    event = {"event_type": "event_no_id"}  # No event_id
    created = asyncio.get_event_loop().run_until_complete(
        agent.process_event("aumos.test", event, "tenant-a")
    )

    assert len(created) == 1
    assert created[0].source_event_id  # Should be non-empty


# ---------------------------------------------------------------------------
# Test 29: Packager — evidence organized by regulation then control
# ---------------------------------------------------------------------------

def test_packager_organizes_by_regulation_then_control():
    evidence_store = EvidenceStore()
    packager = EvidencePackager(evidence_store)

    # Seed evidence for multiple controls
    for control_id, h in [("CC6.1", "h1"), ("CC7.2", "h2"), ("CC9.2", "h3")]:
        asyncio.get_event_loop().run_until_complete(
            evidence_store.save(make_evidence(
                regulation="SOC2",
                control_id=control_id,
                evidence_hash=h,
            ))
        )

    period_start = datetime(2020, 1, 1, tzinfo=timezone.utc)
    period_end = datetime(2030, 1, 1, tzinfo=timezone.utc)

    package = asyncio.get_event_loop().run_until_complete(
        packager.generate_package("tenant-a", ["SOC2"], period_start, period_end)
    )

    by_reg = package["evidence_by_regulation"]["SOC2"]
    assert "CC6.1" in by_reg
    assert "CC7.2" in by_reg
    assert "CC9.2" in by_reg


# ---------------------------------------------------------------------------
# Test 30: EvidenceStore — count returns correct total
# ---------------------------------------------------------------------------

def test_evidence_store_count():
    store = EvidenceStore()

    for i in range(5):
        asyncio.get_event_loop().run_until_complete(
            store.save(make_evidence(evidence_hash=f"hash-{i}"))
        )

    total = asyncio.get_event_loop().run_until_complete(store.count("tenant-a"))
    assert total == 5
    assert asyncio.get_event_loop().run_until_complete(store.count("other-tenant")) == 0
