"""Autonomous Compliance Evidence Harvester agent.

Background agent that processes domain events from Kafka topics and maps
them to compliance evidence records using EvidenceMappingRules. For each
matching rule, it:

1. Renders the evidence description template with event fields.
2. Computes a SHA-256 hash of the event payload for deduplication and integrity.
3. Calculates the retention_until date from the rule's retention_days.
4. Saves the HarvestedEvidence to the EvidenceStore (skipping duplicates).

The agent is designed for streaming use: call process_event() for each
incoming event and collect the resulting evidence items.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from aumos_governance_engine.evidence_harvester.evidence_store import (
    EvidenceStore,
    HarvestedEvidence,
)
from aumos_governance_engine.evidence_harvester.mapping_rules import (
    BUILTIN_RULES,
    EvidenceMappingRule,
)


class RuleStore:
    """In-memory store of EvidenceMappingRules indexed for fast lookup.

    Indexes rules by (source_event_topic, source_event_type) so that
    event processing is O(1) for the lookup step.

    Args:
        rules: Initial list of EvidenceMappingRules to load. Defaults to
            BUILTIN_RULES if not provided.
    """

    def __init__(self, rules: list[EvidenceMappingRule] | None = None) -> None:
        """Initialize with an optional list of rules.

        Args:
            rules: Rules to index. If None, the BUILTIN_RULES are used.
        """
        self._rules: dict[tuple[str, str], list[EvidenceMappingRule]] = {}
        initial_rules = rules if rules is not None else BUILTIN_RULES
        for rule in initial_rules:
            self.add_rule(rule)

    def add_rule(self, rule: EvidenceMappingRule) -> None:
        """Add a rule to the store.

        Args:
            rule: The EvidenceMappingRule to index.
        """
        key = (rule.source_event_topic, rule.source_event_type)
        if key not in self._rules:
            self._rules[key] = []
        self._rules[key].append(rule)

    def find_matching_rules(
        self,
        topic: str,
        event_type: str,
    ) -> list[EvidenceMappingRule]:
        """Return all active rules matching a topic + event_type pair.

        Args:
            topic: The Kafka topic the event arrived on.
            event_type: The event_type field value from the event payload.

        Returns:
            List of active EvidenceMappingRules that match. Empty list if none.
        """
        key = (topic, event_type)
        all_rules = self._rules.get(key, [])
        return [r for r in all_rules if r.is_active]

    def all_rules(self) -> list[EvidenceMappingRule]:
        """Return all rules in insertion order.

        Returns:
            Flat list of all EvidenceMappingRules.
        """
        result: list[EvidenceMappingRule] = []
        for rules in self._rules.values():
            result.extend(rules)
        return result


def _compute_evidence_hash(payload: dict[str, Any]) -> str:
    """Compute a SHA-256 hex digest of a JSON-serialized payload.

    Uses sorted keys for deterministic serialization so that semantically
    identical payloads produce the same hash regardless of key insertion order.

    Args:
        payload: The evidence payload dict to hash.

    Returns:
        Lowercase hex-encoded SHA-256 digest string.
    """
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _render_description(template: str, event: dict[str, Any]) -> str:
    """Render an evidence description template with event fields.

    Uses str.format_map so that template placeholders like {user_id} are
    substituted from the event dict. Missing keys are rendered as the
    placeholder name in angle brackets to avoid KeyError.

    Args:
        template: Python str.format_map template string.
        event: The event payload dict whose fields populate the template.

    Returns:
        The rendered description string.
    """

    class _SafeDict(dict):  # type: ignore[type-arg]
        """Return placeholder name for missing keys."""

        def __missing__(self, key: str) -> str:
            return f"<{key}>"

    return template.format_map(_SafeDict(event))


class EvidenceHarvesterAgent:
    """Background agent that maps domain events to compliance evidence.

    Processes events one at a time via process_event(). For each event,
    finds all matching EvidenceMappingRules, renders descriptions, hashes
    payloads, checks for duplicates, and saves HarvestedEvidence records.

    Args:
        rule_store: The RuleStore providing indexed mapping rules.
        evidence_store: The EvidenceStore for persisting evidence items.
    """

    def __init__(
        self,
        rule_store: RuleStore,
        evidence_store: EvidenceStore,
    ) -> None:
        """Initialize with rule and evidence stores.

        Args:
            rule_store: Indexed EvidenceMappingRule provider.
            evidence_store: Persistence layer for HarvestedEvidence records.
        """
        self._rule_store = rule_store
        self._evidence_store = evidence_store

    async def process_event(
        self,
        topic: str,
        event: dict[str, Any],
        tenant_id: str,
    ) -> list[HarvestedEvidence]:
        """Process a single domain event and create matching evidence records.

        Steps:
        1. Extract event_id and event_type from the event payload.
        2. Find all matching active rules for (topic, event_type).
        3. For each rule: render description, hash payload, check deduplication.
        4. Save non-duplicate evidence items and return the list.

        Args:
            topic: The Kafka topic the event arrived on.
            event: The event payload dict. Must contain an "event_type" field.
                Should contain an "event_id" field; one is generated if absent.
            tenant_id: The owning tenant identifier.

        Returns:
            List of HarvestedEvidence records created and saved for this event.
            Empty if no rules match or all matches are duplicates.
        """
        event_type: str = event.get("event_type", "")
        source_event_id: str = event.get("event_id", str(uuid.uuid4()))

        matching_rules = self._rule_store.find_matching_rules(topic, event_type)

        if not matching_rules:
            return []

        now_utc = datetime.now(timezone.utc)
        created: list[HarvestedEvidence] = []

        for rule in matching_rules:
            evidence_hash = _compute_evidence_hash(event)

            # Skip duplicates — same hash + regulation + control for this tenant
            already_exists = await self._evidence_store.exists(
                tenant_id=tenant_id,
                evidence_hash=evidence_hash,
                regulation=rule.regulation,
                control_id=rule.control_id,
            )
            if already_exists:
                continue

            description = _render_description(rule.evidence_description_template, event)
            retention_until = now_utc + timedelta(days=rule.retention_days)

            evidence = HarvestedEvidence(
                evidence_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                regulation=rule.regulation,
                control_id=rule.control_id,
                evidence_type=rule.evidence_type,
                evidence_description=description,
                source_event_id=source_event_id,
                source_event_topic=topic,
                evidence_payload=dict(event),
                collected_at=now_utc,
                evidence_hash=evidence_hash,
                retention_until=retention_until,
            )

            await self._evidence_store.save(evidence)
            created.append(evidence)

        return created
