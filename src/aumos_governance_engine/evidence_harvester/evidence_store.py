"""In-memory evidence store for the Autonomous Compliance Evidence Harvester.

Stores HarvestedEvidence records with full tenant isolation. Provides query
capabilities by regulation, control_id, evidence_type, and time range.
Computes coverage metrics (fraction of required controls with at least one
evidence item) for a given regulation.

The in-memory implementation is suitable for the current development phase.
Production deployments would swap this out for a PostgreSQL-backed adapter
implementing the same interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class HarvestedEvidence:
    """A single compliance evidence item collected by the harvester.

    Attributes:
        evidence_id: UUID v4 string — globally unique evidence identifier.
        tenant_id: The owning tenant identifier.
        regulation: Regulation code (e.g., "SOC2", "EU_AI_ACT", "HIPAA").
        control_id: The specific control identifier.
        evidence_type: Classification: "log", "configuration", "attestation", "artifact".
        evidence_description: Human-readable description rendered from the rule template.
        source_event_id: The event_id of the triggering domain event.
        source_event_topic: The Kafka topic the event arrived on.
        evidence_payload: The complete event payload dict (deduplication key source).
        collected_at: UTC datetime when the evidence was collected.
        evidence_hash: SHA-256 hex digest of the JSON-serialized evidence_payload.
        retention_until: UTC datetime until which this evidence must be retained.
    """

    evidence_id: str
    tenant_id: str
    regulation: str
    control_id: str
    evidence_type: str
    evidence_description: str
    source_event_id: str
    source_event_topic: str
    evidence_payload: dict[str, Any]
    collected_at: datetime
    evidence_hash: str
    retention_until: datetime


# Controls required per regulation for coverage calculations.
# Maps regulation_code -> list[control_id]
_REGULATION_REQUIRED_CONTROLS: dict[str, list[str]] = {
    "SOC2": ["CC6.1", "CC7.2", "CC9.2", "CC4.1"],
    "EU_AI_ACT": ["Art.9", "Art.10", "Art.13", "Art.17"],
    "HIPAA": ["164.312(a)(1)", "164.312(b)", "164.312(e)(2)(ii)"],
    "ISO27001": ["A.8.1", "A.9.2"],
    "FEDRAMP": ["AC-2", "AU-2"],
}


class EvidenceStore:
    """In-memory compliance evidence store with tenant isolation.

    All read and write operations are keyed by tenant_id so that one
    tenant's evidence is never visible to another tenant.
    """

    def __init__(self) -> None:
        """Initialize an empty evidence store."""
        # { tenant_id: list[HarvestedEvidence] }
        self._store: dict[str, list[HarvestedEvidence]] = {}

    async def save(self, evidence: HarvestedEvidence) -> None:
        """Persist a HarvestedEvidence record.

        Args:
            evidence: The evidence item to store. Overwrites nothing —
                each call appends a new record.
        """
        if evidence.tenant_id not in self._store:
            self._store[evidence.tenant_id] = []
        self._store[evidence.tenant_id].append(evidence)

    async def query(
        self,
        tenant_id: str,
        regulation: str | None = None,
        control_id: str | None = None,
        evidence_type: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[HarvestedEvidence]:
        """Query evidence records with optional filters.

        All filters are ANDed together. Results are sorted by collected_at
        descending (most recent first).

        Args:
            tenant_id: The owning tenant (mandatory — provides isolation).
            regulation: Optional regulation code filter.
            control_id: Optional control ID filter.
            evidence_type: Optional evidence type filter.
            start_date: Optional lower bound for collected_at (inclusive).
            end_date: Optional upper bound for collected_at (inclusive).
            page: Page number (1-indexed).
            page_size: Number of records per page.

        Returns:
            Filtered, paginated list of HarvestedEvidence sorted by
            collected_at descending.
        """
        records = list(self._store.get(tenant_id, []))

        if regulation is not None:
            records = [r for r in records if r.regulation == regulation]
        if control_id is not None:
            records = [r for r in records if r.control_id == control_id]
        if evidence_type is not None:
            records = [r for r in records if r.evidence_type == evidence_type]
        if start_date is not None:
            records = [r for r in records if r.collected_at >= start_date]
        if end_date is not None:
            records = [r for r in records if r.collected_at <= end_date]

        records.sort(key=lambda r: r.collected_at, reverse=True)

        offset = (page - 1) * page_size
        return records[offset : offset + page_size]

    async def get_coverage(
        self,
        tenant_id: str,
        regulation: str,
    ) -> dict[str, float]:
        """Compute evidence coverage metrics for a regulation.

        Determines which required controls for the given regulation have at
        least one evidence item collected. Returns a dict with overall
        coverage fraction and per-control status.

        Args:
            tenant_id: The owning tenant.
            regulation: The regulation code to compute coverage for.

        Returns:
            A dict with:
            - "overall": float — fraction of required controls covered (0.0–1.0)
            - "covered_controls": list[str] — control IDs with >= 1 evidence item
            - "missing_controls": list[str] — control IDs with no evidence
            - "total_required": int — total number of required controls
            - "total_covered": int — number of covered controls
        """
        required_controls = _REGULATION_REQUIRED_CONTROLS.get(regulation, [])

        if not required_controls:
            return {
                "overall": 0.0,
                "covered_controls": [],
                "missing_controls": [],
                "total_required": 0,
                "total_covered": 0,
            }

        # Find which controls have evidence
        records = self._store.get(tenant_id, [])
        covered: set[str] = set()
        for record in records:
            if record.regulation == regulation:
                covered.add(record.control_id)

        covered_controls = [c for c in required_controls if c in covered]
        missing_controls = [c for c in required_controls if c not in covered]

        total_required = len(required_controls)
        total_covered = len(covered_controls)
        overall = total_covered / total_required if total_required > 0 else 0.0

        return {
            "overall": overall,
            "covered_controls": covered_controls,
            "missing_controls": missing_controls,
            "total_required": total_required,
            "total_covered": total_covered,
        }

    async def count(self, tenant_id: str) -> int:
        """Return the total number of evidence records for a tenant.

        Args:
            tenant_id: The owning tenant.

        Returns:
            Count of evidence records (0 if tenant has no records).
        """
        return len(self._store.get(tenant_id, []))

    async def exists(
        self,
        tenant_id: str,
        evidence_hash: str,
        regulation: str,
        control_id: str,
    ) -> bool:
        """Check if evidence with this hash already exists for deduplication.

        Args:
            tenant_id: The owning tenant.
            evidence_hash: SHA-256 hex digest of the evidence payload.
            regulation: The regulation code to scope the deduplication check.
            control_id: The control ID to scope the deduplication check.

        Returns:
            True if a matching evidence record already exists, False otherwise.
        """
        records = self._store.get(tenant_id, [])
        return any(
            r.evidence_hash == evidence_hash
            and r.regulation == regulation
            and r.control_id == control_id
            for r in records
        )
