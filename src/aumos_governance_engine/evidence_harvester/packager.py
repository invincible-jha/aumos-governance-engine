"""Evidence package generator for the Autonomous Compliance Evidence Harvester.

Generates downloadable evidence packages organized by regulation and control.
Each package has a unique package_id, a manifest with metadata, and a
structured collection of evidence items grouped by regulation → control → items.

The packager queries the EvidenceStore for all evidence within the specified
time period and constructs a portable representation suitable for export to
auditors or external compliance platforms.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from aumos_governance_engine.evidence_harvester.evidence_store import (
    EvidenceStore,
    HarvestedEvidence,
)


def _evidence_to_dict(evidence: HarvestedEvidence) -> dict[str, Any]:
    """Serialize a HarvestedEvidence record to a JSON-compatible dict.

    Args:
        evidence: The evidence item to serialize.

    Returns:
        Dict representation suitable for inclusion in a package manifest.
    """
    return {
        "evidence_id": evidence.evidence_id,
        "evidence_type": evidence.evidence_type,
        "evidence_description": evidence.evidence_description,
        "source_event_id": evidence.source_event_id,
        "source_event_topic": evidence.source_event_topic,
        "collected_at": evidence.collected_at.isoformat(),
        "evidence_hash": evidence.evidence_hash,
        "retention_until": evidence.retention_until.isoformat(),
    }


class EvidencePackager:
    """Generates downloadable evidence packages organized by regulation and control.

    A package is a structured in-memory dict (suitable for JSON serialization
    and streaming download) containing:
    - Package metadata (ID, generation timestamp, period, regulations, tenant)
    - A manifest listing all evidence hashes for integrity verification
    - Evidence organized as regulation → control → list[evidence_item]
    - A coverage summary showing which controls are satisfied

    Args:
        evidence_store: The EvidenceStore to query for evidence.
    """

    def __init__(self, evidence_store: EvidenceStore) -> None:
        """Initialize with an evidence store.

        Args:
            evidence_store: The store to query when generating packages.
        """
        self._evidence_store = evidence_store

    async def generate_package(
        self,
        tenant_id: str,
        regulations: list[str],
        period_start: datetime,
        period_end: datetime,
    ) -> dict[str, Any]:
        """Generate a complete evidence package for one or more regulations.

        Queries evidence for the specified tenant, regulations, and time period.
        Organizes results by regulation → control → evidence_items. Computes
        a package-level SHA-256 manifest hash for integrity verification.

        Args:
            tenant_id: The owning tenant identifier.
            regulations: List of regulation codes to include
                (e.g., ["SOC2", "HIPAA"]).
            period_start: Start of the evidence collection period (inclusive).
            period_end: End of the evidence collection period (inclusive).

        Returns:
            A dict representing the complete evidence package with keys:
            - "package_id": str — UUID for this package
            - "tenant_id": str
            - "generated_at": str — ISO 8601 UTC datetime
            - "period_start": str — ISO 8601
            - "period_end": str — ISO 8601
            - "regulations": list[str]
            - "evidence_by_regulation": dict — nested structure
            - "manifest": dict — hashes and total counts
            - "coverage_summary": dict — per-regulation coverage
        """
        package_id = str(uuid.uuid4())
        generated_at = datetime.now(timezone.utc)

        evidence_by_regulation: dict[str, dict[str, list[dict[str, Any]]]] = {}
        all_hashes: list[str] = []
        total_evidence_count = 0

        for regulation in regulations:
            # Query evidence for this regulation within the period
            all_for_regulation = await self._evidence_store.query(
                tenant_id=tenant_id,
                regulation=regulation,
                start_date=period_start,
                end_date=period_end,
                page=1,
                page_size=10_000,  # Large page to get all records
            )

            # Organize by control_id
            by_control: dict[str, list[dict[str, Any]]] = {}
            for evidence in all_for_regulation:
                control_id = evidence.control_id
                if control_id not in by_control:
                    by_control[control_id] = []
                evidence_dict = _evidence_to_dict(evidence)
                by_control[control_id].append(evidence_dict)
                all_hashes.append(evidence.evidence_hash)
                total_evidence_count += 1

            evidence_by_regulation[regulation] = by_control

        # Compute manifest hash — SHA-256 of all sorted evidence hashes
        manifest_hash = hashlib.sha256(
            json.dumps(sorted(all_hashes), separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        # Compute coverage summary per regulation
        coverage_summary: dict[str, dict[str, Any]] = {}
        for regulation in regulations:
            coverage = await self._evidence_store.get_coverage(
                tenant_id=tenant_id,
                regulation=regulation,
            )
            coverage_summary[regulation] = coverage

        return {
            "package_id": package_id,
            "tenant_id": tenant_id,
            "generated_at": generated_at.isoformat(),
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "regulations": regulations,
            "evidence_by_regulation": evidence_by_regulation,
            "manifest": {
                "total_evidence_items": total_evidence_count,
                "evidence_hashes": sorted(all_hashes),
                "manifest_hash": manifest_hash,
            },
            "coverage_summary": coverage_summary,
        }

    async def get_package_status(
        self,
        package_id: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Return the status of a package by ID.

        In the current in-memory implementation, packages are not persisted
        after generation. This returns a status-only response indicating the
        package must be regenerated.

        Args:
            package_id: The UUID of the package to look up.
            tenant_id: The owning tenant (for isolation).

        Returns:
            Dict with "package_id", "status", and "message" keys.
        """
        return {
            "package_id": package_id,
            "tenant_id": tenant_id,
            "status": "not_persisted",
            "message": (
                "Packages are generated on-demand. "
                "Call POST /evidence/packages/generate to generate a new package."
            ),
        }
