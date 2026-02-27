"""AumOS Autonomous Compliance Evidence Harvester.

Background agent that listens to domain events and automatically maps them
to compliance evidence items for SOC 2, EU AI Act, HIPAA, and other
supported regulations. Maintains coverage metrics and generates
downloadable evidence packages for auditors.
"""

from __future__ import annotations

from aumos_governance_engine.evidence_harvester.mapping_rules import (
    EvidenceMappingRule,
    BUILTIN_RULES,
)
from aumos_governance_engine.evidence_harvester.evidence_store import (
    HarvestedEvidence,
    EvidenceStore,
)
from aumos_governance_engine.evidence_harvester.agent import EvidenceHarvesterAgent
from aumos_governance_engine.evidence_harvester.packager import EvidencePackager

__all__ = [
    "EvidenceMappingRule",
    "BUILTIN_RULES",
    "HarvestedEvidence",
    "EvidenceStore",
    "EvidenceHarvesterAgent",
    "EvidencePackager",
]
