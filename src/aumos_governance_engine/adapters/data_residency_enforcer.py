"""Data Residency Enforcer adapter — Geographic data policy enforcement.

Enforces jurisdiction-based data residency rules for tenant data operations.
Detects cross-border transfers, validates adequacy decisions (EU/UK GDPR),
enforces data routing policies, and generates violation alerts with audit logs.

Adequacy decisions tracked (as of EU AI Act / GDPR 2024):
- Full adequacy: Andorra, Argentina, Canada, Faroe Islands, Guernsey, Israel,
  Isle of Man, Japan, Jersey, New Zealand, Switzerland, Uruguay, UK, South Korea
- Partial adequacy: US (Data Privacy Framework entities only)
- No adequacy: China, Russia, India (requires SCCs/BCRs)
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# ISO 3166-1 alpha-2 country codes with EU GDPR adequacy decisions
ADEQUATE_JURISDICTIONS: frozenset[str] = frozenset(
    {
        "AD",  # Andorra
        "AR",  # Argentina
        "CA",  # Canada (PIPEDA)
        "FO",  # Faroe Islands
        "GG",  # Guernsey
        "IL",  # Israel
        "IM",  # Isle of Man
        "JP",  # Japan
        "JE",  # Jersey
        "NZ",  # New Zealand
        "CH",  # Switzerland
        "UY",  # Uruguay
        "GB",  # United Kingdom
        "KR",  # South Korea
        "US",  # US (Data Privacy Framework — partial)
    }
)

# EU/EEA member states (free data flows within zone)
EU_EEA_COUNTRIES: frozenset[str] = frozenset(
    {
        "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
        "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
        "PL", "PT", "RO", "SK", "SI", "ES", "SE",  # EU 27
        "IS", "LI", "NO",  # EEA non-EU
    }
)

# High-risk jurisdictions requiring explicit approval
HIGH_RISK_JURISDICTIONS: frozenset[str] = frozenset(
    {
        "CN", "RU", "IR", "KP", "SY",  # Sanctioned/high-risk
    }
)


@dataclass
class JurisdictionRule:
    """Defines data residency requirements for a jurisdiction or tenant.

    Attributes:
        rule_id: Unique rule UUID.
        tenant_id: Owning tenant (None for platform-wide rules).
        source_jurisdiction: Origin country code (ISO 3166-1 alpha-2).
        allowed_destinations: List of permitted destination country codes.
        blocked_destinations: List of explicitly blocked destination codes.
        requires_scc: Whether Standard Contractual Clauses are required.
        requires_bcr: Whether Binding Corporate Rules are required.
        max_data_classification: Highest data classification permitted.
        enabled: Whether this rule is currently active.
    """

    rule_id: uuid.UUID
    tenant_id: uuid.UUID | None
    source_jurisdiction: str
    allowed_destinations: list[str]
    blocked_destinations: list[str]
    requires_scc: bool
    requires_bcr: bool
    max_data_classification: str
    enabled: bool = True


@dataclass
class ResidencyViolation:
    """Represents a detected data residency policy violation.

    Attributes:
        violation_id: Unique violation UUID.
        tenant_id: Tenant where the violation was detected.
        source_jurisdiction: Origin country code.
        destination_jurisdiction: Attempted destination country code.
        data_type: Classification of the data being transferred.
        rule_id: The rule that was violated.
        detected_at: Timestamp of detection (UTC).
        blocked: Whether the transfer was blocked or only logged.
        details: Structured details about the violation.
    """

    violation_id: uuid.UUID
    tenant_id: uuid.UUID
    source_jurisdiction: str
    destination_jurisdiction: str
    data_type: str
    rule_id: uuid.UUID | None
    detected_at: datetime
    blocked: bool
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class TransferAssessment:
    """Result of assessing a potential cross-border data transfer.

    Attributes:
        permitted: Whether the transfer is permitted.
        source_jurisdiction: Origin country code.
        destination_jurisdiction: Destination country code.
        adequacy_decision: Adequacy status of destination.
        transfer_mechanism: Legal mechanism (adequacy, scc, bcr, none).
        conditions: List of conditions that must be met for the transfer.
        risk_level: Assessed risk level (low, medium, high, blocked).
        requires_dpia: Whether a DPIA is required before transfer.
    """

    permitted: bool
    source_jurisdiction: str
    destination_jurisdiction: str
    adequacy_decision: str
    transfer_mechanism: str
    conditions: list[str]
    risk_level: str
    requires_dpia: bool


class DataResidencyEnforcer:
    """Geographic data policy enforcement and cross-border transfer detection.

    Manages jurisdiction rule definitions, validates data location against
    policies, detects cross-border transfers, maps adequacy decisions, and
    generates violation alerts with full audit logging.

    Supports EU GDPR Chapter V, UK GDPR, and CCPA data residency requirements.
    Adequacy decisions reflect the European Commission's 2024 adequacy list.

    Args:
        default_block_on_violation: Whether to block transfers on violation (True)
            or only log them (False). Defaults to True (fail-closed).
        audit_all_transfers: Whether to log all transfers, not just violations.
    """

    def __init__(
        self,
        default_block_on_violation: bool = True,
        audit_all_transfers: bool = False,
    ) -> None:
        """Initialize the DataResidencyEnforcer.

        Args:
            default_block_on_violation: Block transfers that violate policy.
            audit_all_transfers: Log all cross-border transfers, not just violations.
        """
        self._default_block_on_violation = default_block_on_violation
        self._audit_all_transfers = audit_all_transfers
        self._rules: dict[str, list[JurisdictionRule]] = {}
        self._violations: list[ResidencyViolation] = []

        logger.info(
            "DataResidencyEnforcer initialized",
            default_block_on_violation=default_block_on_violation,
            audit_all_transfers=audit_all_transfers,
        )

    async def add_rule(self, rule: JurisdictionRule) -> JurisdictionRule:
        """Add a jurisdiction residency rule.

        Tenant-specific rules take precedence over platform-wide rules.
        Multiple rules can exist per source jurisdiction.

        Args:
            rule: The JurisdictionRule to add.

        Returns:
            The added JurisdictionRule with assigned rule_id.
        """
        key = str(rule.tenant_id) if rule.tenant_id else "platform"
        if key not in self._rules:
            self._rules[key] = []
        self._rules[key].append(rule)

        logger.info(
            "Jurisdiction rule added",
            rule_id=str(rule.rule_id),
            tenant_id=str(rule.tenant_id) if rule.tenant_id else "platform",
            source_jurisdiction=rule.source_jurisdiction,
            allowed_destinations=rule.allowed_destinations,
        )

        return rule

    async def assess_transfer(
        self,
        tenant_id: uuid.UUID,
        source_jurisdiction: str,
        destination_jurisdiction: str,
        data_type: str,
        data_classification: str = "internal",
    ) -> TransferAssessment:
        """Assess whether a cross-border data transfer is permitted.

        Evaluates the transfer against GDPR adequacy decisions, tenant-specific
        rules, and platform-wide policies. Returns a detailed assessment including
        the legal transfer mechanism and any required conditions.

        Args:
            tenant_id: The tenant initiating the transfer.
            source_jurisdiction: Origin country code (ISO 3166-1 alpha-2).
            destination_jurisdiction: Destination country code.
            data_type: Type of data being transferred.
            data_classification: Data sensitivity classification.

        Returns:
            TransferAssessment with permitted status and transfer mechanism.
        """
        source_upper = source_jurisdiction.upper()
        dest_upper = destination_jurisdiction.upper()

        # Same jurisdiction — always permitted
        if source_upper == dest_upper:
            return TransferAssessment(
                permitted=True,
                source_jurisdiction=source_upper,
                destination_jurisdiction=dest_upper,
                adequacy_decision="same_jurisdiction",
                transfer_mechanism="intra_jurisdiction",
                conditions=[],
                risk_level="low",
                requires_dpia=False,
            )

        # Free flow within EU/EEA
        if source_upper in EU_EEA_COUNTRIES and dest_upper in EU_EEA_COUNTRIES:
            return TransferAssessment(
                permitted=True,
                source_jurisdiction=source_upper,
                destination_jurisdiction=dest_upper,
                adequacy_decision="eu_eea_free_flow",
                transfer_mechanism="eu_eea",
                conditions=[],
                risk_level="low",
                requires_dpia=False,
            )

        # High-risk jurisdiction — blocked
        if dest_upper in HIGH_RISK_JURISDICTIONS:
            logger.warning(
                "Transfer to high-risk jurisdiction blocked",
                tenant_id=str(tenant_id),
                destination=dest_upper,
                data_type=data_type,
            )
            return TransferAssessment(
                permitted=False,
                source_jurisdiction=source_upper,
                destination_jurisdiction=dest_upper,
                adequacy_decision="no_adequacy",
                transfer_mechanism="none",
                conditions=["Transfer to this jurisdiction is blocked by platform policy"],
                risk_level="blocked",
                requires_dpia=True,
            )

        # Check tenant-specific rules
        tenant_rules = self._get_applicable_rules(tenant_id, source_upper)
        for rule in tenant_rules:
            if dest_upper in rule.blocked_destinations:
                return TransferAssessment(
                    permitted=False,
                    source_jurisdiction=source_upper,
                    destination_jurisdiction=dest_upper,
                    adequacy_decision="blocked_by_rule",
                    transfer_mechanism="none",
                    conditions=[f"Transfer blocked by jurisdiction rule {rule.rule_id}"],
                    risk_level="high",
                    requires_dpia=True,
                )
            if rule.allowed_destinations and dest_upper in rule.allowed_destinations:
                conditions = []
                if rule.requires_scc:
                    conditions.append("Standard Contractual Clauses required")
                if rule.requires_bcr:
                    conditions.append("Binding Corporate Rules required")
                return TransferAssessment(
                    permitted=True,
                    source_jurisdiction=source_upper,
                    destination_jurisdiction=dest_upper,
                    adequacy_decision="permitted_by_rule",
                    transfer_mechanism="rule_based",
                    conditions=conditions,
                    risk_level="medium" if conditions else "low",
                    requires_dpia=bool(conditions),
                )

        # Adequacy decision lookup
        adequacy_status, mechanism, conditions, risk = self._evaluate_adequacy(
            source_upper, dest_upper, data_classification
        )

        return TransferAssessment(
            permitted=adequacy_status in ("adequate", "partial_adequacy"),
            source_jurisdiction=source_upper,
            destination_jurisdiction=dest_upper,
            adequacy_decision=adequacy_status,
            transfer_mechanism=mechanism,
            conditions=conditions,
            risk_level=risk,
            requires_dpia=risk in ("medium", "high"),
        )

    async def validate_data_location(
        self,
        tenant_id: uuid.UUID,
        data_location: str,
        required_jurisdiction: str,
    ) -> bool:
        """Validate that data is stored in the required jurisdiction.

        Used to enforce data residency requirements for regulated data types
        (e.g., EU health data must remain in EU/EEA).

        Args:
            tenant_id: The owning tenant UUID.
            data_location: ISO 3166-1 alpha-2 code of actual data location.
            required_jurisdiction: Required jurisdiction (country code or region).

        Returns:
            True if the data location satisfies the jurisdiction requirement.
        """
        location_upper = data_location.upper()
        required_upper = required_jurisdiction.upper()

        # Region-based checks
        if required_upper == "EU" or required_upper == "EEA":
            is_valid = location_upper in EU_EEA_COUNTRIES
        elif required_upper == "ADEQUATE":
            is_valid = location_upper in ADEQUATE_JURISDICTIONS or location_upper in EU_EEA_COUNTRIES
        else:
            is_valid = location_upper == required_upper

        if not is_valid:
            logger.warning(
                "Data location validation failed",
                tenant_id=str(tenant_id),
                data_location=location_upper,
                required_jurisdiction=required_upper,
            )

        return is_valid

    async def record_violation(
        self,
        tenant_id: uuid.UUID,
        source_jurisdiction: str,
        destination_jurisdiction: str,
        data_type: str,
        rule_id: uuid.UUID | None,
        blocked: bool,
        details: dict[str, Any] | None = None,
    ) -> ResidencyViolation:
        """Record a detected data residency policy violation.

        Creates an audit log entry for the violation with full context.
        If blocking mode is enabled, the calling code should halt the transfer.

        Args:
            tenant_id: The tenant where the violation occurred.
            source_jurisdiction: Origin country code.
            destination_jurisdiction: Attempted destination country code.
            data_type: Type of data involved.
            rule_id: Optional rule that was violated.
            blocked: Whether the transfer was blocked.
            details: Additional structured details.

        Returns:
            The created ResidencyViolation record.
        """
        violation = ResidencyViolation(
            violation_id=uuid.uuid4(),
            tenant_id=tenant_id,
            source_jurisdiction=source_jurisdiction.upper(),
            destination_jurisdiction=destination_jurisdiction.upper(),
            data_type=data_type,
            rule_id=rule_id,
            detected_at=datetime.now(UTC),
            blocked=blocked,
            details=details or {},
        )

        self._violations.append(violation)

        logger.warning(
            "Data residency violation recorded",
            violation_id=str(violation.violation_id),
            tenant_id=str(tenant_id),
            source_jurisdiction=violation.source_jurisdiction,
            destination_jurisdiction=violation.destination_jurisdiction,
            data_type=data_type,
            blocked=blocked,
        )

        return violation

    async def get_violation_report(
        self,
        tenant_id: uuid.UUID,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[ResidencyViolation]:
        """Retrieve data residency violations for a tenant.

        Args:
            tenant_id: The tenant UUID.
            start_time: Optional start of time window filter.
            end_time: Optional end of time window filter.

        Returns:
            List of ResidencyViolation records within the time window.
        """
        violations = [v for v in self._violations if v.tenant_id == tenant_id]

        if start_time:
            violations = [v for v in violations if v.detected_at >= start_time]
        if end_time:
            violations = [v for v in violations if v.detected_at <= end_time]

        return violations

    async def get_adequacy_map(self) -> dict[str, dict[str, Any]]:
        """Return the full adequacy decision map for all tracked jurisdictions.

        Useful for compliance dashboards showing which jurisdictions are
        approved for data transfers without additional safeguards.

        Returns:
            Dict mapping country code to adequacy details including
            decision type, applicable frameworks, and last updated.
        """
        adequacy_map: dict[str, dict[str, Any]] = {}

        for country in EU_EEA_COUNTRIES:
            adequacy_map[country] = {
                "status": "eu_eea_free_flow",
                "framework": "EU GDPR (intra-EEA)",
                "requires_safeguards": False,
                "risk_level": "low",
            }

        for country in ADEQUATE_JURISDICTIONS - EU_EEA_COUNTRIES:
            adequacy_map[country] = {
                "status": "adequate",
                "framework": "European Commission Adequacy Decision",
                "requires_safeguards": country == "US",  # DPF partial adequacy
                "risk_level": "low" if country != "US" else "medium",
            }

        for country in HIGH_RISK_JURISDICTIONS:
            adequacy_map[country] = {
                "status": "no_adequacy",
                "framework": "None — transfer blocked",
                "requires_safeguards": True,
                "risk_level": "blocked",
            }

        return adequacy_map

    def _get_applicable_rules(
        self,
        tenant_id: uuid.UUID,
        source_jurisdiction: str,
    ) -> list[JurisdictionRule]:
        """Get applicable jurisdiction rules for a tenant and source jurisdiction.

        Tenant-specific rules take precedence and are returned first,
        followed by platform-wide rules.

        Args:
            tenant_id: The tenant UUID.
            source_jurisdiction: Origin country code.

        Returns:
            Ordered list of applicable JurisdictionRule instances.
        """
        tenant_key = str(tenant_id)
        platform_key = "platform"

        tenant_rules = [
            r for r in self._rules.get(tenant_key, [])
            if r.source_jurisdiction == source_jurisdiction and r.enabled
        ]
        platform_rules = [
            r for r in self._rules.get(platform_key, [])
            if r.source_jurisdiction == source_jurisdiction and r.enabled
        ]

        return tenant_rules + platform_rules

    def _evaluate_adequacy(
        self,
        source: str,
        destination: str,
        data_classification: str,
    ) -> tuple[str, str, list[str], str]:
        """Evaluate the adequacy decision for a cross-border transfer.

        Args:
            source: Source country code.
            destination: Destination country code.
            data_classification: Data sensitivity classification.

        Returns:
            Tuple of (adequacy_status, transfer_mechanism, conditions, risk_level).
        """
        is_source_eu = source in EU_EEA_COUNTRIES

        if destination in ADEQUATE_JURISDICTIONS:
            if destination == "US":
                return (
                    "partial_adequacy",
                    "data_privacy_framework",
                    ["Recipient must be certified under EU-US Data Privacy Framework"],
                    "medium",
                )
            return "adequate", "adequacy_decision", [], "low"

        if is_source_eu:
            # EU source, non-adequate destination: requires SCCs or BCRs
            conditions = [
                "Standard Contractual Clauses (SCCs) required",
                "Transfer Impact Assessment recommended",
            ]
            if data_classification in ("sensitive", "confidential", "restricted"):
                conditions.append("Data Protection Impact Assessment (DPIA) required")
                return "no_adequacy", "scc_required", conditions, "high"
            return "no_adequacy", "scc_required", conditions, "medium"

        return "unknown", "none", ["Manual review required for this jurisdiction pair"], "high"


__all__ = [
    "DataResidencyEnforcer",
    "JurisdictionRule",
    "ResidencyViolation",
    "TransferAssessment",
    "ADEQUATE_JURISDICTIONS",
    "EU_EEA_COUNTRIES",
    "HIGH_RISK_JURISDICTIONS",
]
