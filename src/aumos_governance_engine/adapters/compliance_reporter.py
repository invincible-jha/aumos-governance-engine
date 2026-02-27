"""Compliance Reporter adapter — Multi-framework compliance status reporting.

Aggregates compliance status across GDPR, CCPA, HIPAA, and SOX frameworks,
scores control effectiveness, performs gap analysis, tracks remediation, and
generates structured reports for executive dashboards, auditors, and regulators.

Report formats:
- JSON (for API consumers and dashboard integration)
- Summary dict (for executive dashboards)
- Structured compliance report (for auditor export)
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# Supported compliance frameworks with metadata
FRAMEWORKS: dict[str, dict[str, Any]] = {
    "gdpr": {
        "name": "General Data Protection Regulation",
        "issuing_body": "European Parliament and Council",
        "scope": "Personal data processing for EU/EEA residents",
        "total_articles": 99,
        "key_articles": ["Art. 5", "Art. 6", "Art. 7", "Art. 13", "Art. 17", "Art. 25"],
    },
    "ccpa": {
        "name": "California Consumer Privacy Act",
        "issuing_body": "California State Legislature",
        "scope": "Personal information of California residents",
        "total_articles": 11,
        "key_articles": ["1798.100", "1798.105", "1798.110", "1798.115", "1798.120"],
    },
    "hipaa": {
        "name": "Health Insurance Portability and Accountability Act",
        "issuing_body": "US Department of Health and Human Services",
        "scope": "Protected health information (PHI) processing",
        "total_articles": 5,
        "key_articles": ["164.308", "164.310", "164.312", "164.314", "164.316"],
    },
    "sox": {
        "name": "Sarbanes-Oxley Act",
        "issuing_body": "US Congress",
        "scope": "Financial reporting controls for public companies",
        "total_articles": 11,
        "key_articles": ["Section 302", "Section 404", "Section 409", "Section 802"],
    },
    "iso27001": {
        "name": "ISO/IEC 27001:2022",
        "issuing_body": "ISO/IEC",
        "scope": "Information security management systems",
        "total_articles": 10,
        "key_articles": ["A.5", "A.6", "A.8", "A.9", "A.10", "A.12", "A.13", "A.18"],
    },
}


@dataclass
class ControlStatus:
    """Status of a single compliance control.

    Attributes:
        control_id: Unique control identifier (e.g., GDPR-ART5-A, HIPAA-164312).
        framework: Compliance framework code.
        article_ref: Specific article or section reference.
        description: Human-readable control description.
        status: Current control status (compliant, non_compliant, partial, not_assessed).
        effectiveness_score: Control effectiveness score 0.0-1.0.
        last_assessed: Timestamp of last assessment.
        evidence_count: Number of evidence items supporting this control.
        gaps: List of identified gaps for this control.
        remediation_owner: Optional user ID responsible for remediation.
        remediation_due: Optional deadline for gap remediation.
    """

    control_id: str
    framework: str
    article_ref: str
    description: str
    status: str
    effectiveness_score: float
    last_assessed: datetime | None
    evidence_count: int
    gaps: list[str] = field(default_factory=list)
    remediation_owner: str | None = None
    remediation_due: datetime | None = None


@dataclass
class FrameworkReport:
    """Compliance report for a single framework.

    Attributes:
        framework: Framework code (gdpr, ccpa, hipaa, sox).
        tenant_id: Owning tenant UUID.
        generated_at: Report generation timestamp.
        overall_score: Weighted compliance score 0.0-1.0.
        compliant_controls: Count of compliant controls.
        partial_controls: Count of partially compliant controls.
        non_compliant_controls: Count of non-compliant controls.
        not_assessed_controls: Count of unassessed controls.
        controls: List of ControlStatus for all controls.
        gaps: Aggregated list of all identified gaps.
        remediation_items: List of prioritised remediation items.
        next_assessment_due: Recommended date for next assessment.
    """

    framework: str
    tenant_id: uuid.UUID
    generated_at: datetime
    overall_score: float
    compliant_controls: int
    partial_controls: int
    non_compliant_controls: int
    not_assessed_controls: int
    controls: list[ControlStatus] = field(default_factory=list)
    gaps: list[dict[str, Any]] = field(default_factory=list)
    remediation_items: list[dict[str, Any]] = field(default_factory=list)
    next_assessment_due: datetime | None = None


@dataclass
class ComplianceDashboard:
    """Executive compliance dashboard data structure.

    Attributes:
        tenant_id: Owning tenant UUID.
        generated_at: Dashboard generation timestamp.
        overall_compliance_score: Weighted average across all frameworks.
        framework_scores: Dict mapping framework -> score 0.0-1.0.
        critical_gaps: List of highest-priority compliance gaps.
        upcoming_deadlines: List of near-term remediation deadlines.
        trend: Compliance trend direction (improving, stable, declining).
        frameworks_assessed: Number of frameworks with at least one assessment.
    """

    tenant_id: uuid.UUID
    generated_at: datetime
    overall_compliance_score: float
    framework_scores: dict[str, float]
    critical_gaps: list[dict[str, Any]]
    upcoming_deadlines: list[dict[str, Any]]
    trend: str
    frameworks_assessed: int


class ComplianceReporter:
    """Multi-framework compliance status aggregation and reporting.

    Aggregates compliance status across GDPR, CCPA, HIPAA, SOX, and ISO 27001,
    performs gap analysis, scores control effectiveness, tracks remediation
    items, and generates structured reports in JSON format for dashboards,
    auditors, and regulators.

    Compliance scores are computed as weighted averages where:
    - compliant = 1.0
    - partial = 0.5
    - non_compliant = 0.0
    - not_assessed = 0.0 (treated as unknown risk)

    Args:
        score_not_assessed_as_zero: Whether unassessed controls count as
            non-compliant (True, conservative) or are excluded from score (False).
        assessment_cycle_days: Number of days between required assessments.
    """

    def __init__(
        self,
        score_not_assessed_as_zero: bool = True,
        assessment_cycle_days: int = 90,
    ) -> None:
        """Initialize the ComplianceReporter.

        Args:
            score_not_assessed_as_zero: If True, not_assessed controls score 0.0.
            assessment_cycle_days: Recommended days between assessment cycles.
        """
        self._score_not_assessed_as_zero = score_not_assessed_as_zero
        self._assessment_cycle_days = assessment_cycle_days
        self._control_registry: dict[str, list[ControlStatus]] = {}
        self._remediation_registry: dict[str, list[dict[str, Any]]] = {}

        logger.info(
            "ComplianceReporter initialized",
            score_not_assessed_as_zero=score_not_assessed_as_zero,
            assessment_cycle_days=assessment_cycle_days,
        )

    async def record_control_assessment(
        self,
        tenant_id: uuid.UUID,
        control: ControlStatus,
    ) -> ControlStatus:
        """Record or update a control assessment result.

        Creates or updates the assessment for a specific control. If a control
        with the same control_id already exists for this tenant+framework, it
        is replaced with the new assessment (most recent assessment wins).

        Args:
            tenant_id: The owning tenant UUID.
            control: The ControlStatus assessment to record.

        Returns:
            The recorded ControlStatus.
        """
        key = f"{tenant_id}:{control.framework}"
        if key not in self._control_registry:
            self._control_registry[key] = []

        # Replace existing assessment for same control_id
        existing = self._control_registry[key]
        self._control_registry[key] = [
            c for c in existing if c.control_id != control.control_id
        ]
        self._control_registry[key].append(control)

        logger.info(
            "Control assessment recorded",
            tenant_id=str(tenant_id),
            control_id=control.control_id,
            framework=control.framework,
            status=control.status,
            effectiveness_score=control.effectiveness_score,
        )

        return control

    async def generate_framework_report(
        self,
        tenant_id: uuid.UUID,
        framework: str,
        include_evidence_details: bool = False,
    ) -> FrameworkReport:
        """Generate a detailed compliance report for a single framework.

        Aggregates all control assessments for the framework, computes the
        overall compliance score, identifies gaps, and prioritises remediation.

        Args:
            tenant_id: The owning tenant UUID.
            framework: Framework code (gdpr, ccpa, hipaa, sox, iso27001).
            include_evidence_details: Whether to include evidence item details.

        Returns:
            FrameworkReport with full compliance analysis.

        Raises:
            ValueError: If the framework is not supported.
        """
        if framework not in FRAMEWORKS:
            raise ValueError(
                f"Unsupported framework '{framework}'. "
                f"Supported: {sorted(FRAMEWORKS.keys())}"
            )

        key = f"{tenant_id}:{framework}"
        controls = self._control_registry.get(key, [])

        compliant = [c for c in controls if c.status == "compliant"]
        partial = [c for c in controls if c.status == "partial"]
        non_compliant = [c for c in controls if c.status == "non_compliant"]
        not_assessed = [c for c in controls if c.status == "not_assessed"]

        overall_score = self._compute_framework_score(controls)

        gaps: list[dict[str, Any]] = []
        for control in non_compliant + partial:
            for gap in control.gaps:
                gaps.append({
                    "control_id": control.control_id,
                    "framework": framework,
                    "article_ref": control.article_ref,
                    "gap": gap,
                    "severity": "high" if control.status == "non_compliant" else "medium",
                    "remediation_due": (
                        control.remediation_due.isoformat()
                        if control.remediation_due else None
                    ),
                })

        remediation_items = self._build_remediation_items(non_compliant + partial)

        next_assessment_due = datetime.now(UTC) + timedelta(
            days=self._assessment_cycle_days
        )

        report = FrameworkReport(
            framework=framework,
            tenant_id=tenant_id,
            generated_at=datetime.now(UTC),
            overall_score=overall_score,
            compliant_controls=len(compliant),
            partial_controls=len(partial),
            non_compliant_controls=len(non_compliant),
            not_assessed_controls=len(not_assessed),
            controls=controls,
            gaps=gaps,
            remediation_items=remediation_items,
            next_assessment_due=next_assessment_due,
        )

        logger.info(
            "Framework compliance report generated",
            tenant_id=str(tenant_id),
            framework=framework,
            overall_score=overall_score,
            compliant=len(compliant),
            non_compliant=len(non_compliant),
            gaps=len(gaps),
        )

        return report

    async def generate_dashboard(
        self,
        tenant_id: uuid.UUID,
        frameworks: list[str] | None = None,
    ) -> ComplianceDashboard:
        """Generate an executive compliance dashboard across all frameworks.

        Aggregates scores from all assessed frameworks, identifies critical
        gaps, surfaces upcoming remediation deadlines, and computes a trend.

        Args:
            tenant_id: The owning tenant UUID.
            frameworks: Optional list of frameworks to include. Defaults to all.

        Returns:
            ComplianceDashboard with cross-framework aggregated view.
        """
        target_frameworks = frameworks or list(FRAMEWORKS.keys())

        framework_scores: dict[str, float] = {}
        all_gaps: list[dict[str, Any]] = []
        upcoming_deadlines: list[dict[str, Any]] = []
        frameworks_assessed = 0

        for framework in target_frameworks:
            key = f"{tenant_id}:{framework}"
            controls = self._control_registry.get(key, [])

            if controls:
                frameworks_assessed += 1
                score = self._compute_framework_score(controls)
                framework_scores[framework] = score

                # Collect critical (non_compliant) gaps
                for control in controls:
                    if control.status == "non_compliant":
                        for gap in control.gaps:
                            all_gaps.append({
                                "framework": framework,
                                "control_id": control.control_id,
                                "article_ref": control.article_ref,
                                "gap": gap,
                                "severity": "critical",
                                "score_impact": 1.0 - control.effectiveness_score,
                            })
                    if control.remediation_due:
                        days_to_deadline = (
                            control.remediation_due - datetime.now(UTC)
                        ).days
                        if 0 <= days_to_deadline <= 30:
                            upcoming_deadlines.append({
                                "control_id": control.control_id,
                                "framework": framework,
                                "remediation_due": control.remediation_due.isoformat(),
                                "days_remaining": days_to_deadline,
                                "owner": control.remediation_owner,
                            })

        overall_score = (
            sum(framework_scores.values()) / len(framework_scores)
            if framework_scores else 0.0
        )

        # Sort critical gaps by score impact
        all_gaps.sort(key=lambda g: g["score_impact"], reverse=True)
        critical_gaps = all_gaps[:10]  # Top 10 most impactful gaps

        # Sort deadlines by proximity
        upcoming_deadlines.sort(key=lambda d: d["days_remaining"])

        trend = self._compute_trend(tenant_id)

        return ComplianceDashboard(
            tenant_id=tenant_id,
            generated_at=datetime.now(UTC),
            overall_compliance_score=round(overall_score, 4),
            framework_scores={k: round(v, 4) for k, v in framework_scores.items()},
            critical_gaps=critical_gaps,
            upcoming_deadlines=upcoming_deadlines,
            trend=trend,
            frameworks_assessed=frameworks_assessed,
        )

    async def export_report_json(
        self,
        tenant_id: uuid.UUID,
        frameworks: list[str] | None = None,
    ) -> dict[str, Any]:
        """Export a complete compliance report as a JSON-serializable dict.

        Generates framework reports for all requested frameworks and packages
        them into a single structured document suitable for auditor export
        or regulatory submission.

        Args:
            tenant_id: The owning tenant UUID.
            frameworks: Optional list of frameworks to include. Defaults to all.

        Returns:
            JSON-serializable dict with full compliance status across frameworks.
        """
        target_frameworks = frameworks or list(FRAMEWORKS.keys())
        dashboard = await self.generate_dashboard(tenant_id, target_frameworks)

        framework_reports: dict[str, Any] = {}
        for framework in target_frameworks:
            try:
                report = await self.generate_framework_report(tenant_id, framework)
                framework_reports[framework] = {
                    "framework": framework,
                    "framework_name": FRAMEWORKS[framework]["name"],
                    "overall_score": report.overall_score,
                    "compliant_controls": report.compliant_controls,
                    "partial_controls": report.partial_controls,
                    "non_compliant_controls": report.non_compliant_controls,
                    "not_assessed_controls": report.not_assessed_controls,
                    "gaps": report.gaps,
                    "remediation_items": report.remediation_items,
                    "next_assessment_due": (
                        report.next_assessment_due.isoformat()
                        if report.next_assessment_due else None
                    ),
                }
            except ValueError:
                pass

        return {
            "report_type": "compliance_status_report",
            "tenant_id": str(tenant_id),
            "generated_at": dashboard.generated_at.isoformat(),
            "overall_compliance_score": dashboard.overall_compliance_score,
            "framework_scores": dashboard.framework_scores,
            "frameworks_assessed": dashboard.frameworks_assessed,
            "trend": dashboard.trend,
            "critical_gaps": dashboard.critical_gaps,
            "upcoming_deadlines": dashboard.upcoming_deadlines,
            "framework_details": framework_reports,
            "metadata": {
                "report_version": "1.0",
                "assessment_cycle_days": self._assessment_cycle_days,
                "scoring_method": (
                    "not_assessed_as_zero" if self._score_not_assessed_as_zero
                    else "not_assessed_excluded"
                ),
            },
        }

    async def track_remediation(
        self,
        tenant_id: uuid.UUID,
        control_id: str,
        framework: str,
        remediation_action: str,
        owner: str,
        due_date: datetime,
        priority: str = "medium",
    ) -> dict[str, Any]:
        """Track a remediation action for a compliance gap.

        Creates a remediation record linking a gap to an owner, action plan,
        and deadline. Used for compliance gap closure tracking.

        Args:
            tenant_id: The owning tenant UUID.
            control_id: The control ID with the gap.
            framework: The compliance framework.
            remediation_action: Description of the remediation action.
            owner: User or team responsible for remediation.
            due_date: Deadline for completing the remediation.
            priority: Priority level (critical, high, medium, low).

        Returns:
            Dict containing the remediation tracking record.
        """
        record: dict[str, Any] = {
            "remediation_id": str(uuid.uuid4()),
            "tenant_id": str(tenant_id),
            "control_id": control_id,
            "framework": framework,
            "remediation_action": remediation_action,
            "owner": owner,
            "due_date": due_date.isoformat(),
            "priority": priority,
            "status": "open",
            "created_at": datetime.now(UTC).isoformat(),
        }

        key = str(tenant_id)
        if key not in self._remediation_registry:
            self._remediation_registry[key] = []
        self._remediation_registry[key].append(record)

        logger.info(
            "Remediation action tracked",
            tenant_id=str(tenant_id),
            control_id=control_id,
            framework=framework,
            owner=owner,
            due_date=due_date.isoformat(),
            priority=priority,
        )

        return record

    def _compute_framework_score(self, controls: list[ControlStatus]) -> float:
        """Compute a weighted compliance score for a set of controls.

        Args:
            controls: List of ControlStatus instances to score.

        Returns:
            Weighted compliance score in range [0.0, 1.0].
        """
        if not controls:
            return 0.0

        status_scores = {
            "compliant": 1.0,
            "partial": 0.5,
            "non_compliant": 0.0,
            "not_assessed": 0.0 if self._score_not_assessed_as_zero else None,
        }

        scoreable = []
        for control in controls:
            score_value = status_scores.get(control.status)
            if score_value is not None:
                # Weight by effectiveness_score for partial compliance
                if control.status == "partial":
                    score_value = min(score_value, control.effectiveness_score)
                scoreable.append(score_value)

        if not scoreable:
            return 0.0

        return round(sum(scoreable) / len(scoreable), 4)

    def _build_remediation_items(
        self,
        controls: list[ControlStatus],
    ) -> list[dict[str, Any]]:
        """Build a prioritised remediation items list from non-compliant controls.

        Args:
            controls: List of non-compliant or partial controls.

        Returns:
            Sorted list of remediation item dicts, highest priority first.
        """
        items: list[dict[str, Any]] = []

        for control in controls:
            priority = "critical" if control.status == "non_compliant" else "medium"
            items.append({
                "control_id": control.control_id,
                "framework": control.framework,
                "article_ref": control.article_ref,
                "status": control.status,
                "effectiveness_score": control.effectiveness_score,
                "priority": priority,
                "gaps": control.gaps,
                "owner": control.remediation_owner,
                "due_date": (
                    control.remediation_due.isoformat()
                    if control.remediation_due else None
                ),
                "score_impact": 1.0 - control.effectiveness_score,
            })

        # Sort by priority (critical first) then score impact
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        items.sort(
            key=lambda i: (
                priority_order.get(i["priority"], 99),
                -i["score_impact"],
            )
        )

        return items

    def _compute_trend(self, tenant_id: uuid.UUID) -> str:
        """Compute the compliance trend direction.

        In production this would compare scores against historical snapshots.
        Current implementation returns 'stable' as the baseline.

        Args:
            tenant_id: The owning tenant UUID.

        Returns:
            Trend string: 'improving', 'stable', or 'declining'.
        """
        # TODO: Integrate with historical score snapshots from DB repository
        return "stable"


__all__ = [
    "ComplianceReporter",
    "ComplianceDashboard",
    "ControlStatus",
    "FrameworkReport",
    "FRAMEWORKS",
]
