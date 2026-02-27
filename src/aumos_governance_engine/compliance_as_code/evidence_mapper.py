"""Evidence mapper — maps evaluation results to compliance evidence items.

Translates the structured output from policy evaluations into evidence records
that can be stored, queried, and packaged for auditors. Each compliance
evaluation produces a set of evidence items documenting what was checked,
what passed, what failed, and what data supports the determination.

Evidence types produced:
- evaluation_result: The pass/fail result for a specific article check
- control_check: Evidence that a specific technical control is implemented
- audit_log_reference: Reference to supporting audit log entries
- policy_document: Reference to governance policy documents
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from aumos_common.observability import get_logger

from aumos_governance_engine.compliance_as_code.regulatory_inventory import (
    RegulationArticle,
    get_articles_for_regulation,
)

logger = get_logger(__name__)

# Evidence validity period in days — evidence items expire after this period
_EVIDENCE_VALIDITY_DAYS = 365

# Evidence types produced by the mapper
EVIDENCE_TYPE_EVALUATION_RESULT = "evaluation_result"
EVIDENCE_TYPE_CONTROL_CHECK = "control_check"
EVIDENCE_TYPE_AUDIT_LOG_REFERENCE = "audit_log_reference"
EVIDENCE_TYPE_POLICY_DOCUMENT = "policy_document"
EVIDENCE_TYPE_AUTOMATED_SCAN = "automated_scan"


@dataclass
class EvidenceItem:
    """A single piece of compliance evidence.

    Attributes:
        evidence_id: Unique identifier for this evidence item.
        evaluation_id: Parent evaluation this evidence belongs to.
        regulation: Regulation code (e.g., "eu_ai_act").
        article_ref: Article/section reference this evidence addresses.
        requirement_summary: Brief summary of the requirement being evidenced.
        evidence_type: Classification of the evidence.
        status: Whether this evidence demonstrates compliance or non-compliance.
        evidence_data: Structured data supporting the evidence claim.
        control_ids_evidenced: Technical control IDs evidenced by this item.
        collected_at: When this evidence was collected.
        expires_at: When this evidence expires (requires re-collection).
        confidence: Confidence score 0.0-1.0 in the evidence quality.
        notes: Optional human-readable notes.
    """

    evidence_id: UUID
    evaluation_id: UUID
    regulation: str
    article_ref: str
    requirement_summary: str
    evidence_type: str
    status: str  # compliant | non_compliant | partial | not_applicable
    evidence_data: dict[str, Any]
    control_ids_evidenced: list[str]
    collected_at: datetime
    expires_at: datetime
    confidence: float
    notes: str | None = None


@dataclass
class ArticleEvaluationResult:
    """Result of evaluating a single article/requirement.

    Attributes:
        regulation: Regulation code.
        article_ref: Article reference.
        article_title: Human-readable article title.
        status: Compliance status for this article.
        implemented_controls: Controls found to be implemented.
        missing_controls: Controls required but not found.
        violations: Specific violation messages from policy evaluation.
        evidence_refs: References to supporting evidence.
        score: Compliance score for this article (0.0-1.0).
        weight: Weight of this article in the overall score.
    """

    regulation: str
    article_ref: str
    article_title: str
    status: str
    implemented_controls: list[str]
    missing_controls: list[str]
    violations: list[str]
    evidence_refs: list[str]
    score: float
    weight: float


def map_evaluation_to_evidence(
    evaluation_id: UUID,
    regulation: str,
    article_ref: str,
    article_title: str,
    policy_result: dict[str, Any],
    input_data: dict[str, Any],
    evidence_validity_days: int = _EVIDENCE_VALIDITY_DAYS,
) -> list[EvidenceItem]:
    """Map a policy evaluation result to evidence items.

    Converts the structured output from an OPA or mock policy evaluation
    into a list of EvidenceItem instances that can be stored and presented
    to auditors.

    Args:
        evaluation_id: Parent evaluation UUID.
        regulation: Regulation code.
        article_ref: Article reference evaluated.
        article_title: Human-readable article title.
        policy_result: Structured output from policy evaluation.
        input_data: Input data that was evaluated.
        evidence_validity_days: How many days evidence remains valid.

    Returns:
        List of EvidenceItem instances documenting the evaluation.
    """
    now = datetime.now(UTC)
    expires_at = datetime.fromtimestamp(
        now.timestamp() + evidence_validity_days * 86400, tz=UTC
    )

    allowed: bool = policy_result.get("allow", False)
    violations: list[str] = list(policy_result.get("violations", []))
    implemented_controls: list[str] = list(policy_result.get("implemented_controls", []))
    missing_controls: list[str] = list(policy_result.get("missing_controls", []))
    confidence: float = float(policy_result.get("confidence", 0.8 if allowed else 0.9))

    status = _determine_status(allowed, violations, missing_controls)

    evidence_items: list[EvidenceItem] = []

    # Primary evaluation result evidence
    primary_evidence = EvidenceItem(
        evidence_id=uuid4(),
        evaluation_id=evaluation_id,
        regulation=regulation,
        article_ref=article_ref,
        requirement_summary=f"{regulation} {article_ref}: {article_title}",
        evidence_type=EVIDENCE_TYPE_EVALUATION_RESULT,
        status=status,
        evidence_data={
            "policy_allowed": allowed,
            "violations": violations,
            "implemented_controls": implemented_controls,
            "missing_controls": missing_controls,
            "evaluation_input_summary": _summarize_input(input_data),
            "article_title": article_title,
        },
        control_ids_evidenced=implemented_controls,
        collected_at=now,
        expires_at=expires_at,
        confidence=confidence,
    )
    evidence_items.append(primary_evidence)

    # Per-control evidence items for implemented controls
    for control_id in implemented_controls:
        control_evidence = EvidenceItem(
            evidence_id=uuid4(),
            evaluation_id=evaluation_id,
            regulation=regulation,
            article_ref=article_ref,
            requirement_summary=f"Control implemented: {control_id}",
            evidence_type=EVIDENCE_TYPE_CONTROL_CHECK,
            status="compliant",
            evidence_data={
                "control_id": control_id,
                "detected_in": _find_control_source(control_id, input_data),
                "article_ref": article_ref,
            },
            control_ids_evidenced=[control_id],
            collected_at=now,
            expires_at=expires_at,
            confidence=0.95,
        )
        evidence_items.append(control_evidence)

    # Audit log reference evidence if available
    if audit_refs := input_data.get("audit_log_references", []):
        audit_evidence = EvidenceItem(
            evidence_id=uuid4(),
            evaluation_id=evaluation_id,
            regulation=regulation,
            article_ref=article_ref,
            requirement_summary=f"Audit log evidence for {regulation} {article_ref}",
            evidence_type=EVIDENCE_TYPE_AUDIT_LOG_REFERENCE,
            status=status,
            evidence_data={
                "audit_log_references": audit_refs,
                "reference_count": len(audit_refs),
            },
            control_ids_evidenced=implemented_controls,
            collected_at=now,
            expires_at=expires_at,
            confidence=0.9,
        )
        evidence_items.append(audit_evidence)

    logger.debug(
        "Evidence items mapped from evaluation",
        evaluation_id=str(evaluation_id),
        regulation=regulation,
        article_ref=article_ref,
        status=status,
        evidence_count=len(evidence_items),
    )

    return evidence_items


def _determine_status(
    allowed: bool,
    violations: list[str],
    missing_controls: list[str],
) -> str:
    """Determine the compliance status from evaluation results.

    Args:
        allowed: Whether the policy allowed the evaluated subject.
        violations: List of violation messages.
        missing_controls: List of missing control IDs.

    Returns:
        Status string: compliant | non_compliant | partial | not_applicable.
    """
    if allowed and not violations and not missing_controls:
        return "compliant"
    if not allowed and (violations or missing_controls):
        return "non_compliant"
    if allowed and (violations or missing_controls):
        # Partial: allowed but with some issues
        return "partial"
    return "non_compliant"


def _summarize_input(input_data: dict[str, Any]) -> dict[str, Any]:
    """Create a safe summary of evaluation input for evidence storage.

    Strips sensitive values but preserves structure and key presence.

    Args:
        input_data: Raw evaluation input.

    Returns:
        Sanitized summary dict.
    """
    summary: dict[str, Any] = {}
    for key, value in input_data.items():
        if key in ("api_keys", "credentials", "secrets", "passwords", "tokens"):
            summary[key] = "[REDACTED]"
        elif isinstance(value, dict):
            summary[key] = f"<dict with {len(value)} keys>"
        elif isinstance(value, list):
            summary[key] = f"<list with {len(value)} items>"
        else:
            summary[key] = value
    return summary


def _find_control_source(control_id: str, input_data: dict[str, Any]) -> str:
    """Find where a control ID was detected in the input data.

    Args:
        control_id: The control ID to find.
        input_data: The evaluation input data.

    Returns:
        Source description string.
    """
    implemented = input_data.get("implemented_controls", [])
    if control_id in implemented:
        return "implemented_controls_list"

    # Check nested control structures
    for key, value in input_data.items():
        if isinstance(value, dict) and control_id in value:
            return f"field:{key}"
        if isinstance(value, list) and control_id in value:
            return f"field:{key}"

    return "unknown"


def build_article_evaluation_result(
    regulation: str,
    article_ref: str,
    policy_result: dict[str, Any],
    article_weight: float = 1.0,
) -> ArticleEvaluationResult:
    """Build an ArticleEvaluationResult from a policy evaluation.

    Args:
        regulation: Regulation code.
        article_ref: Article reference.
        policy_result: Structured output from policy evaluation.
        article_weight: Weight of this article in overall scoring.

    Returns:
        ArticleEvaluationResult instance.
    """
    allowed: bool = policy_result.get("allow", False)
    violations: list[str] = list(policy_result.get("violations", []))
    implemented_controls: list[str] = list(policy_result.get("implemented_controls", []))
    missing_controls: list[str] = list(policy_result.get("missing_controls", []))

    status = _determine_status(allowed, violations, missing_controls)

    # Score calculation: full score if compliant, partial if partial, 0 if non-compliant
    score: float
    if status == "compliant":
        score = 1.0
    elif status == "partial":
        total = len(implemented_controls) + len(missing_controls)
        score = len(implemented_controls) / total if total > 0 else 0.5
    else:
        score = 0.0

    article_title = policy_result.get("article_title", article_ref)

    return ArticleEvaluationResult(
        regulation=regulation,
        article_ref=article_ref,
        article_title=article_title,
        status=status,
        implemented_controls=implemented_controls,
        missing_controls=missing_controls,
        violations=violations,
        evidence_refs=[],
        score=score,
        weight=article_weight,
    )


def compute_regulation_compliance_score(
    article_results: list[ArticleEvaluationResult],
) -> float:
    """Compute an overall compliance score for a regulation.

    Uses weighted average of per-article scores.

    Args:
        article_results: List of per-article evaluation results.

    Returns:
        Overall compliance score between 0.0 and 1.0.
    """
    if not article_results:
        return 0.0

    total_weight = sum(r.weight for r in article_results)
    if total_weight == 0.0:
        return 0.0

    weighted_sum = sum(r.score * r.weight for r in article_results)
    return round(weighted_sum / total_weight, 4)


def build_evidence_package_manifest(
    evaluation_id: UUID,
    tenant_id: UUID,
    model_id: str,
    regulations: list[str],
    article_results: list[ArticleEvaluationResult],
    evidence_items: list[EvidenceItem],
    generated_at: datetime,
) -> dict[str, Any]:
    """Build a manifest document for a compliance evidence package.

    The manifest summarizes what is in the package and provides
    metadata for auditors. Used as the index file in ZIP evidence packages.

    Args:
        evaluation_id: The evaluation UUID.
        tenant_id: The tenant UUID.
        model_id: The AI model identifier.
        regulations: List of regulation codes evaluated.
        article_results: Per-article evaluation results.
        evidence_items: All evidence items collected.
        generated_at: Package generation timestamp.

    Returns:
        Package manifest dictionary.
    """
    overall_status = "compliant"
    for result in article_results:
        if result.status == "non_compliant":
            overall_status = "non_compliant"
            break
        if result.status == "partial":
            overall_status = "partial"

    compliance_scores = {}
    for reg_code in regulations:
        reg_results = [r for r in article_results if r.regulation == reg_code]
        compliance_scores[reg_code] = compute_regulation_compliance_score(reg_results)

    return {
        "manifest_version": "1.0",
        "evaluation_id": str(evaluation_id),
        "tenant_id": str(tenant_id),
        "model_id": model_id,
        "generated_at": generated_at.isoformat(),
        "regulations_evaluated": regulations,
        "overall_status": overall_status,
        "compliance_scores": compliance_scores,
        "article_count": len(article_results),
        "evidence_item_count": len(evidence_items),
        "compliant_articles": sum(1 for r in article_results if r.status == "compliant"),
        "non_compliant_articles": sum(1 for r in article_results if r.status == "non_compliant"),
        "partial_articles": sum(1 for r in article_results if r.status == "partial"),
        "not_applicable_articles": sum(
            1 for r in article_results if r.status == "not_applicable"
        ),
    }
