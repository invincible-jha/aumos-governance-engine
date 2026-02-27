"""Compliance-as-Code engine — OPA policy evaluation orchestrator.

Evaluates AI systems against regulatory frameworks and returns compliance
status with evidence within 60 seconds.

Architecture:
- Real OPA path: httpx calls to OPA sidecar via the existing OPAClient
- Mock OPA path: Python-native evaluator for environments without OPA
  (test environments, CI/CD, early development)

The engine processes a compliance evaluation request by:
1. Resolving which regulations and articles to evaluate
2. Loading policies from the PolicyRegistry
3. Evaluating each article's policy against the input data
4. Mapping results to evidence items via EvidenceMapper
5. Computing overall compliance scores
6. Returning a ComplianceEvaluationResult

The architecture supports swapping the mock evaluator for real OPA by
implementing the IOPAEvaluator protocol (same interface as the existing
OPAClient but specialized for compliance batch evaluation).
"""

import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from aumos_common.observability import get_logger

from aumos_governance_engine.compliance_as_code.evidence_mapper import (
    ArticleEvaluationResult,
    EvidenceItem,
    build_article_evaluation_result,
    build_evidence_package_manifest,
    compute_regulation_compliance_score,
    map_evaluation_to_evidence,
)
from aumos_governance_engine.compliance_as_code.policy_registry import PolicyRegistry
from aumos_governance_engine.compliance_as_code.regulatory_inventory import (
    RegulationArticle,
    get_articles_for_regulation,
    get_regulation,
    get_supported_codes,
)

logger = get_logger(__name__)

# Compliance evaluation SLA in seconds
_EVALUATION_SLA_SECONDS = 60

# Status constants
STATUS_COMPLIANT = "compliant"
STATUS_NON_COMPLIANT = "non_compliant"
STATUS_PARTIAL = "partial"
STATUS_NOT_APPLICABLE = "not_applicable"


class IOPAEvaluator(Protocol):
    """Protocol for OPA policy evaluation within the compliance engine.

    Both the mock evaluator and the real OPA client must implement this protocol.
    """

    async def evaluate_policy(
        self,
        regulation: str,
        article_ref: str,
        policy_content: str,
        input_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate a policy against input data.

        Args:
            regulation: Regulation code.
            article_ref: Article reference.
            policy_content: Rego policy source or identifier.
            input_data: Structured evaluation input.

        Returns:
            Evaluation result dict with at minimum:
            - allow (bool)
            - violations (list[str])
            - implemented_controls (list[str])
            - missing_controls (list[str])
        """
        ...


class MockOPAEvaluator:
    """Python-native mock evaluator for environments without a real OPA server.

    Implements the same interface as the real OPA evaluator but processes
    policy logic in Python. The mock evaluator:
    - Checks implemented_controls against required controls from the article definition
    - Generates appropriate violations for missing controls
    - Supports the full compliance status lifecycle

    This evaluator is designed for:
    - Test environments
    - CI/CD pipelines
    - Early development before OPA is configured

    The architecture is identical to real OPA — swap by replacing this class
    with an OPAHttpEvaluator that calls the OPA sidecar.
    """

    def __init__(self, policy_registry: PolicyRegistry) -> None:
        """Initialize MockOPAEvaluator.

        Args:
            policy_registry: Registry containing loaded compliance policies.
        """
        self._registry = policy_registry

    async def evaluate_policy(
        self,
        regulation: str,
        article_ref: str,
        policy_content: str,
        input_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate a compliance policy using Python-native logic.

        Extracts the required_controls from the policy registry and checks
        whether the input's implemented_controls satisfies them.

        Args:
            regulation: Regulation code.
            article_ref: Article reference.
            policy_content: Rego source (used for hash verification only in mock).
            input_data: Structured evaluation input.

        Returns:
            Evaluation result dictionary.
        """
        # Get article definition for required controls
        articles = get_articles_for_regulation(regulation)
        article_def = next(
            (a for a in articles if a.article_ref == article_ref),
            None,
        )

        if article_def is None:
            logger.warning(
                "Article definition not found for evaluation",
                regulation=regulation,
                article_ref=article_ref,
            )
            return {
                "allow": False,
                "violations": [f"Article {article_ref} not found in {regulation} inventory"],
                "implemented_controls": [],
                "missing_controls": [],
                "article_title": article_ref,
                "confidence": 0.5,
            }

        return self._evaluate_article(article_def, input_data)

    def _evaluate_article(
        self,
        article: RegulationArticle,
        input_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate a single article against input data.

        Args:
            article: The regulation article definition.
            input_data: The evaluation input.

        Returns:
            Evaluation result dictionary.
        """
        implemented_controls: list[str] = []
        missing_controls: list[str] = []
        violations: list[str] = []

        # Gather all implemented controls from input
        input_implemented = set(input_data.get("implemented_controls", []))

        # Also check nested control structures
        for key in ("controls", "active_controls", "security_controls"):
            if isinstance(input_data.get(key), list):
                input_implemented.update(input_data[key])
            elif isinstance(input_data.get(key), dict):
                input_implemented.update(
                    k for k, v in input_data[key].items() if v is True
                )

        # Check each required control
        for control_id in article.control_ids:
            if control_id in input_implemented:
                implemented_controls.append(control_id)
            else:
                missing_controls.append(control_id)
                violations.append(
                    f"Required control '{control_id}' not implemented "
                    f"for {article.regulation if hasattr(article, 'regulation') else ''} "
                    f"{article.article_ref}: {article.title}"
                )

        # Apply risk-tier filtering if applicable
        if article.risk_tiers:
            model_risk_tier = input_data.get("risk_tier", "").lower()
            if model_risk_tier and model_risk_tier not in article.risk_tiers:
                # Article doesn't apply to this risk tier
                return {
                    "allow": True,
                    "violations": [],
                    "implemented_controls": list(input_implemented),
                    "missing_controls": [],
                    "article_title": article.title,
                    "status": STATUS_NOT_APPLICABLE,
                    "confidence": 1.0,
                    "not_applicable_reason": (
                        f"Article {article.article_ref} applies to risk tiers "
                        f"{article.risk_tiers}, model is '{model_risk_tier}'"
                    ),
                }

        allowed = len(missing_controls) == 0

        return {
            "allow": allowed,
            "violations": violations,
            "implemented_controls": implemented_controls,
            "missing_controls": missing_controls,
            "article_title": article.title,
            "required_controls": article.control_ids,
            "confidence": 0.95 if allowed else 0.9,
            "automated": article.automated,
        }


@dataclass
class ComplianceEvaluationResult:
    """Result of a compliance evaluation run.

    Attributes:
        evaluation_id: Unique ID for this evaluation.
        model_id: The AI model evaluated.
        tenant_id: Owning tenant.
        triggered_by: Who/what triggered the evaluation.
        regulations_evaluated: List of regulation codes evaluated.
        article_results: Per-article evaluation results.
        evidence_items: All evidence items collected.
        overall_compliant: Whether the model is fully compliant.
        compliant_count: Number of compliant articles.
        non_compliant_count: Number of non-compliant articles.
        partial_count: Number of partially compliant articles.
        not_applicable_count: Number of not-applicable articles.
        compliance_scores: Per-regulation compliance scores.
        overall_score: Weighted overall compliance score.
        evaluated_at: When evaluation completed.
        evaluation_duration_ms: How long evaluation took.
        package_manifest: Evidence package manifest.
    """

    evaluation_id: uuid.UUID
    model_id: str
    tenant_id: uuid.UUID
    triggered_by: str
    regulations_evaluated: list[str]
    article_results: list[ArticleEvaluationResult]
    evidence_items: list[EvidenceItem]
    overall_compliant: bool
    compliant_count: int
    non_compliant_count: int
    partial_count: int
    not_applicable_count: int
    compliance_scores: dict[str, float]
    overall_score: float
    evaluated_at: datetime
    evaluation_duration_ms: float
    package_manifest: dict[str, Any] = field(default_factory=dict)


class ComplianceEngine:
    """OPA policy evaluation orchestrator for regulatory compliance.

    Evaluates AI systems against one or more regulatory frameworks.
    Uses either the MockOPAEvaluator (default) or a real OPA-backed
    evaluator for production use.

    The engine supports:
    - Multi-regulation evaluations in a single call
    - Selective article evaluation (subset of articles)
    - Risk-tier-aware evaluation (articles only apply to relevant tiers)
    - Evidence collection and packaging
    - Sub-60-second evaluation SLA

    Args:
        evaluator: Policy evaluator implementing IOPAEvaluator.
        policy_registry: Registry of loaded compliance policies.
    """

    def __init__(
        self,
        evaluator: IOPAEvaluator,
        policy_registry: PolicyRegistry,
    ) -> None:
        """Initialize ComplianceEngine.

        Args:
            evaluator: The policy evaluator to use.
            policy_registry: Registry holding loaded policies.
        """
        self._evaluator = evaluator
        self._registry = policy_registry

    async def evaluate(
        self,
        model_id: str,
        tenant_id: uuid.UUID,
        regulations: list[str],
        input_data: dict[str, Any],
        triggered_by: str = "api",
        article_filter: list[str] | None = None,
    ) -> ComplianceEvaluationResult:
        """Evaluate an AI model against specified regulations.

        Runs policy evaluation for each article in each regulation and
        collects evidence. Must complete within 60 seconds.

        Args:
            model_id: Identifier of the AI model being evaluated.
            tenant_id: Owning tenant UUID.
            regulations: List of regulation codes to evaluate against.
            input_data: Structured input describing the AI system's
                properties (implemented_controls, risk_tier, etc.).
            triggered_by: Who/what triggered the evaluation.
            article_filter: Optional list of article refs to evaluate
                (evaluates all articles if None).

        Returns:
            ComplianceEvaluationResult with full evaluation output.

        Raises:
            ValueError: If an unsupported regulation code is provided.
        """
        evaluation_id = uuid.uuid4()
        start_time = time.monotonic()
        now = datetime.now(UTC)

        logger.info(
            "Starting compliance evaluation",
            evaluation_id=str(evaluation_id),
            model_id=model_id,
            tenant_id=str(tenant_id),
            regulations=regulations,
            triggered_by=triggered_by,
        )

        # Validate regulation codes
        supported = get_supported_codes()
        for regulation in regulations:
            if regulation not in supported:
                raise ValueError(
                    f"Unsupported regulation '{regulation}'. Supported: {sorted(supported)}"
                )

        all_article_results: list[ArticleEvaluationResult] = []
        all_evidence_items: list[EvidenceItem] = []

        for regulation in regulations:
            reg_def = get_regulation(regulation)
            if reg_def is None:
                continue

            # Ensure policies are loaded for this regulation
            self._registry.load_all_for_regulation(regulation)

            articles = get_articles_for_regulation(regulation)

            for article in articles:
                # Apply article filter if specified
                if article_filter and article.article_ref not in article_filter:
                    continue

                article_result, evidence_items = await self._evaluate_article(
                    evaluation_id=evaluation_id,
                    regulation=regulation,
                    article=article,
                    input_data=input_data,
                )
                all_article_results.append(article_result)
                all_evidence_items.extend(evidence_items)

                # Check SLA
                elapsed = time.monotonic() - start_time
                if elapsed > _EVALUATION_SLA_SECONDS * 0.9:
                    logger.warning(
                        "Compliance evaluation approaching SLA limit",
                        evaluation_id=str(evaluation_id),
                        elapsed_seconds=round(elapsed, 2),
                        sla_seconds=_EVALUATION_SLA_SECONDS,
                    )

        duration_ms = (time.monotonic() - start_time) * 1000

        # Compute scores and counts
        compliance_scores: dict[str, float] = {}
        for regulation in regulations:
            reg_results = [r for r in all_article_results if r.regulation == regulation]
            compliance_scores[regulation] = compute_regulation_compliance_score(reg_results)

        compliant_count = sum(
            1 for r in all_article_results if r.status == STATUS_COMPLIANT
        )
        non_compliant_count = sum(
            1 for r in all_article_results if r.status == STATUS_NON_COMPLIANT
        )
        partial_count = sum(
            1 for r in all_article_results if r.status == STATUS_PARTIAL
        )
        not_applicable_count = sum(
            1 for r in all_article_results if r.status == STATUS_NOT_APPLICABLE
        )

        overall_compliant = non_compliant_count == 0 and partial_count == 0

        # Overall score excludes not-applicable articles
        applicable_results = [
            r for r in all_article_results if r.status != STATUS_NOT_APPLICABLE
        ]
        overall_score = compute_regulation_compliance_score(applicable_results)

        # Build evidence package manifest
        package_manifest = build_evidence_package_manifest(
            evaluation_id=evaluation_id,
            tenant_id=tenant_id,
            model_id=model_id,
            regulations=regulations,
            article_results=all_article_results,
            evidence_items=all_evidence_items,
            generated_at=now,
        )

        result = ComplianceEvaluationResult(
            evaluation_id=evaluation_id,
            model_id=model_id,
            tenant_id=tenant_id,
            triggered_by=triggered_by,
            regulations_evaluated=regulations,
            article_results=all_article_results,
            evidence_items=all_evidence_items,
            overall_compliant=overall_compliant,
            compliant_count=compliant_count,
            non_compliant_count=non_compliant_count,
            partial_count=partial_count,
            not_applicable_count=not_applicable_count,
            compliance_scores=compliance_scores,
            overall_score=overall_score,
            evaluated_at=now,
            evaluation_duration_ms=round(duration_ms, 2),
            package_manifest=package_manifest,
        )

        logger.info(
            "Compliance evaluation complete",
            evaluation_id=str(evaluation_id),
            overall_compliant=overall_compliant,
            overall_score=overall_score,
            duration_ms=round(duration_ms, 2),
            compliant_count=compliant_count,
            non_compliant_count=non_compliant_count,
        )

        if duration_ms > _EVALUATION_SLA_SECONDS * 1000:
            logger.error(
                "Compliance evaluation exceeded SLA",
                evaluation_id=str(evaluation_id),
                duration_ms=round(duration_ms, 2),
                sla_ms=_EVALUATION_SLA_SECONDS * 1000,
            )

        return result

    async def _evaluate_article(
        self,
        evaluation_id: uuid.UUID,
        regulation: str,
        article: RegulationArticle,
        input_data: dict[str, Any],
    ) -> tuple[ArticleEvaluationResult, list[EvidenceItem]]:
        """Evaluate a single article and collect evidence.

        Args:
            evaluation_id: Parent evaluation UUID.
            regulation: Regulation code.
            article: Article definition to evaluate.
            input_data: Evaluation input data.

        Returns:
            Tuple of (ArticleEvaluationResult, list of EvidenceItems).
        """
        # Get policy content from registry
        loaded_policy = self._registry.get(regulation, article.article_ref)
        policy_content = loaded_policy.content if loaded_policy else ""

        # Run evaluation
        policy_result = await self._evaluator.evaluate_policy(
            regulation=regulation,
            article_ref=article.article_ref,
            policy_content=policy_content,
            input_data=input_data,
        )

        # Add article title to result for evidence mapping
        policy_result["article_title"] = article.title

        # Build article result
        article_result = build_article_evaluation_result(
            regulation=regulation,
            article_ref=article.article_ref,
            policy_result=policy_result,
            article_weight=article.weight,
        )

        # Override status to not_applicable if evaluator flagged it
        if policy_result.get("status") == STATUS_NOT_APPLICABLE:
            article_result = ArticleEvaluationResult(
                regulation=article_result.regulation,
                article_ref=article_result.article_ref,
                article_title=article_result.article_title,
                status=STATUS_NOT_APPLICABLE,
                implemented_controls=article_result.implemented_controls,
                missing_controls=[],
                violations=[],
                evidence_refs=[],
                score=1.0,  # N/A counts as neutral
                weight=article_result.weight,
            )

        # Map to evidence items
        evidence_items = map_evaluation_to_evidence(
            evaluation_id=evaluation_id,
            regulation=regulation,
            article_ref=article.article_ref,
            article_title=article.title,
            policy_result=policy_result,
            input_data=input_data,
        )

        return article_result, evidence_items

    async def evaluate_impact(
        self,
        policy_id: uuid.UUID,
        regulation: str,
        article_ref: str,
        proposed_changes: dict[str, Any],
        current_state: dict[str, Any],
    ) -> dict[str, Any]:
        """Assess the impact of proposed changes on compliance.

        Evaluates both current and proposed state and returns a diff
        showing how changes would affect compliance posture.

        Args:
            policy_id: The compliance policy UUID being assessed.
            regulation: Regulation code.
            article_ref: Article reference.
            proposed_changes: Proposed changes to the system state.
            current_state: Current system state.

        Returns:
            Impact assessment result with before/after comparison.
        """
        # Evaluate current state
        current_result = await self._evaluator.evaluate_policy(
            regulation=regulation,
            article_ref=article_ref,
            policy_content="",
            input_data=current_state,
        )

        # Merge proposed changes into current state
        proposed_state = {**current_state, **proposed_changes}
        proposed_result = await self._evaluator.evaluate_policy(
            regulation=regulation,
            article_ref=article_ref,
            policy_content="",
            input_data=proposed_state,
        )

        current_allowed = current_result.get("allow", False)
        proposed_allowed = proposed_result.get("allow", False)

        impact = "neutral"
        if proposed_allowed and not current_allowed:
            impact = "positive"
        elif not proposed_allowed and current_allowed:
            impact = "negative"

        return {
            "policy_id": str(policy_id),
            "regulation": regulation,
            "article_ref": article_ref,
            "impact": impact,
            "current_status": "compliant" if current_allowed else "non_compliant",
            "proposed_status": "compliant" if proposed_allowed else "non_compliant",
            "current_violations": current_result.get("violations", []),
            "proposed_violations": proposed_result.get("violations", []),
            "current_missing_controls": current_result.get("missing_controls", []),
            "proposed_missing_controls": proposed_result.get("missing_controls", []),
            "new_violations": [
                v for v in proposed_result.get("violations", [])
                if v not in current_result.get("violations", [])
            ],
            "resolved_violations": [
                v for v in current_result.get("violations", [])
                if v not in proposed_result.get("violations", [])
            ],
        }


def create_default_engine() -> ComplianceEngine:
    """Create a ComplianceEngine with default (mock) configuration.

    Returns a ComplianceEngine using the MockOPAEvaluator. This is suitable
    for testing and development. For production, instantiate ComplianceEngine
    with a real OPA HTTP evaluator.

    Returns:
        Configured ComplianceEngine instance.
    """
    registry = PolicyRegistry()
    evaluator = MockOPAEvaluator(registry)
    return ComplianceEngine(evaluator=evaluator, policy_registry=registry)
