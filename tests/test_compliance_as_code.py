"""Tests for the compliance-as-code engine (P1.1).

Covers:
- regulatory_inventory: catalog lookups, article metadata
- evidence_mapper: status determination, evidence construction, scoring
- policy_registry: loading, hash checking, fallback policies
- engine: MockOPAEvaluator, ComplianceEngine evaluation, impact assessment

All tests are synchronous or async-first using pytest-asyncio.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from aumos_governance_engine.compliance_as_code.engine import (
    ComplianceEngine,
    MockOPAEvaluator,
    create_default_engine,
)
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
    build_regulation_metadata,
    get_articles_for_regulation,
    get_regulation,
    get_supported_codes,
    list_regulations,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_evaluation_result(
    regulation: str = "iso_42001",
    article_ref: str = "4.1",
    status: str = "compliant",
    score: float = 1.0,
    weight: float = 1.0,
    implemented_controls: list[str] | None = None,
    missing_controls: list[str] | None = None,
    violations: list[str] | None = None,
) -> ArticleEvaluationResult:
    return ArticleEvaluationResult(
        regulation=regulation,
        article_ref=article_ref,
        article_title=f"{regulation} {article_ref}",
        status=status,
        implemented_controls=implemented_controls or [],
        missing_controls=missing_controls or [],
        violations=violations or [],
        evidence_refs=[],
        score=score,
        weight=weight,
    )


def _make_policy_result(
    allow: bool = True,
    violations: list[str] | None = None,
    implemented_controls: list[str] | None = None,
    missing_controls: list[str] | None = None,
    confidence: float = 0.95,
    article_title: str = "Test Article",
) -> dict[str, Any]:
    return {
        "allow": allow,
        "violations": violations or [],
        "implemented_controls": implemented_controls or [],
        "missing_controls": missing_controls or [],
        "confidence": confidence,
        "article_title": article_title,
    }


# ---------------------------------------------------------------------------
# Test 1: Regulatory inventory — supported codes
# ---------------------------------------------------------------------------


def test_supported_regulation_codes_are_complete() -> None:
    """All six required regulation codes are present in the catalog."""
    codes = get_supported_codes()
    expected = {"eu_ai_act", "nist_ai_rmf", "iso_42001", "hipaa", "sox", "dora"}
    assert expected.issubset(codes), f"Missing codes: {expected - codes}"


# ---------------------------------------------------------------------------
# Test 2: Regulatory inventory — get_regulation returns correct metadata
# ---------------------------------------------------------------------------


def test_get_regulation_returns_definition_for_known_code() -> None:
    """get_regulation returns a fully populated RegulationDefinition."""
    reg = get_regulation("eu_ai_act")
    assert reg is not None
    assert reg.code == "eu_ai_act"
    assert reg.ai_specific is True
    assert len(reg.articles) > 0


def test_get_regulation_returns_none_for_unknown_code() -> None:
    """get_regulation returns None for unrecognized codes."""
    assert get_regulation("unknown_regulation_xyz") is None


# ---------------------------------------------------------------------------
# Test 3: Regulatory inventory — article count sanity checks
# ---------------------------------------------------------------------------


def test_eu_ai_act_has_expected_articles() -> None:
    """EU AI Act must include Art. 6, Art. 9, Art. 43."""
    articles = get_articles_for_regulation("eu_ai_act")
    refs = {a.article_ref for a in articles}
    assert "Art. 6" in refs
    assert "Art. 9" in refs
    assert "Art. 43" in refs


def test_iso_42001_has_all_seven_sections() -> None:
    """ISO 42001 must include all seven sections (4.1 through 10.1)."""
    articles = get_articles_for_regulation("iso_42001")
    refs = {a.article_ref for a in articles}
    expected_refs = {"4.1", "5.1", "6.1", "7.2", "8.4", "9.1", "10.1"}
    assert expected_refs == refs


# ---------------------------------------------------------------------------
# Test 4: Regulatory inventory — build_regulation_metadata
# ---------------------------------------------------------------------------


def test_build_regulation_metadata_has_required_fields() -> None:
    """build_regulation_metadata returns a dict with all mandatory fields."""
    meta = build_regulation_metadata("hipaa")
    assert meta["code"] == "hipaa"
    assert "article_count" in meta
    assert meta["article_count"] > 0
    assert "full_name" in meta
    assert "issuing_body" in meta


def test_build_regulation_metadata_raises_for_unknown_code() -> None:
    """build_regulation_metadata raises KeyError for unknown codes."""
    with pytest.raises(KeyError):
        build_regulation_metadata("not_a_real_regulation")


# ---------------------------------------------------------------------------
# Test 5: Regulatory inventory — list_regulations
# ---------------------------------------------------------------------------


def test_list_regulations_returns_all_six() -> None:
    """list_regulations returns all six definitions."""
    regs = list_regulations()
    assert len(regs) >= 6
    codes = {r.code for r in regs}
    assert "eu_ai_act" in codes
    assert "dora" in codes


# ---------------------------------------------------------------------------
# Test 6: Evidence mapper — _determine_status
# ---------------------------------------------------------------------------


def test_determine_status_via_build_article_evaluation_result_compliant() -> None:
    """Status is 'compliant' when all controls pass and no violations."""
    result = build_article_evaluation_result(
        regulation="iso_42001",
        article_ref="4.1",
        policy_result=_make_policy_result(
            allow=True,
            violations=[],
            implemented_controls=["CONTEXT_ANALYSIS", "STAKEHOLDER_MAPPING"],
            missing_controls=[],
        ),
    )
    assert result.status == "compliant"
    assert result.score == 1.0


def test_determine_status_non_compliant_when_controls_missing() -> None:
    """Status is 'non_compliant' when required controls are missing."""
    result = build_article_evaluation_result(
        regulation="iso_42001",
        article_ref="4.1",
        policy_result=_make_policy_result(
            allow=False,
            violations=["Required control 'STAKEHOLDER_MAPPING' not implemented"],
            implemented_controls=["CONTEXT_ANALYSIS"],
            missing_controls=["STAKEHOLDER_MAPPING"],
        ),
    )
    assert result.status == "non_compliant"
    assert result.score == 0.0


# ---------------------------------------------------------------------------
# Test 7: Evidence mapper — scoring logic
# ---------------------------------------------------------------------------


def test_compliance_score_is_zero_when_no_results() -> None:
    """compute_regulation_compliance_score returns 0.0 for empty input."""
    assert compute_regulation_compliance_score([]) == 0.0


def test_compliance_score_weighted_average_across_articles() -> None:
    """Weighted average score is computed correctly."""
    results = [
        _make_evaluation_result(score=1.0, weight=1.0),
        _make_evaluation_result(score=0.0, weight=1.0),
    ]
    score = compute_regulation_compliance_score(results)
    assert score == pytest.approx(0.5, abs=0.001)


def test_compliance_score_respects_weights() -> None:
    """Higher-weighted articles contribute more to overall score."""
    results = [
        _make_evaluation_result(score=1.0, weight=2.0),  # weight 2x
        _make_evaluation_result(score=0.0, weight=1.0),
    ]
    score = compute_regulation_compliance_score(results)
    # (1.0 * 2 + 0.0 * 1) / (2 + 1) = 0.6667
    assert score == pytest.approx(2 / 3, abs=0.001)


# ---------------------------------------------------------------------------
# Test 8: Evidence mapper — map_evaluation_to_evidence
# ---------------------------------------------------------------------------


def test_map_evaluation_to_evidence_produces_primary_item() -> None:
    """map_evaluation_to_evidence always produces at least one evidence item."""
    evaluation_id = uuid.uuid4()
    items = map_evaluation_to_evidence(
        evaluation_id=evaluation_id,
        regulation="iso_42001",
        article_ref="4.1",
        article_title="Understanding the organization",
        policy_result=_make_policy_result(
            allow=True,
            implemented_controls=["CONTEXT_ANALYSIS"],
        ),
        input_data={"implemented_controls": ["CONTEXT_ANALYSIS"]},
    )
    assert len(items) >= 1
    primary = items[0]
    assert primary.evaluation_id == evaluation_id
    assert primary.regulation == "iso_42001"
    assert primary.article_ref == "4.1"
    assert primary.evidence_type == "evaluation_result"


def test_map_evaluation_produces_control_check_items_per_control() -> None:
    """One control_check evidence item is created per implemented control."""
    evaluation_id = uuid.uuid4()
    items = map_evaluation_to_evidence(
        evaluation_id=evaluation_id,
        regulation="iso_42001",
        article_ref="4.1",
        article_title="Understanding the organization",
        policy_result=_make_policy_result(
            allow=True,
            implemented_controls=["CONTEXT_ANALYSIS", "STAKEHOLDER_MAPPING"],
        ),
        input_data={"implemented_controls": ["CONTEXT_ANALYSIS", "STAKEHOLDER_MAPPING"]},
    )
    control_check_items = [i for i in items if i.evidence_type == "control_check"]
    assert len(control_check_items) == 2


def test_map_evaluation_produces_audit_log_evidence_when_refs_present() -> None:
    """An audit_log_reference evidence item is created when audit refs exist."""
    evaluation_id = uuid.uuid4()
    items = map_evaluation_to_evidence(
        evaluation_id=evaluation_id,
        regulation="hipaa",
        article_ref="164.312(b)",
        article_title="Audit Controls",
        policy_result=_make_policy_result(
            allow=True,
            implemented_controls=["AUDIT_LOGGING"],
        ),
        input_data={
            "implemented_controls": ["AUDIT_LOGGING"],
            "audit_log_references": ["audit://log/2024-01-01", "audit://log/2024-01-02"],
        },
    )
    audit_items = [i for i in items if i.evidence_type == "audit_log_reference"]
    assert len(audit_items) == 1
    assert audit_items[0].evidence_data["reference_count"] == 2


# ---------------------------------------------------------------------------
# Test 9: Evidence mapper — build_evidence_package_manifest
# ---------------------------------------------------------------------------


def test_evidence_package_manifest_has_required_structure() -> None:
    """Evidence package manifest contains all required metadata fields."""
    evaluation_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    article_results = [
        _make_evaluation_result(status="compliant", score=1.0),
        _make_evaluation_result(status="non_compliant", score=0.0),
    ]
    manifest = build_evidence_package_manifest(
        evaluation_id=evaluation_id,
        tenant_id=tenant_id,
        model_id="model-test-001",
        regulations=["iso_42001"],
        article_results=article_results,
        evidence_items=[],
        generated_at=datetime.now(UTC),
    )
    assert manifest["manifest_version"] == "1.0"
    assert manifest["evaluation_id"] == str(evaluation_id)
    assert manifest["tenant_id"] == str(tenant_id)
    assert manifest["overall_status"] == "non_compliant"
    assert manifest["compliant_articles"] == 1
    assert manifest["non_compliant_articles"] == 1


# ---------------------------------------------------------------------------
# Test 10: Policy registry — load and retrieve
# ---------------------------------------------------------------------------


def test_policy_registry_load_from_content_and_retrieve() -> None:
    """Policies can be loaded from content strings and retrieved by key."""
    registry = PolicyRegistry()
    content = "package test\n\ndefault allow = true"
    registry.load_from_content(
        regulation="iso_42001",
        article_ref="4.1",
        content=content,
        version="1.0.0",
    )
    loaded = registry.get("iso_42001", "4.1")
    assert loaded is not None
    assert loaded.content == content
    assert loaded.regulation == "iso_42001"
    assert loaded.article_ref == "4.1"


def test_policy_registry_returns_none_for_missing_policy() -> None:
    """PolicyRegistry.get returns None for unregistered policies."""
    registry = PolicyRegistry()
    result = registry.get("eu_ai_act", "Art. 999")
    assert result is None


def test_policy_registry_content_hash_changes_on_update() -> None:
    """Policy content hash changes when policy is updated."""
    registry = PolicyRegistry()
    content_v1 = "package test\n\ndefault allow = true"
    content_v2 = "package test\n\ndefault allow = false"
    registry.load_from_content("iso_42001", "4.1", content_v1, "1.0.0")
    hash_v1 = registry.get("iso_42001", "4.1").content_hash  # type: ignore[union-attr]
    registry.load_from_content("iso_42001", "4.1", content_v2, "1.0.1")
    hash_v2 = registry.get("iso_42001", "4.1").content_hash  # type: ignore[union-attr]
    assert hash_v1 != hash_v2


def test_policy_registry_get_stats_reflects_loaded_policies() -> None:
    """PolicyRegistry stats accurately reflect the number of loaded policies."""
    registry = PolicyRegistry()
    for i in range(3):
        registry.load_from_content(
            "iso_42001",
            f"4.{i}",
            "package test\ndefault allow = true",
            "1.0.0",
        )
    stats = registry.get_stats()
    assert stats["total_policies"] >= 3


# ---------------------------------------------------------------------------
# Test 11: MockOPAEvaluator — compliant evaluation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mock_evaluator_returns_allow_when_all_controls_present() -> None:
    """MockOPAEvaluator returns allow=True when all required controls are implemented."""
    registry = PolicyRegistry()
    evaluator = MockOPAEvaluator(registry)

    result = await evaluator.evaluate_policy(
        regulation="iso_42001",
        article_ref="4.1",
        policy_content="",
        input_data={
            "implemented_controls": ["CONTEXT_ANALYSIS", "STAKEHOLDER_MAPPING"],
        },
    )
    assert result["allow"] is True
    assert result["violations"] == []
    assert result["missing_controls"] == []


# ---------------------------------------------------------------------------
# Test 12: MockOPAEvaluator — non-compliant evaluation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mock_evaluator_returns_violations_when_controls_missing() -> None:
    """MockOPAEvaluator reports violations for each missing required control."""
    registry = PolicyRegistry()
    evaluator = MockOPAEvaluator(registry)

    result = await evaluator.evaluate_policy(
        regulation="iso_42001",
        article_ref="4.1",
        policy_content="",
        input_data={
            "implemented_controls": [],  # Nothing implemented
        },
    )
    assert result["allow"] is False
    assert len(result["violations"]) == 2  # CONTEXT_ANALYSIS + STAKEHOLDER_MAPPING
    assert "CONTEXT_ANALYSIS" in result["missing_controls"]
    assert "STAKEHOLDER_MAPPING" in result["missing_controls"]


# ---------------------------------------------------------------------------
# Test 13: MockOPAEvaluator — risk tier filtering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mock_evaluator_not_applicable_for_non_matching_risk_tier() -> None:
    """EU AI Act high-risk articles return not_applicable for low-risk systems."""
    registry = PolicyRegistry()
    evaluator = MockOPAEvaluator(registry)

    result = await evaluator.evaluate_policy(
        regulation="eu_ai_act",
        article_ref="Art. 6",  # High-risk only
        policy_content="",
        input_data={
            "implemented_controls": [],
            "risk_tier": "minimal",  # Not high-risk
        },
    )
    assert result["allow"] is True
    assert result.get("status") == "not_applicable"


@pytest.mark.asyncio
async def test_mock_evaluator_evaluates_high_risk_article_for_high_risk_system() -> None:
    """EU AI Act high-risk articles are evaluated for high-risk systems."""
    registry = PolicyRegistry()
    evaluator = MockOPAEvaluator(registry)

    result = await evaluator.evaluate_policy(
        regulation="eu_ai_act",
        article_ref="Art. 6",
        policy_content="",
        input_data={
            "implemented_controls": ["AI_RISK_CLASSIFICATION", "HIGH_RISK_DETERMINATION"],
            "risk_tier": "high",
        },
    )
    # Risk tier matches — should evaluate normally
    assert result.get("status") != "not_applicable"
    assert result["allow"] is True


# ---------------------------------------------------------------------------
# Test 14: ComplianceEngine — full multi-regulation evaluation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_compliance_engine_evaluates_single_regulation() -> None:
    """ComplianceEngine produces a result with correct structure for one regulation."""
    engine = create_default_engine()
    tenant_id = uuid.uuid4()

    result = await engine.evaluate(
        model_id="test-model-001",
        tenant_id=tenant_id,
        regulations=["iso_42001"],
        input_data={
            "implemented_controls": [
                "CONTEXT_ANALYSIS",
                "STAKEHOLDER_MAPPING",
                "AI_GOVERNANCE_COMMITTEE",
                "EXECUTIVE_SPONSORSHIP",
                "AI_RISK_ASSESSMENT",
                "AI_IMPACT_ANALYSIS",
                "OPPORTUNITY_IDENTIFICATION",
                "AI_TRAINING_PROGRAM",
                "COMPETENCE_ASSESSMENT",
                "AI_IMPACT_ASSESSMENT",
                "EXPLAINABILITY_REPORT",
                "STAKEHOLDER_IMPACT",
                "MODEL_MONITORING",
                "DRIFT_DETECTION",
                "BIAS_DETECTION",
                "PERFORMANCE_KPIs",
                "IMPROVEMENT_PROCESS",
                "LESSONS_LEARNED",
            ],
        },
        triggered_by="test",
    )

    assert result.model_id == "test-model-001"
    assert result.tenant_id == tenant_id
    assert "iso_42001" in result.regulations_evaluated
    assert result.evaluation_id is not None
    assert result.evaluation_duration_ms >= 0
    assert isinstance(result.article_results, list)
    assert len(result.article_results) == 7  # ISO 42001 has 7 articles
    assert result.overall_compliant is True


@pytest.mark.asyncio
async def test_compliance_engine_reports_non_compliant_when_controls_missing() -> None:
    """ComplianceEngine flags non-compliance when required controls are absent."""
    engine = create_default_engine()

    result = await engine.evaluate(
        model_id="non-compliant-model",
        tenant_id=uuid.uuid4(),
        regulations=["iso_42001"],
        input_data={"implemented_controls": []},  # Nothing implemented
        triggered_by="test",
    )
    assert result.overall_compliant is False
    assert result.non_compliant_count > 0
    assert result.overall_score < 1.0


# ---------------------------------------------------------------------------
# Test 15: ComplianceEngine — invalid regulation raises ValueError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_compliance_engine_raises_for_unsupported_regulation() -> None:
    """ComplianceEngine raises ValueError for unsupported regulation codes."""
    engine = create_default_engine()
    with pytest.raises(ValueError, match="Unsupported regulation"):
        await engine.evaluate(
            model_id="model-x",
            tenant_id=uuid.uuid4(),
            regulations=["fantasy_regulation_2099"],
            input_data={},
        )


# ---------------------------------------------------------------------------
# Test 16: ComplianceEngine — article filter restricts evaluation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_compliance_engine_respects_article_filter() -> None:
    """ComplianceEngine only evaluates filtered articles when article_filter is set."""
    engine = create_default_engine()

    result = await engine.evaluate(
        model_id="filtered-model",
        tenant_id=uuid.uuid4(),
        regulations=["iso_42001"],
        input_data={"implemented_controls": ["CONTEXT_ANALYSIS", "STAKEHOLDER_MAPPING"]},
        article_filter=["4.1"],
    )
    # Only one article should be evaluated
    assert len(result.article_results) == 1
    assert result.article_results[0].article_ref == "4.1"


# ---------------------------------------------------------------------------
# Test 17: ComplianceEngine — impact assessment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_impact_assessment_detects_positive_impact() -> None:
    """evaluate_impact reports 'positive' when proposed changes resolve violations."""
    engine = create_default_engine()
    policy_id = uuid.uuid4()

    impact_result = await engine.evaluate_impact(
        policy_id=policy_id,
        regulation="iso_42001",
        article_ref="4.1",
        proposed_changes={
            "implemented_controls": ["CONTEXT_ANALYSIS", "STAKEHOLDER_MAPPING"],
        },
        current_state={
            "implemented_controls": [],  # Currently non-compliant
        },
    )
    assert impact_result["impact"] == "positive"
    assert impact_result["current_status"] == "non_compliant"
    assert impact_result["proposed_status"] == "compliant"


@pytest.mark.asyncio
async def test_impact_assessment_detects_negative_impact() -> None:
    """evaluate_impact reports 'negative' when proposed changes introduce violations."""
    engine = create_default_engine()
    policy_id = uuid.uuid4()

    impact_result = await engine.evaluate_impact(
        policy_id=policy_id,
        regulation="iso_42001",
        article_ref="4.1",
        proposed_changes={
            "implemented_controls": [],  # Removing all controls
        },
        current_state={
            "implemented_controls": ["CONTEXT_ANALYSIS", "STAKEHOLDER_MAPPING"],
        },
    )
    assert impact_result["impact"] == "negative"
    assert impact_result["current_status"] == "compliant"
    assert impact_result["proposed_status"] == "non_compliant"


# ---------------------------------------------------------------------------
# Test 18: ComplianceEngine — multi-regulation evaluation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_compliance_engine_evaluates_multiple_regulations() -> None:
    """ComplianceEngine processes multiple regulations in a single call."""
    engine = create_default_engine()

    result = await engine.evaluate(
        model_id="multi-reg-model",
        tenant_id=uuid.uuid4(),
        regulations=["iso_42001", "nist_ai_rmf"],
        input_data={
            "implemented_controls": [],  # Force non-compliance on both
        },
    )
    assert "iso_42001" in result.regulations_evaluated
    assert "nist_ai_rmf" in result.regulations_evaluated
    # Should have results from both regulations
    reg_codes_in_results = {r.regulation for r in result.article_results}
    assert "iso_42001" in reg_codes_in_results
    assert "nist_ai_rmf" in reg_codes_in_results
    # Should have scores for both
    assert "iso_42001" in result.compliance_scores
    assert "nist_ai_rmf" in result.compliance_scores


# ---------------------------------------------------------------------------
# Test 19: Evidence item expiry
# ---------------------------------------------------------------------------


def test_evidence_items_have_future_expiry() -> None:
    """Evidence items must expire in the future (default 365 days)."""
    evaluation_id = uuid.uuid4()
    now = datetime.now(UTC)

    items = map_evaluation_to_evidence(
        evaluation_id=evaluation_id,
        regulation="hipaa",
        article_ref="164.312(a)(1)",
        article_title="Access Control",
        policy_result=_make_policy_result(
            allow=True,
            implemented_controls=["UNIQUE_USER_ID", "ACCESS_CONTROL", "AUTH_MFA"],
        ),
        input_data={"implemented_controls": ["UNIQUE_USER_ID", "ACCESS_CONTROL", "AUTH_MFA"]},
    )
    for item in items:
        assert item.expires_at > now, "Evidence item must expire in the future"


# ---------------------------------------------------------------------------
# Test 20: MockOPAEvaluator — nested controls detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mock_evaluator_detects_controls_in_active_controls_field() -> None:
    """MockOPAEvaluator detects controls from 'active_controls' field."""
    registry = PolicyRegistry()
    evaluator = MockOPAEvaluator(registry)

    result = await evaluator.evaluate_policy(
        regulation="iso_42001",
        article_ref="4.1",
        policy_content="",
        input_data={
            "implemented_controls": [],
            "active_controls": ["CONTEXT_ANALYSIS", "STAKEHOLDER_MAPPING"],
        },
    )
    assert result["allow"] is True
    assert result["missing_controls"] == []
