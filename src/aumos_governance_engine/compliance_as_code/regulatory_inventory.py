"""Regulatory inventory — catalog of all supported regulations and their requirements.

Provides the authoritative mapping of regulations to:
- Articles and requirements
- Risk tiers and applicability conditions
- Control mappings (regulation article -> technical control ID)
- Evaluation criteria

This module is the single source of truth for regulation metadata within
the compliance-as-code engine. It is consumed by the engine, policy_registry,
and evidence_mapper.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RegulationArticle:
    """A single article or requirement within a regulation.

    Attributes:
        article_ref: Article/section reference (e.g., "Art. 9", "164.312(a)(1)").
        title: Short title for the article.
        requirement_text: Full text of the requirement.
        control_ids: Technical control identifiers that satisfy this requirement.
        automated: Whether automated assessment can fully satisfy this control.
        risk_tiers: Risk tiers this article applies to (empty = applies to all).
        weight: Relative weight for compliance scoring (0.0-1.0).
    """

    article_ref: str
    title: str
    requirement_text: str
    control_ids: list[str]
    automated: bool
    risk_tiers: list[str] = field(default_factory=list)
    weight: float = 1.0


@dataclass(frozen=True)
class RegulationDefinition:
    """Complete definition of a supported regulation.

    Attributes:
        code: Short regulation code used in API (e.g., "eu_ai_act").
        name: Short human-readable name (e.g., "EU AI Act").
        full_name: Full official name.
        issuing_body: Organization that issued the regulation.
        scope: Scope description.
        ai_specific: Whether this is an AI-specific regulation.
        effective_date: When the regulation became/becomes effective.
        policy_file_prefix: Path prefix for Rego policy files.
        articles: List of articles/requirements within this regulation.
    """

    code: str
    name: str
    full_name: str
    issuing_body: str
    scope: str
    ai_specific: bool
    effective_date: str
    policy_file_prefix: str
    articles: list[RegulationArticle]


# ---------------------------------------------------------------------------
# EU AI Act
# ---------------------------------------------------------------------------

_EU_AI_ACT_ARTICLES: list[RegulationArticle] = [
    RegulationArticle(
        article_ref="Art. 6",
        title="Classification rules for high-risk AI systems",
        requirement_text=(
            "AI systems referred to in Annex III are classified as high-risk AI systems "
            "and shall comply with the requirements set out in Chapter III, Section 2."
        ),
        control_ids=["AI_RISK_CLASSIFICATION", "HIGH_RISK_DETERMINATION"],
        automated=True,
        risk_tiers=["high"],
        weight=1.0,
    ),
    RegulationArticle(
        article_ref="Art. 9",
        title="Risk management system",
        requirement_text=(
            "A risk management system shall be established, implemented, documented and "
            "maintained throughout the entire lifecycle of a high-risk AI system."
        ),
        control_ids=["AI_RISK_MGMT", "RISK_LIFECYCLE_MGMT", "RISK_DOCUMENTATION"],
        automated=True,
        risk_tiers=["high"],
        weight=1.0,
    ),
    RegulationArticle(
        article_ref="Art. 10",
        title="Data and data governance",
        requirement_text=(
            "High-risk AI systems shall be developed using training, validation and testing "
            "data sets that meet quality criteria including relevance, representativeness, "
            "freedom from errors and completeness."
        ),
        control_ids=["DATA_QUALITY_ASSURANCE", "DATASET_GOVERNANCE", "BIAS_DETECTION"],
        automated=True,
        risk_tiers=["high"],
        weight=0.9,
    ),
    RegulationArticle(
        article_ref="Art. 11",
        title="Technical documentation",
        requirement_text=(
            "Providers of high-risk AI systems shall draw up technical documentation "
            "before placing on the market or putting into service."
        ),
        control_ids=["TECHNICAL_DOCUMENTATION", "MODEL_CARD", "SYSTEM_CARD"],
        automated=False,
        risk_tiers=["high"],
        weight=0.9,
    ),
    RegulationArticle(
        article_ref="Art. 12",
        title="Record-keeping",
        requirement_text=(
            "High-risk AI systems shall be designed and developed with capabilities "
            "enabling automatic recording of events (logs) over the lifetime."
        ),
        control_ids=["AUDIT_LOGGING", "LOG_RETENTION", "EVENT_RECORDING"],
        automated=True,
        risk_tiers=["high"],
        weight=0.85,
    ),
    RegulationArticle(
        article_ref="Art. 13",
        title="Transparency and provision of information",
        requirement_text=(
            "High-risk AI systems shall be designed and developed in such a way to ensure "
            "that their operation is sufficiently transparent to enable deployers to "
            "interpret the system's output and use it appropriately."
        ),
        control_ids=["EXPLAINABILITY", "MODEL_CARD", "TRANSPARENCY_REPORT"],
        automated=False,
        risk_tiers=["high"],
        weight=0.9,
    ),
    RegulationArticle(
        article_ref="Art. 14",
        title="Human oversight",
        requirement_text=(
            "High-risk AI systems shall be designed and developed so that they can be "
            "effectively overseen by natural persons during the period in which they are "
            "in use."
        ),
        control_ids=["HUMAN_OVERSIGHT", "OVERRIDE_CAPABILITY", "MONITORING_DASHBOARD"],
        automated=True,
        risk_tiers=["high"],
        weight=0.95,
    ),
    RegulationArticle(
        article_ref="Art. 15",
        title="Accuracy, robustness and cybersecurity",
        requirement_text=(
            "High-risk AI systems shall be designed and developed to achieve an "
            "appropriate level of accuracy, robustness, and cybersecurity."
        ),
        control_ids=["MODEL_ACCURACY_BENCHMARK", "ROBUSTNESS_TESTING", "SECURITY_TESTING"],
        automated=True,
        risk_tiers=["high"],
        weight=0.9,
    ),
    RegulationArticle(
        article_ref="Art. 17",
        title="Quality management system",
        requirement_text=(
            "Providers of high-risk AI systems shall put a quality management system in place "
            "to ensure compliance with this Regulation."
        ),
        control_ids=["MLOPS_LIFECYCLE", "MODEL_VERSIONING", "DATA_GOVERNANCE", "QUALITY_MGMT"],
        automated=True,
        risk_tiers=["high"],
        weight=0.85,
    ),
    RegulationArticle(
        article_ref="Art. 43",
        title="Conformity assessment",
        requirement_text=(
            "Providers of high-risk AI systems shall carry out a conformity assessment "
            "procedure prior to placing on the market or putting into service."
        ),
        control_ids=["CONFORMITY_ASSESSMENT", "THIRD_PARTY_AUDIT", "CE_MARKING"],
        automated=False,
        risk_tiers=["high"],
        weight=1.0,
    ),
]

# ---------------------------------------------------------------------------
# NIST AI RMF
# ---------------------------------------------------------------------------

_NIST_AI_RMF_ARTICLES: list[RegulationArticle] = [
    RegulationArticle(
        article_ref="GOVERN-1",
        title="Policies, processes, procedures, and practices",
        requirement_text=(
            "Policies, processes, procedures, and practices across the organization "
            "related to the mapping, measuring, and managing of AI risks are in place, "
            "transparent, and implemented effectively."
        ),
        control_ids=["AI_GOVERNANCE_POLICY", "RISK_MANAGEMENT_PROCESS"],
        automated=False,
        weight=1.0,
    ),
    RegulationArticle(
        article_ref="GOVERN-2",
        title="Accountability structures",
        requirement_text=(
            "Accountability structures are in place so that appropriate teams and individuals "
            "are empowered, responsible, and trained for mapping, measuring, and managing AI risks."
        ),
        control_ids=["RACI_MATRIX", "RESPONSIBLE_AI_TEAM"],
        automated=False,
        weight=0.9,
    ),
    RegulationArticle(
        article_ref="MAP-1",
        title="Context is established",
        requirement_text=(
            "Context is established for the AI risk assessment. Organizational risk "
            "tolerances are determined and risks related to trustworthy AI are identified."
        ),
        control_ids=["AI_RISK_ASSESSMENT", "CONTEXT_ESTABLISHMENT"],
        automated=True,
        weight=0.9,
    ),
    RegulationArticle(
        article_ref="MAP-2",
        title="Scientific and established methods",
        requirement_text=(
            "Scientific and established or best practices are used in AI risk identification "
            "and categorization."
        ),
        control_ids=["RISK_METHODOLOGY", "BEST_PRACTICES_DOCUMENTATION"],
        automated=False,
        weight=0.8,
    ),
    RegulationArticle(
        article_ref="MEASURE-1",
        title="AI risks are assessed",
        requirement_text=(
            "AI risk measurement approaches are identified and prioritized, with measurements "
            "taking place on a regular cadence."
        ),
        control_ids=["MODEL_MONITORING", "DRIFT_DETECTION", "BIAS_DETECTION"],
        automated=True,
        weight=0.9,
    ),
    RegulationArticle(
        article_ref="MEASURE-2",
        title="AI risks are managed",
        requirement_text=(
            "AI risks and related impacts are evaluated for all stages of the AI lifecycle."
        ),
        control_ids=["LIFECYCLE_RISK_MGMT", "IMPACT_ASSESSMENT"],
        automated=True,
        weight=0.85,
    ),
    RegulationArticle(
        article_ref="MANAGE-1",
        title="AI risks are prioritized",
        requirement_text=(
            "AI risks based on assessments are prioritized, responded to, and managed."
        ),
        control_ids=["RISK_PRIORITIZATION", "INCIDENT_RESPONSE"],
        automated=False,
        weight=0.85,
    ),
    RegulationArticle(
        article_ref="MANAGE-2",
        title="Strategies for treatment of risks",
        requirement_text=(
            "Strategies to address identified risks are developed, prioritized, and planned."
        ),
        control_ids=["RISK_TREATMENT_PLAN", "MITIGATION_STRATEGIES"],
        automated=False,
        weight=0.8,
    ),
]

# ---------------------------------------------------------------------------
# ISO 42001
# ---------------------------------------------------------------------------

_ISO_42001_ARTICLES: list[RegulationArticle] = [
    RegulationArticle(
        article_ref="4.1",
        title="Understanding the organization and its context",
        requirement_text=(
            "The organization shall determine external and internal issues relevant to "
            "its purpose and that affect its ability to achieve the intended outcomes of "
            "its AI management system."
        ),
        control_ids=["CONTEXT_ANALYSIS", "STAKEHOLDER_MAPPING"],
        automated=False,
        weight=0.8,
    ),
    RegulationArticle(
        article_ref="5.1",
        title="Leadership and commitment",
        requirement_text=(
            "Top management shall demonstrate leadership and commitment with respect to "
            "the AI management system."
        ),
        control_ids=["AI_GOVERNANCE_COMMITTEE", "EXECUTIVE_SPONSORSHIP"],
        automated=False,
        weight=0.9,
    ),
    RegulationArticle(
        article_ref="6.1",
        title="Actions to address risks and opportunities",
        requirement_text=(
            "When planning for the AI management system, the organization shall consider "
            "actions to address risks and opportunities."
        ),
        control_ids=["AI_RISK_ASSESSMENT", "AI_IMPACT_ANALYSIS", "OPPORTUNITY_IDENTIFICATION"],
        automated=True,
        weight=1.0,
    ),
    RegulationArticle(
        article_ref="7.2",
        title="Competence",
        requirement_text=(
            "The organization shall determine the necessary competence of persons doing "
            "work under its control that affects AI system performance."
        ),
        control_ids=["AI_TRAINING_PROGRAM", "COMPETENCE_ASSESSMENT"],
        automated=False,
        weight=0.75,
    ),
    RegulationArticle(
        article_ref="8.4",
        title="System impact assessment",
        requirement_text=(
            "The organization shall conduct a system impact assessment for AI systems "
            "that have or may have significant impact."
        ),
        control_ids=["AI_IMPACT_ASSESSMENT", "EXPLAINABILITY_REPORT", "STAKEHOLDER_IMPACT"],
        automated=False,
        weight=0.95,
    ),
    RegulationArticle(
        article_ref="9.1",
        title="Monitoring, measurement, analysis and evaluation",
        requirement_text=(
            "The organization shall determine what needs to be monitored and measured, "
            "including AI system performance and compliance."
        ),
        control_ids=["MODEL_MONITORING", "DRIFT_DETECTION", "BIAS_DETECTION", "PERFORMANCE_KPIs"],
        automated=True,
        weight=0.9,
    ),
    RegulationArticle(
        article_ref="10.1",
        title="Continual improvement",
        requirement_text=(
            "The organization shall continually improve the suitability, adequacy, and "
            "effectiveness of the AI management system."
        ),
        control_ids=["IMPROVEMENT_PROCESS", "LESSONS_LEARNED"],
        automated=False,
        weight=0.75,
    ),
]

# ---------------------------------------------------------------------------
# HIPAA
# ---------------------------------------------------------------------------

_HIPAA_ARTICLES: list[RegulationArticle] = [
    RegulationArticle(
        article_ref="164.308(a)(1)",
        title="Security Management Process",
        requirement_text=(
            "Implement policies and procedures to prevent, detect, contain, and correct "
            "security violations."
        ),
        control_ids=["SECURITY_POLICY", "INCIDENT_DETECTION", "VULNERABILITY_MGMT"],
        automated=True,
        weight=1.0,
    ),
    RegulationArticle(
        article_ref="164.308(a)(3)",
        title="Workforce Security",
        requirement_text=(
            "Implement policies and procedures to ensure that all members of its workforce "
            "have appropriate access to electronic protected health information."
        ),
        control_ids=["ACCESS_CONTROL", "RBAC", "WORKFORCE_CLEARANCE"],
        automated=True,
        weight=0.95,
    ),
    RegulationArticle(
        article_ref="164.310(a)(1)",
        title="Facility Access Controls",
        requirement_text=(
            "Implement policies and procedures to limit physical access to its electronic "
            "information systems."
        ),
        control_ids=["PHYSICAL_ACCESS_CONTROL", "FACILITY_SECURITY"],
        automated=False,
        weight=0.8,
    ),
    RegulationArticle(
        article_ref="164.312(a)(1)",
        title="Access Control",
        requirement_text=(
            "Implement technical policies and procedures for electronic information systems "
            "that maintain electronic protected health information to allow access only to "
            "those persons or software programs that have been granted access rights."
        ),
        control_ids=["UNIQUE_USER_ID", "ACCESS_CONTROL", "AUTH_MFA"],
        automated=True,
        weight=1.0,
    ),
    RegulationArticle(
        article_ref="164.312(b)",
        title="Audit Controls",
        requirement_text=(
            "Implement hardware, software, and/or procedural mechanisms that record and "
            "examine activity in information systems that contain or use electronic "
            "protected health information."
        ),
        control_ids=["AUDIT_LOGGING", "LOG_RETENTION", "ACTIVITY_MONITORING"],
        automated=True,
        weight=0.95,
    ),
    RegulationArticle(
        article_ref="164.312(c)(1)",
        title="Integrity",
        requirement_text=(
            "Implement policies and procedures to protect electronic protected health "
            "information from improper alteration or destruction."
        ),
        control_ids=["DATA_INTEGRITY", "TAMPER_DETECTION", "CHECKSUM_VALIDATION"],
        automated=True,
        weight=0.9,
    ),
    RegulationArticle(
        article_ref="164.312(e)(1)",
        title="Transmission Security",
        requirement_text=(
            "Implement technical security measures to guard against unauthorized access "
            "to electronic protected health information that is being transmitted over "
            "an electronic communications network."
        ),
        control_ids=["TLS_ENCRYPTION", "NETWORK_SECURITY", "VPN_REQUIRED"],
        automated=True,
        weight=0.9,
    ),
    RegulationArticle(
        article_ref="164.514(b)",
        title="Minimum Necessary",
        requirement_text=(
            "When using or disclosing protected health information or requesting protected "
            "health information, a covered entity or business associate must make reasonable "
            "efforts to limit protected health information to the minimum necessary."
        ),
        control_ids=["MINIMUM_NECESSARY", "DATA_MINIMIZATION", "PHI_ACCESS_CONTROLS"],
        automated=True,
        weight=0.9,
    ),
    RegulationArticle(
        article_ref="164.508",
        title="Authorization",
        requirement_text=(
            "A covered entity may not use or disclose protected health information without "
            "a valid authorization, except as otherwise provided."
        ),
        control_ids=["PATIENT_AUTHORIZATION", "CONSENT_MANAGEMENT", "DATA_USE_AGREEMENT"],
        automated=False,
        weight=1.0,
    ),
]

# ---------------------------------------------------------------------------
# SOX (AI in Financial Controls)
# ---------------------------------------------------------------------------

_SOX_ARTICLES: list[RegulationArticle] = [
    RegulationArticle(
        article_ref="Sec. 302",
        title="Corporate Responsibility for Financial Reports",
        requirement_text=(
            "Principal executive and financial officers must certify the accuracy of "
            "financial reports. AI systems influencing financial reporting must be "
            "subject to appropriate controls."
        ),
        control_ids=["AI_FINANCIAL_CONTROLS", "EXECUTIVE_CERTIFICATION", "CONTROL_ASSESSMENT"],
        automated=False,
        weight=1.0,
    ),
    RegulationArticle(
        article_ref="Sec. 404",
        title="Management Assessment of Internal Controls",
        requirement_text=(
            "Management must assess and report on the effectiveness of internal controls "
            "over financial reporting. AI systems used in financial controls must be "
            "documented and tested."
        ),
        control_ids=["INTERNAL_CONTROLS_ASSESSMENT", "AI_AUDIT_TRAIL", "CONTROL_TESTING"],
        automated=True,
        weight=1.0,
    ),
    RegulationArticle(
        article_ref="Sec. 802",
        title="Audit Trail Requirements",
        requirement_text=(
            "Records must be maintained that document the basis for, and conclusions of, "
            "significant accounting decisions made by or with AI assistance."
        ),
        control_ids=["AUDIT_TRAIL", "DECISION_LOGGING", "RECORD_RETENTION"],
        automated=True,
        weight=0.95,
    ),
]

# ---------------------------------------------------------------------------
# DORA
# ---------------------------------------------------------------------------

_DORA_ARTICLES: list[RegulationArticle] = [
    RegulationArticle(
        article_ref="Art. 17",
        title="ICT-related incident management process",
        requirement_text=(
            "Financial entities shall define, establish and implement an ICT-related "
            "incident management process to detect, manage and notify ICT-related incidents."
        ),
        control_ids=["INCIDENT_MANAGEMENT", "INCIDENT_CLASSIFICATION", "NOTIFICATION_PROCEDURES"],
        automated=True,
        weight=1.0,
    ),
    RegulationArticle(
        article_ref="Art. 18",
        title="Classification of ICT-related incidents",
        requirement_text=(
            "Financial entities shall classify ICT-related incidents and determine their "
            "impact on the basis of the criteria set out in Article 18(1)."
        ),
        control_ids=["INCIDENT_CLASSIFICATION", "SEVERITY_SCORING", "IMPACT_ANALYSIS"],
        automated=True,
        weight=0.9,
    ),
    RegulationArticle(
        article_ref="Art. 28",
        title="ICT third-party risk management",
        requirement_text=(
            "Financial entities shall manage ICT third-party risk as an integral component "
            "of ICT risk within their ICT risk management framework."
        ),
        control_ids=["THIRD_PARTY_RISK", "VENDOR_ASSESSMENT", "SUPPLY_CHAIN_SECURITY"],
        automated=False,
        weight=0.95,
    ),
    RegulationArticle(
        article_ref="Art. 29",
        title="Preliminary assessment of ICT concentration risk",
        requirement_text=(
            "Before entering into a contractual arrangement on the use of ICT services, "
            "financial entities shall identify and assess all relevant risks."
        ),
        control_ids=["CONCENTRATION_RISK", "DEPENDENCY_MAPPING", "RISK_ASSESSMENT"],
        automated=True,
        weight=0.85,
    ),
]

# ---------------------------------------------------------------------------
# Regulation catalog
# ---------------------------------------------------------------------------

_REGULATION_CATALOG: dict[str, RegulationDefinition] = {
    "eu_ai_act": RegulationDefinition(
        code="eu_ai_act",
        name="EU AI Act",
        full_name="Regulation on Artificial Intelligence (EU) 2024/1689",
        issuing_body="European Parliament and Council",
        scope="AI system risk classification, obligations by risk tier",
        ai_specific=True,
        effective_date="2024-08-01",
        policy_file_prefix="policies/eu_ai_act",
        articles=_EU_AI_ACT_ARTICLES,
    ),
    "nist_ai_rmf": RegulationDefinition(
        code="nist_ai_rmf",
        name="NIST AI RMF",
        full_name="NIST Artificial Intelligence Risk Management Framework",
        issuing_body="NIST (US)",
        scope="AI risk management across govern, map, measure, manage functions",
        ai_specific=True,
        effective_date="2023-01-26",
        policy_file_prefix="policies/nist_ai_rmf",
        articles=_NIST_AI_RMF_ARTICLES,
    ),
    "iso_42001": RegulationDefinition(
        code="iso_42001",
        name="ISO 42001:2023",
        full_name="Artificial Intelligence — Management System",
        issuing_body="ISO/IEC",
        scope="AI management systems — responsible AI governance",
        ai_specific=True,
        effective_date="2023-12-18",
        policy_file_prefix="policies/iso_42001",
        articles=_ISO_42001_ARTICLES,
    ),
    "hipaa": RegulationDefinition(
        code="hipaa",
        name="HIPAA",
        full_name="Health Insurance Portability and Accountability Act",
        issuing_body="HHS (US)",
        scope="Healthcare data protection and patient privacy",
        ai_specific=False,
        effective_date="1996-08-21",
        policy_file_prefix="policies/hipaa",
        articles=_HIPAA_ARTICLES,
    ),
    "sox": RegulationDefinition(
        code="sox",
        name="SOX",
        full_name="Sarbanes-Oxley Act — AI in Financial Controls",
        issuing_body="US Congress",
        scope="AI systems used in financial controls and reporting",
        ai_specific=False,
        effective_date="2002-07-30",
        policy_file_prefix="policies/sox",
        articles=_SOX_ARTICLES,
    ),
    "dora": RegulationDefinition(
        code="dora",
        name="DORA",
        full_name="Digital Operational Resilience Act (EU) 2022/2554",
        issuing_body="European Parliament and Council",
        scope="ICT risk management, incident reporting, third-party risk for financial entities",
        ai_specific=False,
        effective_date="2025-01-17",
        policy_file_prefix="policies/dora",
        articles=_DORA_ARTICLES,
    ),
}


def get_regulation(code: str) -> RegulationDefinition | None:
    """Retrieve a regulation definition by its code.

    Args:
        code: The regulation code (e.g., "eu_ai_act", "hipaa").

    Returns:
        The RegulationDefinition if found, None otherwise.
    """
    return _REGULATION_CATALOG.get(code)


def list_regulations() -> list[RegulationDefinition]:
    """Return all supported regulation definitions.

    Returns:
        List of all RegulationDefinition objects in the catalog.
    """
    return list(_REGULATION_CATALOG.values())


def get_supported_codes() -> set[str]:
    """Return the set of all supported regulation codes.

    Returns:
        Set of regulation code strings.
    """
    return set(_REGULATION_CATALOG.keys())


def get_articles_for_regulation(code: str) -> list[RegulationArticle]:
    """Return all articles for a regulation.

    Args:
        code: The regulation code.

    Returns:
        List of RegulationArticle objects, or empty list if regulation not found.
    """
    regulation = get_regulation(code)
    if regulation is None:
        return []
    return regulation.articles


def build_regulation_metadata(code: str) -> dict[str, Any]:
    """Build a metadata dictionary for API responses.

    Args:
        code: The regulation code.

    Returns:
        Dictionary with regulation metadata fields.

    Raises:
        KeyError: If the regulation code is not found.
    """
    regulation = _REGULATION_CATALOG[code]
    return {
        "code": regulation.code,
        "name": regulation.name,
        "full_name": regulation.full_name,
        "issuing_body": regulation.issuing_body,
        "scope": regulation.scope,
        "ai_specific": regulation.ai_specific,
        "effective_date": regulation.effective_date,
        "article_count": len(regulation.articles),
    }
