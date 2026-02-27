"""Evidence mapping rules for the Autonomous Compliance Evidence Harvester.

Each EvidenceMappingRule describes how a specific event on a specific Kafka
topic maps to compliance evidence for a particular regulation and control.
When the EvidenceHarvesterAgent receives an event matching a rule's
(source_event_topic, source_event_type) pair, it creates a HarvestedEvidence
record for the matching regulation/control.

Built-in rules cover SOC 2 Type II, EU AI Act, and HIPAA with 20+ mappings
across authentication, data governance, model management, and audit controls.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class EvidenceMappingRule:
    """Immutable rule mapping an event to compliance evidence.

    Attributes:
        rule_id: Unique identifier for this rule (e.g., "soc2-cc6.1-auth").
        source_event_topic: The Kafka topic to match (e.g., "aumos.security.auth-events").
        source_event_type: The event_type field value in the event payload to match.
        regulation: Regulation code (e.g., "SOC2", "EU_AI_ACT", "HIPAA").
        control_id: The specific control identifier (e.g., "CC6.1", "Art.10", "164.312(a)(1)").
        control_description: Human-readable description of the control.
        evidence_type: Classification of the evidence (e.g., "log", "configuration", "attestation").
        evidence_description_template: Python str.format_map template. Event fields
            are available for interpolation (e.g., "{user_id} authenticated successfully").
        retention_days: How many days the evidence must be retained.
        is_active: Whether the rule is currently active. Inactive rules are skipped.
    """

    rule_id: str
    source_event_topic: str
    source_event_type: str
    regulation: str
    control_id: str
    control_description: str
    evidence_type: str
    evidence_description_template: str
    retention_days: int
    is_active: bool = True


# ---------------------------------------------------------------------------
# Built-in mapping rules — 20+ rules covering SOC 2, EU AI Act, HIPAA
# ---------------------------------------------------------------------------

BUILTIN_RULES: list[EvidenceMappingRule] = [
    # ------------------------------------------------------------------
    # SOC 2 Type II
    # ------------------------------------------------------------------

    # CC6.1 — Logical and Physical Access Controls
    EvidenceMappingRule(
        rule_id="soc2-cc6.1-login-success",
        source_event_topic="aumos.security.auth-events",
        source_event_type="login_success",
        regulation="SOC2",
        control_id="CC6.1",
        control_description="Logical and physical access controls to meet the entity's objectives",
        evidence_type="log",
        evidence_description_template=(
            "Successful authentication by user {user_id} from {source_ip} at {timestamp}"
        ),
        retention_days=365,
    ),
    EvidenceMappingRule(
        rule_id="soc2-cc6.1-login-failure",
        source_event_topic="aumos.security.auth-events",
        source_event_type="login_failure",
        regulation="SOC2",
        control_id="CC6.1",
        control_description="Logical and physical access controls to meet the entity's objectives",
        evidence_type="log",
        evidence_description_template=(
            "Failed authentication attempt for user {user_id} from {source_ip} at {timestamp}"
        ),
        retention_days=365,
    ),
    EvidenceMappingRule(
        rule_id="soc2-cc6.1-mfa-enrolled",
        source_event_topic="aumos.security.auth-events",
        source_event_type="mfa_enrolled",
        regulation="SOC2",
        control_id="CC6.1",
        control_description="Logical and physical access controls to meet the entity's objectives",
        evidence_type="configuration",
        evidence_description_template=(
            "User {user_id} enrolled multi-factor authentication method {mfa_method}"
        ),
        retention_days=365,
    ),
    EvidenceMappingRule(
        rule_id="soc2-cc6.1-permission-granted",
        source_event_topic="aumos.security.access-events",
        source_event_type="permission_granted",
        regulation="SOC2",
        control_id="CC6.1",
        control_description="Logical and physical access controls to meet the entity's objectives",
        evidence_type="configuration",
        evidence_description_template=(
            "Permission {permission} granted to {grantee_id} by {actor_id} on resource {resource_id}"
        ),
        retention_days=365,
    ),
    EvidenceMappingRule(
        rule_id="soc2-cc6.1-permission-revoked",
        source_event_topic="aumos.security.access-events",
        source_event_type="permission_revoked",
        regulation="SOC2",
        control_id="CC6.1",
        control_description="Logical and physical access controls to meet the entity's objectives",
        evidence_type="configuration",
        evidence_description_template=(
            "Permission {permission} revoked from {grantee_id} by {actor_id} on resource {resource_id}"
        ),
        retention_days=365,
    ),

    # CC7.2 — System Monitoring and Anomaly Detection
    EvidenceMappingRule(
        rule_id="soc2-cc7.2-anomaly-detected",
        source_event_topic="aumos.security.threat-events",
        source_event_type="anomaly_detected",
        regulation="SOC2",
        control_id="CC7.2",
        control_description="Monitor system components for anomalies indicating malicious acts",
        evidence_type="log",
        evidence_description_template=(
            "Anomaly detected: {anomaly_type} with severity {severity} on {component}"
        ),
        retention_days=365,
    ),
    EvidenceMappingRule(
        rule_id="soc2-cc7.2-alert-triggered",
        source_event_topic="aumos.observability.alerts",
        source_event_type="security_alert_triggered",
        regulation="SOC2",
        control_id="CC7.2",
        control_description="Monitor system components for anomalies indicating malicious acts",
        evidence_type="log",
        evidence_description_template=(
            "Security alert triggered: {alert_name} on {service} — severity {severity}"
        ),
        retention_days=365,
    ),

    # CC9.2 — Vendor Risk Management
    EvidenceMappingRule(
        rule_id="soc2-cc9.2-vendor-assessed",
        source_event_topic="aumos.governance.vendor-events",
        source_event_type="vendor_risk_assessed",
        regulation="SOC2",
        control_id="CC9.2",
        control_description="Vendor risk management and third-party assessments",
        evidence_type="attestation",
        evidence_description_template=(
            "Vendor {vendor_name} risk assessment completed with score {risk_score}"
        ),
        retention_days=730,
    ),

    # CC4.1 — Audit of Controls (COSO)
    EvidenceMappingRule(
        rule_id="soc2-cc4.1-policy-evaluated",
        source_event_topic="aumos.governance.policy-events",
        source_event_type="policy_evaluated",
        regulation="SOC2",
        control_id="CC4.1",
        control_description="Monitoring of controls including evaluations of design and operating effectiveness",
        evidence_type="log",
        evidence_description_template=(
            "Governance policy {policy_id} evaluated: allowed={allowed}, violations={violations_count}"
        ),
        retention_days=365,
    ),

    # ------------------------------------------------------------------
    # EU AI Act
    # ------------------------------------------------------------------

    # Article 9 — Risk Management System
    EvidenceMappingRule(
        rule_id="eu-ai-act-art9-risk-assessment",
        source_event_topic="aumos.governance.risk-events",
        source_event_type="ai_risk_assessment_completed",
        regulation="EU_AI_ACT",
        control_id="Art.9",
        control_description="Risk management system for high-risk AI systems",
        evidence_type="attestation",
        evidence_description_template=(
            "AI risk assessment completed for model {model_id}: risk_tier={risk_tier}"
        ),
        retention_days=3650,
    ),
    EvidenceMappingRule(
        rule_id="eu-ai-act-art9-risk-mitigated",
        source_event_topic="aumos.governance.risk-events",
        source_event_type="risk_mitigation_applied",
        regulation="EU_AI_ACT",
        control_id="Art.9",
        control_description="Risk management system for high-risk AI systems",
        evidence_type="configuration",
        evidence_description_template=(
            "Risk mitigation {mitigation_type} applied to model {model_id} by {actor_id}"
        ),
        retention_days=3650,
    ),

    # Article 10 — Data Governance
    EvidenceMappingRule(
        rule_id="eu-ai-act-art10-dataset-registered",
        source_event_topic="aumos.data.governance-events",
        source_event_type="dataset_registered",
        regulation="EU_AI_ACT",
        control_id="Art.10",
        control_description="Data and data governance requirements for training, validation, testing datasets",
        evidence_type="configuration",
        evidence_description_template=(
            "Dataset {dataset_id} registered: type={dataset_type}, size={record_count} records"
        ),
        retention_days=3650,
    ),
    EvidenceMappingRule(
        rule_id="eu-ai-act-art10-data-quality-validated",
        source_event_topic="aumos.data.governance-events",
        source_event_type="data_quality_validated",
        regulation="EU_AI_ACT",
        control_id="Art.10",
        control_description="Data and data governance requirements for training, validation, testing datasets",
        evidence_type="log",
        evidence_description_template=(
            "Data quality validation for dataset {dataset_id}: score={quality_score}, issues={issue_count}"
        ),
        retention_days=3650,
    ),

    # Article 13 — Transparency and Information Provision
    EvidenceMappingRule(
        rule_id="eu-ai-act-art13-model-card-published",
        source_event_topic="aumos.governance.model-events",
        source_event_type="model_card_published",
        regulation="EU_AI_ACT",
        control_id="Art.13",
        control_description="Transparency and provision of information to deployers",
        evidence_type="artifact",
        evidence_description_template=(
            "Model card published for model {model_id} version {model_version}"
        ),
        retention_days=3650,
    ),
    EvidenceMappingRule(
        rule_id="eu-ai-act-art13-explainability-report",
        source_event_topic="aumos.governance.explainability-events",
        source_event_type="explainability_report_generated",
        regulation="EU_AI_ACT",
        control_id="Art.13",
        control_description="Transparency and provision of information to deployers",
        evidence_type="artifact",
        evidence_description_template=(
            "Explainability report generated for model {model_id}: method={explanation_method}"
        ),
        retention_days=3650,
    ),

    # Article 17 — Quality Management System
    EvidenceMappingRule(
        rule_id="eu-ai-act-art17-model-promoted",
        source_event_topic="aumos.mlops.lifecycle-events",
        source_event_type="model_promoted",
        regulation="EU_AI_ACT",
        control_id="Art.17",
        control_description="Quality management system for high-risk AI providers",
        evidence_type="log",
        evidence_description_template=(
            "Model {model_id} promoted from {from_stage} to {to_stage} by {actor_id}"
        ),
        retention_days=3650,
    ),
    EvidenceMappingRule(
        rule_id="eu-ai-act-art17-bias-tested",
        source_event_topic="aumos.governance.fairness-events",
        source_event_type="bias_test_completed",
        regulation="EU_AI_ACT",
        control_id="Art.17",
        control_description="Quality management system for high-risk AI providers",
        evidence_type="log",
        evidence_description_template=(
            "Bias test completed for model {model_id}: {bias_metric}={bias_score}"
        ),
        retention_days=3650,
    ),

    # ------------------------------------------------------------------
    # HIPAA
    # ------------------------------------------------------------------

    # 164.312(a)(1) — Access Control
    EvidenceMappingRule(
        rule_id="hipaa-164.312a1-user-provisioned",
        source_event_topic="aumos.security.access-events",
        source_event_type="user_provisioned",
        regulation="HIPAA",
        control_id="164.312(a)(1)",
        control_description="Access Control — assign a unique identifier to each user",
        evidence_type="configuration",
        evidence_description_template=(
            "User {user_id} provisioned with role {role} for tenant {tenant_id}"
        ),
        retention_days=2190,
    ),
    EvidenceMappingRule(
        rule_id="hipaa-164.312a1-user-deprovisioned",
        source_event_topic="aumos.security.access-events",
        source_event_type="user_deprovisioned",
        regulation="HIPAA",
        control_id="164.312(a)(1)",
        control_description="Access Control — assign a unique identifier to each user",
        evidence_type="configuration",
        evidence_description_template=(
            "User {user_id} deprovisioned from tenant {tenant_id} by {actor_id}"
        ),
        retention_days=2190,
    ),

    # 164.312(b) — Audit Controls
    EvidenceMappingRule(
        rule_id="hipaa-164.312b-audit-log-exported",
        source_event_topic="aumos.governance.audit-events",
        source_event_type="audit_log_exported",
        regulation="HIPAA",
        control_id="164.312(b)",
        control_description="Audit Controls — hardware, software, and procedural mechanisms to examine activity",
        evidence_type="artifact",
        evidence_description_template=(
            "Audit log exported for tenant {tenant_id}: period={period_start} to {period_end}, records={record_count}"
        ),
        retention_days=2190,
    ),
    EvidenceMappingRule(
        rule_id="hipaa-164.312b-phi-accessed",
        source_event_topic="aumos.data.access-events",
        source_event_type="phi_data_accessed",
        regulation="HIPAA",
        control_id="164.312(b)",
        control_description="Audit Controls — hardware, software, and procedural mechanisms to examine activity",
        evidence_type="log",
        evidence_description_template=(
            "PHI dataset {dataset_id} accessed by {user_id} for purpose {access_purpose}"
        ),
        retention_days=2190,
    ),

    # 164.312(e)(2)(ii) — Encryption at Rest
    EvidenceMappingRule(
        rule_id="hipaa-164.312e2ii-encryption-verified",
        source_event_topic="aumos.security.compliance-events",
        source_event_type="encryption_at_rest_verified",
        regulation="HIPAA",
        control_id="164.312(e)(2)(ii)",
        control_description="Encryption and decryption of ePHI — mechanism to encrypt and decrypt",
        evidence_type="attestation",
        evidence_description_template=(
            "Encryption at rest verified for datastore {datastore_id}: algorithm={algorithm}"
        ),
        retention_days=2190,
    ),
]
