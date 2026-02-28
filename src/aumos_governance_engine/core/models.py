"""SQLAlchemy ORM models for the governance engine.

All models use the `gov_` table prefix and extend AumOSModel for automatic
tenant_id, id (UUID), created_at, and updated_at fields.

Models:
- GovernancePolicy    — OPA Rego policies with version tracking
- ComplianceWorkflow  — Per-tenant per-regulation compliance assessment lifecycle
- AuditTrailEntry     — IMMUTABLE audit log (lives on SEPARATE audit DB)
- EvidenceRecord      — Compliance evidence artifacts linking controls to proof
- RegulationMapping   — Mapping of regulation articles to technical control IDs

P1.1 Compliance-as-Code models:
- CompliancePolicyVersion  — Versioned compliance policies with legal review
- ComplianceEvaluation     — Evaluation runs of AI models against regulations
- ComplianceEvidenceItem   — Individual evidence items from an evaluation

Competitive gap models (gaps 194-201):
- PolicyTestCase       — Individual test case for a Rego policy (gap 194)
- PolicyTestRun        — Execution of a set of test cases against a policy (gap 194)
- PolicyVersion        — Explicit versioning with SHA-256 hash and rollback (gap 196)
- PolicyEvaluationLog  — Decision log for analytics queries (gap 197)
- PolicySimulation     — What-if simulation run record (gap 195)
- OPASidecarStatus     — Health and bundle metadata for OPA sidecar (gap 199)
- ExternalEvidenceImport — Imported evidence from Jira/ServiceNow (gap 201)

IMPORTANT: AuditTrailEntry is defined here for ORM mapping purposes but it is
written ONLY via AuditTrailRepository, which connects to the separate audit DB.
Never write to gov_audit_trail_entries via the primary DB session.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from aumos_common.database import AumOSModel


class GovernancePolicy(AumOSModel):
    """OPA Rego governance policy with version tracking.

    Policies are authored in OPA's Rego language and evaluated against
    structured JSON inputs. Each policy is versioned — updating a policy
    creates a new record rather than mutating in place. The `status` field
    tracks the lifecycle of a given policy version.

    When a policy is activated, the Rego content is pushed to OPA as a bundle
    via OPAClient. Deactivating a policy removes it from OPA.

    Attributes:
        tenant_id: Owning tenant UUID (inherited from AumOSModel).
        name: Human-readable policy name.
        policy_type: Evaluation engine type — `opa_rego` or `custom`.
        rego_content: Full OPA Rego policy text (only for opa_rego policies).
        version: Monotonically increasing integer version within the tenant+name scope.
        status: Lifecycle state — draft | active | deprecated | archived.
        regulation_refs: List of regulation codes this policy implements (JSONB array).
        description: Optional human-readable description of what this policy enforces.
    """

    __tablename__ = "gov_governance_policies"

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Human-readable policy name, unique within tenant scope",
    )
    policy_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="opa_rego",
        comment="Evaluation engine: opa_rego | custom",
    )
    rego_content: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Full OPA Rego policy text. Required when policy_type = opa_rego.",
    )
    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        comment="Monotonically increasing version number within tenant+name scope",
    )
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="draft",
        index=True,
        comment="Lifecycle state: draft | active | deprecated | archived",
    )
    regulation_refs: Mapped[list] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=list,
        comment="List of regulation codes this policy implements: [soc2, iso27001, ...]",
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Optional human-readable description of what this policy enforces",
    )


class ComplianceWorkflow(AumOSModel):
    """Per-tenant compliance workflow for a specific regulation.

    Tracks the lifecycle of a compliance assessment — from initiation through
    evidence collection and final attestation. One workflow record per
    (tenant, regulation, assessment_period) combination.

    Attributes:
        tenant_id: Owning tenant UUID (inherited from AumOSModel).
        regulation: Regulation code being assessed.
        name: Human-readable workflow name (e.g., "SOC 2 Type II — FY2026").
        status: Assessment lifecycle state.
        evidence_count: Denormalized count of attached evidence records.
        last_assessment: Timestamp of the most recent assessment action.
        next_due: Timestamp when the next assessment action is due.
        assigned_to: UUID of the user responsible for this workflow.
        notes: Free-text notes for the compliance team.
    """

    __tablename__ = "gov_compliance_workflows"

    regulation: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Regulation code: soc2 | iso27001 | hipaa | iso42001 | eu_ai_act | fedramp",
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Human-readable workflow name, e.g., 'SOC 2 Type II — FY2026'",
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="initiated",
        index=True,
        comment=(
            "Assessment lifecycle: initiated | evidence_collection | under_review | "
            "remediation | attested | archived"
        ),
    )
    evidence_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Denormalized count of attached EvidenceRecord rows",
    )
    last_assessment: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of the most recent assessment action (UTC)",
    )
    next_due: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="When the next assessment action is due (UTC)",
    )
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="UUID of the user responsible for driving this workflow",
    )
    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Free-text notes for the compliance team",
    )


class AuditTrailEntry(AumOSModel):
    """Immutable audit trail entry for governance events.

    IMPORTANT: This model is mapped to the SEPARATE audit database, not the
    primary database. It must only be written via AuditTrailRepository using
    `get_audit_db_session` from adapters/audit_wall.py.

    This table has NO UPDATE or DELETE operations. All entries are permanent.
    If a correction is needed, write a new compensating entry with
    event_type="audit.correction" referencing the original entry ID in details.

    Attributes:
        tenant_id: Owning tenant UUID (inherited from AumOSModel).
        event_type: Dot-notation event type (e.g., governance.policy.created).
        actor_id: UUID of the user or service that performed the action.
        resource_type: Type of the affected resource (e.g., governance_policy).
        resource_id: UUID of the affected resource.
        action: Short action verb (created, updated, activated, evaluated, etc.).
        details: Structured JSONB payload with event-specific data.
        timestamp: Immutable event timestamp (set at insert time).
        source_service: Originating service name (always aumos-governance-engine).
        correlation_id: Request correlation ID for distributed tracing.
    """

    __tablename__ = "gov_audit_trail_entries"

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Dot-notation event type, e.g., governance.policy.created",
    )
    actor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="UUID of the user or service account that performed the action",
    )
    resource_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Type of the affected resource: governance_policy | compliance_workflow | evidence_record",
    )
    resource_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="UUID of the affected resource",
    )
    action: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Short action verb: created | updated | activated | evaluated | submitted | archived",
    )
    details: Mapped[dict] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=dict,
        comment="Structured event-specific payload — differs per event_type",
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Immutable event timestamp (UTC) — set at insert time, never modified",
    )
    source_service: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="aumos-governance-engine",
        comment="Originating service name",
    )
    correlation_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True,
        comment="Request correlation ID for distributed tracing (X-Request-ID header)",
    )


class EvidenceRecord(AumOSModel):
    """Compliance evidence record linking a workflow control to proof artifacts.

    Evidence records are created when compliance evidence is submitted — either
    by automated collection jobs or by compliance team members manually uploading
    artifacts. Each record links to a specific compliance workflow and describes
    what evidence was collected and where it is stored.

    Attributes:
        tenant_id: Owning tenant UUID (inherited from AumOSModel).
        workflow_id: FK to the ComplianceWorkflow this evidence belongs to.
        evidence_type: Type classification of the evidence artifact.
        title: Short descriptive title.
        description: Detailed description of what this evidence demonstrates.
        artifact_uri: Storage URI for the evidence artifact (e.g., s3://bucket/key).
        collected_at: When the evidence was collected/created.
        collector: Whether collection was automated or manual.
        control_ids: List of regulation control IDs this evidence satisfies.
        status: Evidence review status.
    """

    __tablename__ = "gov_evidence_records"

    workflow_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="UUID of the ComplianceWorkflow this evidence is attached to",
    )
    evidence_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment=(
            "Evidence type: audit_log | config_export | test_result | screenshot | "
            "policy_document | access_review | penetration_test | training_record"
        ),
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Short descriptive title for this evidence item",
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
        comment="Detailed description of what this evidence demonstrates",
    )
    artifact_uri: Mapped[str | None] = mapped_column(
        String(2048),
        nullable=True,
        comment="Storage URI for the artifact: s3://bucket/path or https://...",
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="When the evidence was collected or uploaded (UTC)",
    )
    collector: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="manual",
        comment="How evidence was collected: auto | manual",
    )
    control_ids: Mapped[list] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=list,
        comment="List of regulation control IDs this evidence satisfies, e.g., [CC6.1, CC6.2]",
    )
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pending_review",
        comment="Review status: pending_review | accepted | rejected | needs_revision",
    )
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="UUID of the reviewer who accepted or rejected this evidence",
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the evidence was reviewed (UTC)",
    )


class RegulationMapping(AumOSModel):
    """Mapping of regulation articles to technical control IDs.

    Provides the authoritative mapping between a regulation's requirements
    (expressed as article references) and the concrete technical controls
    that satisfy those requirements. Controls are identified using a naming
    pattern compatible with NIST CSF.

    The static baseline mappings for the six supported regulations are
    seeded by migration. Tenants can add custom mappings that extend the
    baseline. The `automated` flag indicates whether automated evidence
    collection can satisfy this control.

    Attributes:
        tenant_id: Owning tenant UUID (inherited from AumOSModel). NULL for platform-wide mappings.
        regulation: Regulation code.
        article_ref: Article or section reference within the regulation.
        requirement_text: Full text of the requirement from the regulation.
        control_ids: List of technical control identifiers.
        automated: Whether this control can be automatically assessed.
        notes: Optional implementation notes for the compliance team.
    """

    __tablename__ = "gov_regulation_mappings"

    regulation: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Regulation code: soc2 | iso27001 | hipaa | iso42001 | eu_ai_act | fedramp",
    )
    article_ref: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Article/section reference within the regulation, e.g., CC6.1, A.8.1, 164.312(a)(1)",
    )
    requirement_text: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Full text of the regulatory requirement",
    )
    control_ids: Mapped[list] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=list,
        comment="List of technical control IDs that satisfy this requirement",
    )
    automated: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether automated evidence collection can fully satisfy this control",
    )
    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Optional implementation notes for the compliance team",
    )


# ---------------------------------------------------------------------------
# P1.1 Compliance-as-Code models
# ---------------------------------------------------------------------------


class CompliancePolicyVersion(AumOSModel):
    """Versioned compliance policy record with legal review lifecycle.

    Tracks each version of a compliance policy (Rego or Python-equivalent)
    against a specific regulation article. Creating a new version does not
    mutate existing records — a new row is inserted.

    Attributes:
        policy_id: Business-level policy identifier (stable across versions).
        regulation: Regulation code (eu_ai_act, hipaa, etc.).
        article: Article reference within the regulation.
        version: Monotonically increasing version within policy_id scope.
        content_hash: SHA-256 hash of the policy_text for tamper-detection.
        policy_text: Full policy source (Rego or Python-equivalent).
        effective_date: When this version became/becomes effective.
        approved_by: UUID of the approver.
        legal_review_status: Legal review lifecycle state.
    """

    __tablename__ = "gov_compliance_policy_versions"

    policy_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Stable business identifier across versions (e.g., eu_ai_act:Art.9)",
    )
    regulation: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Regulation code: eu_ai_act | nist_ai_rmf | iso_42001 | hipaa | sox | dora",
    )
    article: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Article/section reference within the regulation",
    )
    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        comment="Monotonically increasing version within policy_id scope",
    )
    content_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="SHA-256 hex digest of policy_text for tamper-detection",
    )
    policy_text: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Full policy source (Rego or Python-equivalent logic)",
    )
    effective_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When this policy version became/becomes effective (UTC)",
    )
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="UUID of the user or service that approved this policy version",
    )
    legal_review_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pending",
        comment="Legal review state: pending | in_review | approved | rejected",
    )


class ComplianceEvaluation(AumOSModel):
    """A single compliance evaluation run of an AI model against regulations.

    Records the full results of evaluating an AI system against one or more
    regulatory frameworks. The results JSONB field contains per-article
    evaluation details. Evidence items are stored in ComplianceEvidenceItem.

    Attributes:
        model_id: The AI model identifier that was evaluated.
        triggered_by: What triggered the evaluation (api, scheduled, ci_cd).
        regulations_evaluated: List of regulation codes evaluated.
        results: Per-article evaluation results as structured JSONB.
        overall_compliant: Whether all evaluations passed.
        compliant_count: Count of compliant articles.
        non_compliant_count: Count of non-compliant articles.
        partial_count: Count of partially compliant articles.
        not_applicable_count: Count of not-applicable articles.
        evaluated_at: When the evaluation completed.
        evaluation_duration_ms: Total evaluation time in milliseconds.
    """

    __tablename__ = "gov_compliance_evaluations"

    model_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Identifier of the AI model that was evaluated",
    )
    triggered_by: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="api",
        comment="What triggered the evaluation: api | scheduled | ci_cd | manual",
    )
    regulations_evaluated: Mapped[list] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=list,
        comment="List of regulation codes evaluated in this run",
    )
    results: Mapped[dict] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=dict,
        comment="Per-article evaluation results with status, violations, and scores",
    )
    overall_compliant: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Whether all article evaluations passed",
    )
    compliant_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of articles that were fully compliant",
    )
    non_compliant_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of articles that were non-compliant",
    )
    partial_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of articles that were partially compliant",
    )
    not_applicable_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of articles that were not applicable to this model",
    )
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="When this evaluation completed (UTC)",
    )
    evaluation_duration_ms: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Total evaluation duration in milliseconds",
    )


class ComplianceEvidenceItem(AumOSModel):
    """An individual evidence item collected during a compliance evaluation.

    Each evaluation produces multiple evidence items — one per article per
    evidence type. These items form the evidentiary basis for compliance claims
    and are packaged into ZIP evidence packages for auditors.

    Attributes:
        evaluation_id: FK to the parent ComplianceEvaluation.
        regulation: Regulation code this evidence addresses.
        article: Article reference this evidence addresses.
        requirement: Brief summary of the requirement being evidenced.
        evidence_type: Classification of the evidence artifact.
        evidence_ref: Structured reference to the evidence (URI, log ID, etc.).
        collected_at: When the evidence was collected.
        expires_at: When the evidence expires and must be re-collected.
    """

    __tablename__ = "gov_compliance_evidence_items"

    evaluation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="UUID of the parent ComplianceEvaluation",
    )
    regulation: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Regulation code this evidence addresses",
    )
    article: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Article/section reference within the regulation",
    )
    requirement: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Brief summary of the requirement being evidenced",
    )
    evidence_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment=(
            "Evidence type: evaluation_result | control_check | "
            "audit_log_reference | policy_document | automated_scan"
        ),
    )
    evidence_ref: Mapped[dict] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=dict,
        comment="Structured reference to the evidence data (URI, log ID, control list, etc.)",
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="When this evidence was collected (UTC)",
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When this evidence expires and must be re-collected (UTC)",
    )


# ---------------------------------------------------------------------------
# Gap 194 — Rego Policy Testing Framework
# ---------------------------------------------------------------------------


class PolicyTestCase(AumOSModel):
    """A single test case for a Rego governance policy.

    Test cases define expected OPA evaluation outcomes for specific inputs.
    They enable CI/CD-style regression testing of policy changes before
    activation. Each test case is bound to a policy and specifies an
    input payload and the expected allow/deny outcome.

    Attributes:
        policy_id: FK to the GovernancePolicy under test (no DB FK — cross-service safe).
        name: Human-readable test case name.
        description: What this test case validates.
        input_data: The JSON input payload to evaluate the policy against.
        expected_allow: True if the policy should allow the input, False if deny.
        expected_violations: Optional list of expected violation strings.
        tags: Optional list of tag strings for grouping test cases.
    """

    __tablename__ = "gov_policy_test_cases"

    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="UUID of the GovernancePolicy this test case targets",
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Human-readable test case name",
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="What scenario this test case validates",
    )
    input_data: Mapped[dict] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=dict,
        comment="JSON input payload to evaluate against the policy",
    )
    expected_allow: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="True = expect policy to allow; False = expect deny",
    )
    expected_violations: Mapped[list] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=list,
        comment="Optional list of expected violation message substrings",
    )
    tags: Mapped[list] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=list,
        comment="Optional tag strings for grouping and filtering test cases",
    )


class PolicyTestRun(AumOSModel):
    """Execution record for a batch of policy test cases.

    Created each time a test suite is executed. Stores aggregate pass/fail
    counts and per-test-case results. Writing to the Audit Wall is required
    for every test run to maintain traceability of policy quality gates.

    Attributes:
        policy_id: FK to the GovernancePolicy under test.
        test_case_ids: List of test case UUIDs included in this run.
        triggered_by: User or system that triggered the run.
        status: Run lifecycle state — running | passed | failed | error.
        total_cases: Total number of test cases in the run.
        passed_cases: Count of test cases that passed.
        failed_cases: Count of test cases that failed.
        error_cases: Count of test cases that errored.
        results: Per-test-case result details (JSONB array).
        started_at: When the run started.
        completed_at: When the run completed.
        duration_ms: Total run duration in milliseconds.
    """

    __tablename__ = "gov_policy_test_runs"

    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="UUID of the GovernancePolicy that was tested",
    )
    test_case_ids: Mapped[list] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=list,
        comment="List of PolicyTestCase UUIDs included in this run",
    )
    triggered_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="UUID of the user or service that triggered the test run",
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="running",
        index=True,
        comment="Run lifecycle: running | passed | failed | error",
    )
    total_cases: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Total number of test cases in this run",
    )
    passed_cases: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of test cases that produced the expected outcome",
    )
    failed_cases: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of test cases that produced an unexpected outcome",
    )
    error_cases: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of test cases that errored during OPA evaluation",
    )
    results: Mapped[list] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=list,
        comment="Per-test-case result objects: {test_case_id, passed, actual_allow, error}",
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="When the test run started (UTC)",
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the test run completed (UTC)",
    )
    duration_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Total run duration in milliseconds",
    )


# ---------------------------------------------------------------------------
# Gap 196 — Policy Versioning with Rollback
# ---------------------------------------------------------------------------


class PolicyVersion(AumOSModel):
    """Explicit version snapshot of a GovernancePolicy's Rego content.

    Every time a policy is updated or a new version activated, a PolicyVersion
    record is created capturing the full Rego source at that point in time.
    The SHA-256 hash enables tamper-detection. Rollback creates a new
    PolicyVersion by copying a prior version's Rego content.

    Attributes:
        policy_id: FK to the GovernancePolicy (stable across versions).
        version_number: Monotonically increasing version within policy scope.
        rego_content: Full Rego source at this version.
        sha256_hash: SHA-256 hex digest of rego_content.
        change_description: Why this version was created.
        authored_by: UUID of the user who authored this version.
        activated_at: When this version was activated in OPA (None = not yet activated).
        is_current: True only for the most recently activated version.
    """

    __tablename__ = "gov_policy_versions"

    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="UUID of the GovernancePolicy (stable across all versions)",
    )
    version_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Monotonically increasing version number within policy scope",
    )
    rego_content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Full Rego source code at this version",
    )
    sha256_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="SHA-256 hex digest of rego_content for tamper detection",
    )
    change_description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Human-readable description of what changed in this version",
    )
    authored_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="UUID of the user who authored this policy version",
    )
    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When this version was pushed to OPA and activated (UTC)",
    )
    is_current: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="True only for the single most-recently activated version",
    )


# ---------------------------------------------------------------------------
# Gap 195 — Policy Simulation / Dry-Run
# ---------------------------------------------------------------------------


class PolicySimulation(AumOSModel):
    """Record of a policy simulation (dry-run) run.

    Simulations evaluate a policy against a set of historical or hypothetical
    inputs without affecting production state. Used for 'what-if' analysis —
    e.g., 'how would this new Rego policy have decided these past requests?'

    Attributes:
        policy_id: The policy being simulated (may be a draft version).
        scenario_name: Human-readable simulation scenario label.
        input_dataset: List of input objects to evaluate.
        results: Simulation outcome per input — {input_index, allow, violations}.
        allow_count: Count of inputs that would be allowed.
        deny_count: Count of inputs that would be denied.
        triggered_by: UUID of the user who ran the simulation.
        completed_at: When the simulation completed.
        duration_ms: Simulation duration in milliseconds.
    """

    __tablename__ = "gov_policy_simulations"

    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="UUID of the policy being simulated",
    )
    scenario_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Human-readable label for this simulation scenario",
    )
    input_dataset: Mapped[list] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=list,
        comment="List of input payloads evaluated during the simulation",
    )
    results: Mapped[list] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=list,
        comment="Per-input simulation results: {input_index, allow, violations}",
    )
    allow_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of inputs that would be allowed by the policy",
    )
    deny_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of inputs that would be denied by the policy",
    )
    triggered_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="UUID of the user who initiated this simulation",
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the simulation completed (UTC)",
    )
    duration_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Simulation duration in milliseconds",
    )


# ---------------------------------------------------------------------------
# Gap 197 — Decision Log Analytics
# ---------------------------------------------------------------------------


class PolicyEvaluationLog(AumOSModel):
    """Persistent log of individual policy evaluation decisions.

    Every call to PolicyService.evaluate_policy() appends a row here.
    This table is the data source for DecisionAnalyticsService which
    provides aggregated metrics, latency percentiles, and violation trends.

    This table accumulates high volume — keep indexed on (policy_id, evaluated_at)
    and partition by month in production.

    Attributes:
        policy_id: The policy that was evaluated.
        input_hash: SHA-256 of the input payload (for dedup/caching, not PII).
        allow_result: Whether the policy allowed the request.
        violations: List of violation strings returned by OPA.
        latency_ms: Evaluation latency in milliseconds.
        evaluated_at: Timestamp of the evaluation.
        actor_id: UUID of the user who triggered the evaluation.
        correlation_id: Request correlation ID.
    """

    __tablename__ = "gov_policy_evaluation_logs"

    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="UUID of the GovernancePolicy that was evaluated",
    )
    input_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="SHA-256 of the input payload (not stored raw — privacy)",
    )
    allow_result: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        index=True,
        comment="True if the policy allowed the request",
    )
    violations: Mapped[list] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=list,
        comment="Violation strings returned by OPA for this evaluation",
    )
    latency_ms: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Evaluation latency in milliseconds",
    )
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="When this evaluation occurred (UTC)",
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="UUID of the user or service that triggered this evaluation",
    )
    correlation_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        comment="X-Request-ID for distributed tracing",
    )


# ---------------------------------------------------------------------------
# Gap 199 — OPA Bundle Distribution
# ---------------------------------------------------------------------------


class OPASidecarStatus(AumOSModel):
    """Health and bundle metadata for the OPA sidecar instance.

    Records the last-known state of the OPA sidecar — its version, which
    bundles are currently loaded, and the last health-check result. Used
    by the bundle distribution endpoints to report sidecar status.

    Attributes:
        sidecar_name: Unique name/label for this OPA instance.
        opa_version: OPA binary version string.
        loaded_bundles: List of bundle IDs currently loaded in OPA.
        last_health_check_at: When the last health check was performed.
        is_healthy: Whether OPA was healthy at last check.
        bundle_etag: ETag of the last bundle sent (for version negotiation).
    """

    __tablename__ = "gov_opa_sidecar_status"

    sidecar_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Unique identifier for this OPA sidecar instance",
    )
    opa_version: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        comment="OPA binary version string reported by /health endpoint",
    )
    loaded_bundles: Mapped[list] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=list,
        comment="List of bundle policy IDs currently loaded in this OPA instance",
    )
    last_health_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of the last OPA health check (UTC)",
    )
    is_healthy: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether OPA was healthy at the last health check",
    )
    bundle_etag: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="ETag of the last bundle distributed (for version negotiation)",
    )


# ---------------------------------------------------------------------------
# Gap 201 — External Evidence Import
# ---------------------------------------------------------------------------


class ExternalEvidenceImport(AumOSModel):
    """Record of an evidence item imported from an external system.

    Tracks evidence imported from Jira, ServiceNow, or via inbound webhook.
    The import creates an EvidenceRecord in the primary store and records
    the external system reference here for bi-directional traceability.

    Attributes:
        evidence_record_id: FK to the created EvidenceRecord.
        workflow_id: FK to the ComplianceWorkflow this import targets.
        source_system: The external system — jira | servicenow | webhook.
        external_id: The external item ID (Jira issue key, SN ticket number, etc.).
        external_url: Direct URL to the external item.
        import_status: Whether the import succeeded or failed.
        import_error: Error message if the import failed.
        imported_at: When the import was performed.
        raw_payload: The raw data from the external system (for audit purposes).
    """

    __tablename__ = "gov_external_evidence_imports"

    evidence_record_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="UUID of the created EvidenceRecord (null if import failed)",
    )
    workflow_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="UUID of the target ComplianceWorkflow",
    )
    source_system: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="External system: jira | servicenow | webhook",
    )
    external_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="External item identifier (e.g., PROJ-1234 for Jira)",
    )
    external_url: Mapped[str | None] = mapped_column(
        String(2048),
        nullable=True,
        comment="Direct URL to the external evidence item",
    )
    import_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        comment="Import lifecycle: pending | success | failed",
    )
    import_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Error message if import_status is failed",
    )
    imported_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the import completed (UTC)",
    )
    raw_payload: Mapped[dict] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=dict,
        comment="Raw data from the external system (for audit and re-import)",
    )
