"""SQLAlchemy ORM models for the governance engine.

All models use the `gov_` table prefix and extend AumOSModel for automatic
tenant_id, id (UUID), created_at, and updated_at fields.

Models:
- GovernancePolicy    — OPA Rego policies with version tracking
- ComplianceWorkflow  — Per-tenant per-regulation compliance assessment lifecycle
- AuditTrailEntry     — IMMUTABLE audit log (lives on SEPARATE audit DB)
- EvidenceRecord      — Compliance evidence artifacts linking controls to proof
- RegulationMapping   — Mapping of regulation articles to technical control IDs

IMPORTANT: AuditTrailEntry is defined here for ORM mapping purposes but it is
written ONLY via AuditTrailRepository, which connects to the separate audit DB.
Never write to gov_audit_trail_entries via the primary DB session.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
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
