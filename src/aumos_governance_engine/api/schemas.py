"""Pydantic request and response schemas for the governance engine API.

All API inputs and outputs use Pydantic models — never raw dicts.
Schemas are grouped by resource type.

Resources:
- GovernancePolicy — policy CRUD and evaluation
- ComplianceWorkflow — compliance workflow management
- AuditTrailEntry — immutable audit trail query
- EvidenceRecord — evidence submission and listing
- Regulation — regulation metadata and control mappings
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# GovernancePolicy schemas
# ---------------------------------------------------------------------------


class GovernancePolicyCreateRequest(BaseModel):
    """Request body for creating a new governance policy."""

    name: str = Field(
        description="Human-readable policy name, unique within tenant scope",
        min_length=1,
        max_length=255,
    )
    policy_type: str = Field(
        default="opa_rego",
        description="Policy engine type: opa_rego | custom",
    )
    rego_content: str | None = Field(
        default=None,
        description="Full OPA Rego policy source. Required when policy_type is opa_rego.",
    )
    description: str | None = Field(
        default=None,
        description="Human-readable description of what this policy enforces",
    )
    regulation_refs: list[str] = Field(
        default_factory=list,
        description="List of regulation codes this policy implements: [soc2, iso27001, ...]",
    )


class GovernancePolicyResponse(BaseModel):
    """Response schema for a governance policy."""

    id: uuid.UUID = Field(description="Policy UUID")
    tenant_id: uuid.UUID = Field(description="Owning tenant UUID")
    name: str = Field(description="Policy name")
    policy_type: str = Field(description="Engine type: opa_rego | custom")
    rego_content: str | None = Field(description="Rego source (may be redacted for non-owners)")
    version: int = Field(description="Version number within this tenant+name scope")
    status: str = Field(description="Lifecycle status: draft | active | deprecated | archived")
    regulation_refs: list[str] = Field(description="Associated regulation codes")
    description: str | None = Field(description="Policy description")
    created_at: datetime = Field(description="Creation timestamp (UTC)")
    updated_at: datetime = Field(description="Last update timestamp (UTC)")


class PolicyActivateRequest(BaseModel):
    """Request body for activating a policy (may be empty — activation uses path param)."""

    notes: str | None = Field(
        default=None,
        description="Optional notes explaining why this policy is being activated",
    )


class PolicyEvaluateRequest(BaseModel):
    """Request body for evaluating a governance policy against input data."""

    input: dict[str, Any] = Field(
        description="Structured JSON input data to evaluate the policy against. "
        "Schema depends on the specific Rego policy.",
    )


class PolicyEvaluateResponse(BaseModel):
    """Response schema for a policy evaluation result."""

    policy_id: uuid.UUID = Field(description="Evaluated policy UUID")
    policy_name: str = Field(description="Policy name")
    allowed: bool = Field(description="Whether the policy allows the action (OPA allow decision)")
    violations: list[str] = Field(
        default_factory=list,
        description="List of violation messages from the Rego policy",
    )
    latency_ms: float = Field(description="OPA evaluation latency in milliseconds")
    evaluated_at: datetime = Field(description="Evaluation timestamp (UTC)")


# ---------------------------------------------------------------------------
# ComplianceWorkflow schemas
# ---------------------------------------------------------------------------


class ComplianceWorkflowCreateRequest(BaseModel):
    """Request body for creating a compliance workflow."""

    regulation: str = Field(
        description="Regulation code: soc2 | iso27001 | hipaa | iso42001 | eu_ai_act | fedramp",
    )
    name: str = Field(
        description="Human-readable workflow name, e.g., 'SOC 2 Type II — FY2026'",
        min_length=1,
        max_length=255,
    )
    next_due: datetime | None = Field(
        default=None,
        description="When the first assessment action is due (UTC)",
    )
    assigned_to: uuid.UUID | None = Field(
        default=None,
        description="UUID of the user responsible for this workflow",
    )
    notes: str | None = Field(
        default=None,
        description="Initial notes for the compliance team",
    )


class ComplianceWorkflowResponse(BaseModel):
    """Response schema for a compliance workflow."""

    id: uuid.UUID = Field(description="Workflow UUID")
    tenant_id: uuid.UUID = Field(description="Owning tenant UUID")
    regulation: str = Field(description="Regulation code")
    name: str = Field(description="Workflow name")
    status: str = Field(
        description=(
            "Assessment status: initiated | evidence_collection | under_review | "
            "remediation | attested | archived"
        )
    )
    evidence_count: int = Field(description="Number of attached evidence records")
    last_assessment: datetime | None = Field(description="Most recent assessment action (UTC)")
    next_due: datetime | None = Field(description="Next assessment due date (UTC)")
    assigned_to: uuid.UUID | None = Field(description="Responsible user UUID")
    notes: str | None = Field(description="Compliance team notes")
    created_at: datetime = Field(description="Workflow creation timestamp (UTC)")
    updated_at: datetime = Field(description="Last update timestamp (UTC)")


class ComplianceDashboardRegulationSummary(BaseModel):
    """Per-regulation summary for the compliance dashboard."""

    regulation: str = Field(description="Regulation code")
    total_workflows: int = Field(description="Total workflow count for this regulation")
    attested_workflows: int = Field(description="Number of workflows in attested status")
    in_progress_workflows: int = Field(description="Workflows currently in progress")
    total_evidence: int = Field(description="Total evidence records across all workflows")
    compliance_score: float = Field(
        description="Compliance score 0.0-1.0 based on attested/total ratio",
    )
    last_assessment: datetime | None = Field(description="Most recent assessment timestamp (UTC)")
    next_due: datetime | None = Field(description="Earliest upcoming due date (UTC)")


class ComplianceDashboardResponse(BaseModel):
    """Response schema for the compliance dashboard."""

    tenant_id: uuid.UUID = Field(description="Tenant UUID")
    generated_at: datetime = Field(description="Dashboard generation timestamp (UTC)")
    regulations: list[ComplianceDashboardRegulationSummary] = Field(
        description="Per-regulation compliance summaries",
    )


# ---------------------------------------------------------------------------
# AuditTrailEntry schemas
# ---------------------------------------------------------------------------


class AuditTrailQueryParams(BaseModel):
    """Query parameters for the audit trail endpoint (used as dependency)."""

    event_type: str | None = Field(default=None, description="Filter by event type prefix")
    resource_type: str | None = Field(default=None, description="Filter by resource type")
    resource_id: uuid.UUID | None = Field(default=None, description="Filter by resource UUID")
    actor_id: uuid.UUID | None = Field(default=None, description="Filter by actor UUID")
    start_time: datetime | None = Field(default=None, description="Start of time range (UTC)")
    end_time: datetime | None = Field(default=None, description="End of time range (UTC)")
    page: int = Field(default=1, ge=1, description="Page number")
    page_size: int = Field(default=50, ge=1, le=200, description="Records per page")


class AuditTrailEntryResponse(BaseModel):
    """Response schema for an immutable audit trail entry."""

    id: uuid.UUID = Field(description="Audit entry UUID")
    tenant_id: uuid.UUID = Field(description="Owning tenant UUID")
    event_type: str = Field(description="Dot-notation event type")
    actor_id: uuid.UUID = Field(description="UUID of the actor who performed the action")
    resource_type: str = Field(description="Type of the affected resource")
    resource_id: uuid.UUID = Field(description="UUID of the affected resource")
    action: str = Field(description="Action verb")
    details: dict[str, Any] = Field(description="Event-specific payload")
    timestamp: datetime = Field(description="Immutable event timestamp (UTC)")
    source_service: str = Field(description="Originating service name")
    correlation_id: str | None = Field(description="Request correlation ID")


# ---------------------------------------------------------------------------
# EvidenceRecord schemas
# ---------------------------------------------------------------------------


class EvidenceSubmitRequest(BaseModel):
    """Request body for submitting a compliance evidence record."""

    workflow_id: uuid.UUID = Field(description="UUID of the compliance workflow to attach evidence to")
    evidence_type: str = Field(
        description=(
            "Evidence type: audit_log | config_export | test_result | screenshot | "
            "policy_document | access_review | penetration_test | training_record"
        )
    )
    title: str = Field(
        description="Short descriptive title",
        min_length=1,
        max_length=255,
    )
    description: str = Field(
        default="",
        description="Detailed description of what this evidence demonstrates",
    )
    artifact_uri: str | None = Field(
        default=None,
        description="Storage URI for the artifact (s3://bucket/key or https://...)",
    )
    collector: str = Field(
        default="manual",
        description="How evidence was collected: auto | manual",
    )
    control_ids: list[str] = Field(
        default_factory=list,
        description="List of regulation control IDs this evidence satisfies",
    )


class EvidenceRecordResponse(BaseModel):
    """Response schema for a compliance evidence record."""

    id: uuid.UUID = Field(description="Evidence record UUID")
    tenant_id: uuid.UUID = Field(description="Owning tenant UUID")
    workflow_id: uuid.UUID = Field(description="Associated workflow UUID")
    evidence_type: str = Field(description="Evidence type classification")
    title: str = Field(description="Evidence title")
    description: str = Field(description="Evidence description")
    artifact_uri: str | None = Field(description="Storage URI for the artifact")
    collected_at: datetime = Field(description="Collection timestamp (UTC)")
    collector: str = Field(description="Collection method: auto | manual")
    control_ids: list[str] = Field(description="Control IDs satisfied by this evidence")
    status: str = Field(description="Review status: pending_review | accepted | rejected | needs_revision")
    reviewed_by: uuid.UUID | None = Field(description="Reviewer UUID")
    reviewed_at: datetime | None = Field(description="Review timestamp (UTC)")
    created_at: datetime = Field(description="Record creation timestamp (UTC)")
    updated_at: datetime = Field(description="Last update timestamp (UTC)")


# ---------------------------------------------------------------------------
# Regulation schemas
# ---------------------------------------------------------------------------


class RegulationMetadata(BaseModel):
    """Metadata for a supported regulation."""

    code: str = Field(description="Regulation code used in API calls")
    name: str = Field(description="Short name (e.g., SOC 2 Type II)")
    full_name: str = Field(description="Full official regulation name")
    issuing_body: str = Field(description="Issuing organization")
    scope: str = Field(description="Scope of the regulation")
    ai_specific: bool = Field(description="Whether this regulation is AI-specific")


class RegulationListResponse(BaseModel):
    """Response schema for the list of supported regulations."""

    regulations: list[dict[str, Any]] = Field(description="List of regulation metadata objects")


class RegulationControlResponse(BaseModel):
    """Response schema for a regulation control mapping entry."""

    regulation: str = Field(description="Regulation code")
    article_ref: str = Field(description="Article or section reference within the regulation")
    requirement_text: str = Field(description="Full text of the regulatory requirement")
    control_ids: list[str] = Field(description="Technical control identifiers")
    automated: bool = Field(description="Whether automated evidence collection can satisfy this control")
    notes: str | None = Field(description="Optional implementation notes")
