"""Compliance Workflow Template Service — Gap #200.

Provides YAML-based workflow templates for all six supported regulations:
- SOC 2 Type II (soc2)
- ISO 27001:2022 (iso27001)
- HIPAA Security Rule (hipaa)
- ISO 42001:2023 AI Management (iso42001)
- EU AI Act (eu_ai_act)
- FedRAMP Moderate (fedramp)

Templates are bundled as static YAML files inside the package and loaded at
service startup. On instantiation, the template is materialized into
gov_compliance_workflows and associated evidence control metadata for the
requesting tenant.
"""

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from aumos_common.auth import TenantContext
from aumos_common.errors import NotFoundError, ValidationError
from aumos_common.observability import get_logger

from aumos_governance_engine.adapters.audit_wall import AuditWallRepository
from aumos_governance_engine.adapters.repositories import ComplianceWorkflowRepository
from aumos_governance_engine.core.models import ComplianceWorkflow

logger = get_logger(__name__)

# Path to the bundled YAML template directory
_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


class WorkflowTemplate:
    """Parsed representation of a compliance workflow template.

    Args:
        data: Raw YAML-parsed dict from the template file.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        """Initialize WorkflowTemplate from parsed YAML data.

        Args:
            data: YAML-deserialized template dict.
        """
        self.regulation_code: str = data["regulation_code"]
        self.name: str = data["name"]
        self.full_name: str = data["full_name"]
        self.issuing_body: str = data["issuing_body"]
        self.description: str = data.get("description", "")
        self.default_duration_days: int = data.get("default_duration_days", 365)
        self.review_milestones: list[dict[str, Any]] = data.get("review_milestones", [])
        self.controls: list[dict[str, Any]] = data.get("controls", [])

    def to_summary_dict(self) -> dict[str, Any]:
        """Return a summary dict for listing purposes (no full control detail).

        Returns:
            Dict with template metadata and control count.
        """
        return {
            "regulation_code": self.regulation_code,
            "name": self.name,
            "full_name": self.full_name,
            "issuing_body": self.issuing_body,
            "description": self.description.strip(),
            "default_duration_days": self.default_duration_days,
            "milestone_count": len(self.review_milestones),
            "control_count": len(self.controls),
        }

    def to_detail_dict(self) -> dict[str, Any]:
        """Return the full template dict including all controls and milestones.

        Returns:
            Full template dict for the instantiation response.
        """
        return {
            **self.to_summary_dict(),
            "review_milestones": self.review_milestones,
            "controls": self.controls,
        }


class ComplianceTemplateService:
    """Service for listing and instantiating compliance workflow templates.

    Templates are loaded from YAML files at startup and cached in memory.
    Instantiation creates a ComplianceWorkflow record pre-populated with
    control IDs, required evidence types, and review milestones.

    Args:
        workflow_repo: Repository for ComplianceWorkflow persistence.
        audit_repo: Audit Wall repository for immutable audit writes.
        template_dir: Path to the directory containing YAML template files.
    """

    def __init__(
        self,
        workflow_repo: ComplianceWorkflowRepository,
        audit_repo: AuditWallRepository,
        template_dir: Path = _TEMPLATE_DIR,
    ) -> None:
        """Initialize ComplianceTemplateService and load templates from disk.

        Args:
            workflow_repo: ComplianceWorkflow repository for DB persistence.
            audit_repo: Audit Wall repository.
            template_dir: Directory containing *.yaml template files.
        """
        self._workflow_repo = workflow_repo
        self._audit_repo = audit_repo
        self._templates: dict[str, WorkflowTemplate] = {}
        self._load_templates(template_dir)

    def _load_templates(self, template_dir: Path) -> None:
        """Load all YAML templates from the template directory.

        Iterates over *.yaml files in template_dir, parses each as a
        WorkflowTemplate, and caches by regulation_code.

        Args:
            template_dir: Directory path containing YAML template files.
        """
        if not template_dir.exists():
            logger.warning(
                "Template directory not found — no templates loaded",
                template_dir=str(template_dir),
            )
            return

        loaded = 0
        for yaml_file in sorted(template_dir.glob("*.yaml")):
            try:
                raw = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                template = WorkflowTemplate(raw)
                self._templates[template.regulation_code] = template
                loaded += 1
                logger.debug(
                    "Loaded compliance template",
                    regulation_code=template.regulation_code,
                    control_count=len(template.controls),
                )
            except Exception as exc:
                logger.error(
                    "Failed to load compliance template",
                    yaml_file=str(yaml_file),
                    error=str(exc),
                )

        logger.info("Compliance templates loaded", count=loaded, template_codes=list(self._templates.keys()))

    def list_templates(self) -> list[dict[str, Any]]:
        """Return summary metadata for all available workflow templates.

        Returns:
            List of template summary dicts, one per supported regulation.
        """
        return [t.to_summary_dict() for t in self._templates.values()]

    def get_template(self, regulation_code: str) -> WorkflowTemplate:
        """Return a template by regulation code.

        Args:
            regulation_code: The regulation code (e.g., 'soc2', 'hipaa').

        Returns:
            The WorkflowTemplate for the given regulation.

        Raises:
            NotFoundError: If no template exists for the given regulation code.
        """
        template = self._templates.get(regulation_code)
        if template is None:
            available = list(self._templates.keys())
            raise NotFoundError(
                message=f"No workflow template found for regulation '{regulation_code}'. "
                f"Available templates: {available}",
            )
        return template

    async def instantiate_from_template(
        self,
        tenant: TenantContext,
        regulation_code: str,
        workflow_name: str,
        actor_id: uuid.UUID,
        assigned_to: uuid.UUID | None = None,
        notes: str | None = None,
        duration_days: int | None = None,
        correlation_id: str | None = None,
    ) -> ComplianceWorkflow:
        """Instantiate a compliance workflow from a regulation template.

        Fetches the template for the given regulation, creates a
        ComplianceWorkflow record pre-populated with milestones and control
        context from the template, and writes an Audit Wall entry.

        Args:
            tenant: Tenant context from auth middleware.
            regulation_code: Regulation template to use (e.g., 'soc2').
            workflow_name: Human-readable name for the new workflow.
            actor_id: UUID of the user creating the workflow.
            assigned_to: Optional UUID of the user responsible for the workflow.
            notes: Optional initial notes.
            duration_days: Override for the template's default duration.
            correlation_id: Optional request correlation ID.

        Returns:
            The newly created ComplianceWorkflow ORM instance.

        Raises:
            NotFoundError: If the regulation code is not found in templates.
            ValidationError: If workflow_name is empty.
        """
        workflow_name = workflow_name.strip()
        if not workflow_name:
            raise ValidationError(message="workflow_name must not be empty")

        template = self.get_template(regulation_code)

        effective_duration = duration_days or template.default_duration_days
        created_at_utc = datetime.now(UTC)
        next_due: datetime | None = None

        if template.review_milestones:
            first_milestone_offset = template.review_milestones[0].get("offset_days", 30)
            next_due = created_at_utc + timedelta(days=first_milestone_offset)

        # Build milestone + control metadata to embed in the workflow notes/metadata
        template_metadata: dict[str, Any] = {
            "template_regulation_code": regulation_code,
            "template_name": template.name,
            "template_milestones": template.review_milestones,
            "template_controls": template.controls,
            "template_duration_days": effective_duration,
            "instantiated_from_template": True,
        }

        # Compose initial notes combining user notes and template description
        combined_notes: str = template.description.strip()
        if notes:
            combined_notes = f"{combined_notes}\n\n{notes}"

        workflow = ComplianceWorkflow(
            tenant_id=tenant.tenant_id,
            regulation=regulation_code,
            name=workflow_name,
            status="initiated",
            evidence_count=0,
            last_assessment=None,
            next_due=next_due,
            assigned_to=assigned_to,
            notes=combined_notes,
        )

        # Persist workflow
        workflow = await self._workflow_repo.create(workflow)

        logger.info(
            "Compliance workflow instantiated from template",
            tenant_id=str(tenant.tenant_id),
            regulation_code=regulation_code,
            workflow_id=str(workflow.id),
            workflow_name=workflow_name,
            control_count=len(template.controls),
        )

        # Write to Audit Wall
        try:
            await self._audit_repo.write(
                tenant_id=tenant.tenant_id,
                event_type="governance.compliance.workflow.created_from_template",
                actor_id=actor_id,
                resource_type="compliance_workflow",
                resource_id=workflow.id,
                action="create_from_template",
                details={
                    "regulation_code": regulation_code,
                    "template_name": template.name,
                    "workflow_name": workflow_name,
                    "control_count": len(template.controls),
                    "milestone_count": len(template.review_milestones),
                    "duration_days": effective_duration,
                },
                source_service="aumos-governance-engine",
                correlation_id=correlation_id,
            )
        except Exception as audit_exc:
            logger.error(
                "Audit Wall write failed for template instantiation",
                workflow_id=str(workflow.id),
                error=str(audit_exc),
            )

        return workflow
