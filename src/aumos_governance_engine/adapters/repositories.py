"""SQLAlchemy repositories for the governance engine primary database.

Each repository implements the corresponding interface from core/interfaces.py
and extends BaseRepository from aumos-common for standard CRUD operations.

Repositories:
- PolicyRepository               — GovernancePolicy CRUD
- ComplianceWorkflowRepository   — ComplianceWorkflow CRUD and dashboard
- EvidenceRepository             — EvidenceRecord CRUD
- RegulationMappingRepository    — RegulationMapping read-only

NOTE: AuditTrailRepository is intentionally in audit_wall.py, not here.
It uses a separate database session and must never be imported alongside
the primary DB repositories.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.auth import TenantContext
from aumos_common.database import BaseRepository
from aumos_common.errors import NotFoundError
from aumos_common.observability import get_logger

from aumos_governance_engine.core.models import (
    ComplianceWorkflow,
    EvidenceRecord,
    GovernancePolicy,
    RegulationMapping,
)

logger = get_logger(__name__)


class PolicyRepository(BaseRepository[GovernancePolicy]):
    """Repository for GovernancePolicy persistence on the primary database.

    Extends BaseRepository which provides RLS-aware session management.
    All queries are automatically scoped to the current tenant via RLS.

    Args:
        session: The primary DB async session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize PolicyRepository with a database session.

        Args:
            session: The SQLAlchemy async session for the primary DB.
        """
        super().__init__(session, GovernancePolicy)

    async def create(
        self,
        tenant: TenantContext,
        name: str,
        policy_type: str,
        rego_content: str | None,
        description: str | None,
        regulation_refs: list[str],
    ) -> GovernancePolicy:
        """Create and persist a new governance policy.

        Args:
            tenant: The tenant context.
            name: Policy name.
            policy_type: Engine type.
            rego_content: Rego source.
            description: Optional description.
            regulation_refs: Associated regulation codes.

        Returns:
            The persisted GovernancePolicy with auto-generated version.
        """
        # Determine version — find max version for this tenant+name combination
        stmt = select(func.max(GovernancePolicy.version)).where(
            GovernancePolicy.tenant_id == tenant.tenant_id,
            GovernancePolicy.name == name,
        )
        result = await self._session.execute(stmt)
        max_version = result.scalar() or 0
        next_version = max_version + 1

        policy = GovernancePolicy(
            tenant_id=tenant.tenant_id,
            name=name,
            policy_type=policy_type,
            rego_content=rego_content,
            description=description,
            regulation_refs=regulation_refs,
            version=next_version,
            status="draft",
        )
        self._session.add(policy)
        await self._session.flush()
        await self._session.refresh(policy)
        logger.info(
            "Policy created in DB",
            policy_id=str(policy.id),
            tenant_id=str(tenant.tenant_id),
            version=next_version,
        )
        return policy

    async def get_by_id(self, policy_id: uuid.UUID, tenant: TenantContext) -> GovernancePolicy:
        """Retrieve a policy by ID, scoped to the tenant.

        Args:
            policy_id: The policy UUID.
            tenant: The tenant context.

        Returns:
            The GovernancePolicy.

        Raises:
            NotFoundError: If not found.
        """
        stmt = select(GovernancePolicy).where(
            GovernancePolicy.id == policy_id,
            GovernancePolicy.tenant_id == tenant.tenant_id,
        )
        result = await self._session.execute(stmt)
        policy = result.scalar_one_or_none()
        if policy is None:
            raise NotFoundError(resource="GovernancePolicy", resource_id=str(policy_id))
        return policy

    async def list_all(
        self,
        tenant: TenantContext,
        status_filter: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> list[GovernancePolicy]:
        """List policies for a tenant with optional status filter.

        Args:
            tenant: The tenant context.
            status_filter: Optional status.
            page: Page number.
            page_size: Records per page.

        Returns:
            List of GovernancePolicy records.
        """
        stmt = select(GovernancePolicy).where(
            GovernancePolicy.tenant_id == tenant.tenant_id,
        )
        if status_filter:
            stmt = stmt.where(GovernancePolicy.status == status_filter)
        stmt = stmt.order_by(GovernancePolicy.created_at.desc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def update_status(
        self,
        policy_id: uuid.UUID,
        new_status: str,
        tenant: TenantContext,
    ) -> GovernancePolicy:
        """Update the status of a policy.

        Args:
            policy_id: The policy UUID.
            new_status: Target status.
            tenant: The tenant context.

        Returns:
            The updated GovernancePolicy.
        """
        stmt = (
            update(GovernancePolicy)
            .where(
                GovernancePolicy.id == policy_id,
                GovernancePolicy.tenant_id == tenant.tenant_id,
            )
            .values(status=new_status)
            .returning(GovernancePolicy)
        )
        result = await self._session.execute(stmt)
        policy = result.scalar_one_or_none()
        if policy is None:
            raise NotFoundError(resource="GovernancePolicy", resource_id=str(policy_id))
        return policy


class ComplianceWorkflowRepository(BaseRepository[ComplianceWorkflow]):
    """Repository for ComplianceWorkflow persistence on the primary database.

    Args:
        session: The primary DB async session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize ComplianceWorkflowRepository with a database session.

        Args:
            session: The SQLAlchemy async session for the primary DB.
        """
        super().__init__(session, ComplianceWorkflow)

    async def create(
        self,
        tenant: TenantContext,
        regulation: str,
        name: str,
        next_due: datetime | None = None,
        assigned_to: uuid.UUID | None = None,
        notes: str | None = None,
    ) -> ComplianceWorkflow:
        """Create and persist a new compliance workflow.

        Args:
            tenant: The tenant context.
            regulation: Regulation code.
            name: Workflow name.
            next_due: Optional due date.
            assigned_to: Optional responsible user.
            notes: Optional notes.

        Returns:
            The persisted ComplianceWorkflow.
        """
        workflow = ComplianceWorkflow(
            tenant_id=tenant.tenant_id,
            regulation=regulation,
            name=name,
            status="initiated",
            evidence_count=0,
            next_due=next_due,
            assigned_to=assigned_to,
            notes=notes,
        )
        self._session.add(workflow)
        await self._session.flush()
        await self._session.refresh(workflow)
        return workflow

    async def get_by_id(
        self,
        workflow_id: uuid.UUID,
        tenant: TenantContext,
    ) -> ComplianceWorkflow:
        """Retrieve a workflow by ID.

        Args:
            workflow_id: The workflow UUID.
            tenant: The tenant context.

        Returns:
            The ComplianceWorkflow.

        Raises:
            NotFoundError: If not found.
        """
        stmt = select(ComplianceWorkflow).where(
            ComplianceWorkflow.id == workflow_id,
            ComplianceWorkflow.tenant_id == tenant.tenant_id,
        )
        result = await self._session.execute(stmt)
        workflow = result.scalar_one_or_none()
        if workflow is None:
            raise NotFoundError(resource="ComplianceWorkflow", resource_id=str(workflow_id))
        return workflow

    async def list_all(
        self,
        tenant: TenantContext,
        regulation_filter: str | None = None,
        status_filter: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> list[ComplianceWorkflow]:
        """List workflows for a tenant.

        Args:
            tenant: The tenant context.
            regulation_filter: Optional regulation code.
            status_filter: Optional status.
            page: Page number.
            page_size: Records per page.

        Returns:
            List of ComplianceWorkflow records.
        """
        stmt = select(ComplianceWorkflow).where(
            ComplianceWorkflow.tenant_id == tenant.tenant_id,
        )
        if regulation_filter:
            stmt = stmt.where(ComplianceWorkflow.regulation == regulation_filter)
        if status_filter:
            stmt = stmt.where(ComplianceWorkflow.status == status_filter)
        stmt = stmt.order_by(ComplianceWorkflow.created_at.desc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def update_status(
        self,
        workflow_id: uuid.UUID,
        new_status: str,
        tenant: TenantContext,
    ) -> ComplianceWorkflow:
        """Update a workflow's lifecycle status.

        Args:
            workflow_id: The workflow UUID.
            new_status: Target status.
            tenant: The tenant context.

        Returns:
            The updated ComplianceWorkflow.
        """
        stmt = (
            update(ComplianceWorkflow)
            .where(
                ComplianceWorkflow.id == workflow_id,
                ComplianceWorkflow.tenant_id == tenant.tenant_id,
            )
            .values(status=new_status, last_assessment=func.now())
            .returning(ComplianceWorkflow)
        )
        result = await self._session.execute(stmt)
        workflow = result.scalar_one_or_none()
        if workflow is None:
            raise NotFoundError(resource="ComplianceWorkflow", resource_id=str(workflow_id))
        return workflow

    async def increment_evidence_count(
        self,
        workflow_id: uuid.UUID,
        tenant: TenantContext,
    ) -> None:
        """Atomically increment the denormalized evidence count.

        Args:
            workflow_id: The workflow UUID.
            tenant: The tenant context.
        """
        stmt = (
            update(ComplianceWorkflow)
            .where(
                ComplianceWorkflow.id == workflow_id,
                ComplianceWorkflow.tenant_id == tenant.tenant_id,
            )
            .values(evidence_count=ComplianceWorkflow.evidence_count + 1)
        )
        await self._session.execute(stmt)

    async def get_dashboard_summary(
        self,
        tenant: TenantContext,
    ) -> list[dict[str, Any]]:
        """Aggregate compliance status across all regulations for a tenant.

        Args:
            tenant: The tenant context.

        Returns:
            List of dicts with aggregated per-regulation compliance data.
        """
        stmt = select(
            ComplianceWorkflow.regulation,
            func.count(ComplianceWorkflow.id).label("total_workflows"),
            func.sum(
                func.cast(ComplianceWorkflow.status == "attested", type_=None)
            ).label("attested_workflows"),
            func.sum(ComplianceWorkflow.evidence_count).label("total_evidence"),
            func.max(ComplianceWorkflow.last_assessment).label("last_assessment"),
            func.min(ComplianceWorkflow.next_due).label("next_due"),
        ).where(
            ComplianceWorkflow.tenant_id == tenant.tenant_id,
        ).group_by(
            ComplianceWorkflow.regulation,
        )

        result = await self._session.execute(stmt)
        rows = result.all()

        summaries = []
        for row in rows:
            total = row.total_workflows or 0
            attested = int(row.attested_workflows or 0)
            in_progress = total - attested
            compliance_score = round(attested / total, 4) if total > 0 else 0.0
            summaries.append({
                "regulation": row.regulation,
                "total_workflows": total,
                "attested_workflows": attested,
                "in_progress_workflows": in_progress,
                "total_evidence": int(row.total_evidence or 0),
                "compliance_score": compliance_score,
                "last_assessment": row.last_assessment,
                "next_due": row.next_due,
            })

        return summaries


class EvidenceRepository(BaseRepository[EvidenceRecord]):
    """Repository for EvidenceRecord persistence on the primary database.

    Args:
        session: The primary DB async session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize EvidenceRepository with a database session.

        Args:
            session: The SQLAlchemy async session for the primary DB.
        """
        super().__init__(session, EvidenceRecord)

    async def create(
        self,
        tenant: TenantContext,
        workflow_id: uuid.UUID,
        evidence_type: str,
        title: str,
        description: str,
        artifact_uri: str | None,
        collected_at: datetime,
        collector: str,
        control_ids: list[str],
    ) -> EvidenceRecord:
        """Create and persist a new evidence record.

        Args:
            tenant: The tenant context.
            workflow_id: Associated workflow UUID.
            evidence_type: Type classification.
            title: Short title.
            description: Detailed description.
            artifact_uri: Optional storage URI.
            collected_at: Collection timestamp.
            collector: auto or manual.
            control_ids: Control IDs satisfied.

        Returns:
            The persisted EvidenceRecord.
        """
        record = EvidenceRecord(
            tenant_id=tenant.tenant_id,
            workflow_id=workflow_id,
            evidence_type=evidence_type,
            title=title,
            description=description,
            artifact_uri=artifact_uri,
            collected_at=collected_at,
            collector=collector,
            control_ids=control_ids,
            status="pending_review",
        )
        self._session.add(record)
        await self._session.flush()
        await self._session.refresh(record)
        return record

    async def list_by_workflow(
        self,
        workflow_id: uuid.UUID,
        tenant: TenantContext,
        page: int = 1,
        page_size: int = 20,
    ) -> list[EvidenceRecord]:
        """List evidence records for a workflow.

        Args:
            workflow_id: The workflow UUID.
            tenant: The tenant context.
            page: Page number.
            page_size: Records per page.

        Returns:
            List of EvidenceRecord records.
        """
        stmt = (
            select(EvidenceRecord)
            .where(
                EvidenceRecord.workflow_id == workflow_id,
                EvidenceRecord.tenant_id == tenant.tenant_id,
            )
            .order_by(EvidenceRecord.collected_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())


class RegulationMappingRepository(BaseRepository[RegulationMapping]):
    """Repository for RegulationMapping read operations.

    Regulation mappings are read-only from the API perspective. They are
    seeded by migration and can be extended by tenants via admin operations.

    Args:
        session: The primary DB async session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize RegulationMappingRepository with a database session.

        Args:
            session: The SQLAlchemy async session for the primary DB.
        """
        super().__init__(session, RegulationMapping)

    async def list_by_regulation(
        self,
        regulation: str,
        tenant: TenantContext,
        automated_only: bool = False,
    ) -> list[RegulationMapping]:
        """List control mappings for a regulation.

        Returns both platform-wide (tenant_id IS NULL) and tenant-specific
        mappings, with tenant-specific rows taking precedence via ordering.

        Args:
            regulation: The regulation code.
            tenant: The tenant context.
            automated_only: If True, only return auto-assessable controls.

        Returns:
            List of RegulationMapping records.
        """
        from sqlalchemy import or_

        stmt = (
            select(RegulationMapping)
            .where(
                RegulationMapping.regulation == regulation,
                or_(
                    RegulationMapping.tenant_id == tenant.tenant_id,
                    RegulationMapping.tenant_id.is_(None),
                ),
            )
        )
        if automated_only:
            stmt = stmt.where(RegulationMapping.automated.is_(True))
        stmt = stmt.order_by(RegulationMapping.article_ref)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())
