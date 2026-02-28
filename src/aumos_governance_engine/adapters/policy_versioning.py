"""Policy versioning and rollback adapter for the governance engine.

Implements Gap #196: Policy Versioning with Rollback.

Every time a policy's Rego content changes, a PolicyVersion record is created
with the SHA-256 hash of the content for tamper detection. Rollback creates a
new version by copying a prior version's Rego content, maintaining the append-
only audit trail.
"""

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from aumos_common.auth import TenantContext
from aumos_common.database import BaseRepository
from aumos_common.errors import NotFoundError
from aumos_common.observability import get_logger
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_governance_engine.core.models import PolicyVersion

logger = get_logger(__name__)


class PolicyVersionRepository(BaseRepository[PolicyVersion]):
    """Repository for PolicyVersion persistence.

    Args:
        session: The primary DB async session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize with a database session.

        Args:
            session: The SQLAlchemy async session for the primary DB.
        """
        super().__init__(session, PolicyVersion)

    async def create_version(
        self,
        tenant: TenantContext,
        policy_id: uuid.UUID,
        rego_content: str,
        authored_by: uuid.UUID,
        change_description: str | None = None,
    ) -> PolicyVersion:
        """Create a new policy version snapshot.

        Auto-increments the version number, computes the SHA-256 hash,
        and marks all previous versions as non-current.

        Args:
            tenant: The tenant context.
            policy_id: UUID of the GovernancePolicy.
            rego_content: The Rego source code at this version.
            authored_by: UUID of the user authoring this version.
            change_description: Optional description of what changed.

        Returns:
            The newly created PolicyVersion.
        """
        # Compute next version number
        stmt = select(func.max(PolicyVersion.version_number)).where(
            PolicyVersion.policy_id == policy_id,
            PolicyVersion.tenant_id == tenant.tenant_id,
        )
        result = await self._session.execute(stmt)
        max_ver = result.scalar() or 0
        next_ver = max_ver + 1

        # Compute SHA-256
        sha256_hash = hashlib.sha256(rego_content.encode()).hexdigest()

        # Mark all previous versions as not current
        await self._session.execute(
            update(PolicyVersion)
            .where(
                PolicyVersion.policy_id == policy_id,
                PolicyVersion.tenant_id == tenant.tenant_id,
                PolicyVersion.is_current == True,  # noqa: E712
            )
            .values(is_current=False)
        )

        version = PolicyVersion(
            tenant_id=tenant.tenant_id,
            policy_id=policy_id,
            version_number=next_ver,
            rego_content=rego_content,
            sha256_hash=sha256_hash,
            change_description=change_description,
            authored_by=authored_by,
            is_current=True,
        )
        self._session.add(version)
        await self._session.flush()
        await self._session.refresh(version)
        logger.info(
            "Created policy version",
            policy_id=str(policy_id),
            version=next_ver,
            sha256=sha256_hash[:8],
        )
        return version

    async def get_by_id(
        self,
        version_id: uuid.UUID,
        tenant: TenantContext,
    ) -> PolicyVersion:
        """Retrieve a specific version by ID.

        Args:
            version_id: The PolicyVersion UUID.
            tenant: The tenant context.

        Returns:
            The PolicyVersion.

        Raises:
            NotFoundError: If not found.
        """
        stmt = select(PolicyVersion).where(
            PolicyVersion.id == version_id,
            PolicyVersion.tenant_id == tenant.tenant_id,
        )
        result = await self._session.execute(stmt)
        ver = result.scalar_one_or_none()
        if ver is None:
            raise NotFoundError(resource="PolicyVersion", resource_id=str(version_id))
        return ver

    async def get_by_version_number(
        self,
        policy_id: uuid.UUID,
        version_number: int,
        tenant: TenantContext,
    ) -> PolicyVersion:
        """Retrieve a policy version by version number.

        Args:
            policy_id: The policy UUID.
            version_number: The version number to retrieve.
            tenant: The tenant context.

        Returns:
            The PolicyVersion.

        Raises:
            NotFoundError: If not found.
        """
        stmt = select(PolicyVersion).where(
            PolicyVersion.policy_id == policy_id,
            PolicyVersion.version_number == version_number,
            PolicyVersion.tenant_id == tenant.tenant_id,
        )
        result = await self._session.execute(stmt)
        ver = result.scalar_one_or_none()
        if ver is None:
            raise NotFoundError(
                resource="PolicyVersion",
                resource_id=f"{policy_id}:v{version_number}",
            )
        return ver

    async def list_by_policy(
        self,
        policy_id: uuid.UUID,
        tenant: TenantContext,
        page: int = 1,
        page_size: int = 20,
    ) -> list[PolicyVersion]:
        """List all versions for a policy, newest first.

        Args:
            policy_id: The policy UUID.
            tenant: The tenant context.
            page: Page number (1-indexed).
            page_size: Records per page.

        Returns:
            List of PolicyVersion records ordered by version_number descending.
        """
        stmt = (
            select(PolicyVersion)
            .where(
                PolicyVersion.policy_id == policy_id,
                PolicyVersion.tenant_id == tenant.tenant_id,
            )
            .order_by(PolicyVersion.version_number.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def mark_activated(
        self,
        version_id: uuid.UUID,
        tenant: TenantContext,
    ) -> PolicyVersion:
        """Mark a version as activated (pushed to OPA).

        Args:
            version_id: The PolicyVersion UUID.
            tenant: The tenant context.

        Returns:
            The updated PolicyVersion.
        """
        stmt = (
            update(PolicyVersion)
            .where(
                PolicyVersion.id == version_id,
                PolicyVersion.tenant_id == tenant.tenant_id,
            )
            .values(activated_at=datetime.now(UTC))
            .returning(PolicyVersion)
        )
        result = await self._session.execute(stmt)
        ver = result.scalar_one_or_none()
        if ver is None:
            raise NotFoundError(resource="PolicyVersion", resource_id=str(version_id))
        return ver


class PolicyVersionService:
    """Service for policy versioning and rollback.

    Implements Gap #196: version creation on every Rego update,
    rollback by creating a new version from prior content, and
    Audit Wall writes for every version change.

    Args:
        version_repo: Repository for PolicyVersion records.
        opa_client: OPA REST API client for bundle re-upload on rollback.
        audit_trail_repo: Audit Wall repository.
    """

    def __init__(
        self,
        version_repo: PolicyVersionRepository,
        opa_client: Any,
        audit_trail_repo: Any,
    ) -> None:
        """Initialize PolicyVersionService.

        Args:
            version_repo: PolicyVersionRepository instance.
            opa_client: OPA client implementing IOPAClient.
            audit_trail_repo: Audit trail repository for compliance writes.
        """
        self._version_repo = version_repo
        self._opa_client = opa_client
        self._audit_trail_repo = audit_trail_repo

    async def snapshot_version(
        self,
        tenant: TenantContext,
        policy_id: uuid.UUID,
        rego_content: str,
        authored_by: uuid.UUID,
        change_description: str | None = None,
        correlation_id: str | None = None,
    ) -> PolicyVersion:
        """Create a version snapshot for a policy Rego update.

        Args:
            tenant: The tenant context.
            policy_id: The GovernancePolicy UUID.
            rego_content: The new Rego source code.
            authored_by: UUID of the authoring user.
            change_description: Optional description of the change.
            correlation_id: Optional request correlation ID.

        Returns:
            The newly created PolicyVersion.
        """
        version = await self._version_repo.create_version(
            tenant=tenant,
            policy_id=policy_id,
            rego_content=rego_content,
            authored_by=authored_by,
            change_description=change_description,
        )

        try:
            await self._audit_trail_repo.append(
                tenant_id=tenant.tenant_id,
                event_type="governance.policy.version.created",
                actor_id=authored_by,
                resource_type="policy_version",
                resource_id=version.id,
                action="created",
                details={
                    "policy_id": str(policy_id),
                    "version_number": version.version_number,
                    "sha256_hash": version.sha256_hash,
                    "change_description": change_description,
                },
                timestamp=datetime.now(UTC),
                correlation_id=correlation_id,
            )
        except Exception as audit_err:
            logger.error(
                "Failed to write version snapshot to Audit Wall",
                version_id=str(version.id),
                error=str(audit_err),
            )

        return version

    async def rollback_to_version(
        self,
        tenant: TenantContext,
        policy_id: uuid.UUID,
        target_version_number: int,
        rolled_back_by: uuid.UUID,
        correlation_id: str | None = None,
    ) -> PolicyVersion:
        """Roll back a policy to a prior version.

        Creates a new version record with the same Rego content as the target
        version. Does NOT mutate the target version — preserves immutable history.
        Re-uploads the Rego content to OPA.

        Args:
            tenant: The tenant context.
            policy_id: The GovernancePolicy UUID.
            target_version_number: The version number to roll back to.
            rolled_back_by: UUID of the user performing the rollback.
            correlation_id: Optional request correlation ID.

        Returns:
            The newly created PolicyVersion (rollback snapshot).
        """
        # Fetch the target version to roll back to
        target = await self._version_repo.get_by_version_number(
            policy_id=policy_id,
            version_number=target_version_number,
            tenant=tenant,
        )

        # Create a new version that is a copy of the target
        new_version = await self._version_repo.create_version(
            tenant=tenant,
            policy_id=policy_id,
            rego_content=target.rego_content,
            authored_by=rolled_back_by,
            change_description=f"Rollback to version {target_version_number}",
        )

        # Re-upload to OPA
        try:
            await self._opa_client.upload_policy(policy_id, target.rego_content)
            await self._version_repo.mark_activated(new_version.id, tenant)
        except Exception as upload_err:
            logger.error(
                "Failed to re-upload OPA policy during rollback",
                policy_id=str(policy_id),
                error=str(upload_err),
            )

        # Write to Audit Wall
        try:
            await self._audit_trail_repo.append(
                tenant_id=tenant.tenant_id,
                event_type="governance.policy.version.rolled_back",
                actor_id=rolled_back_by,
                resource_type="policy_version",
                resource_id=new_version.id,
                action="rolled_back",
                details={
                    "policy_id": str(policy_id),
                    "rolled_back_to_version": target_version_number,
                    "new_version_number": new_version.version_number,
                    "sha256_hash": new_version.sha256_hash,
                },
                timestamp=datetime.now(UTC),
                correlation_id=correlation_id,
            )
        except Exception as audit_err:
            logger.error(
                "Failed to write rollback to Audit Wall",
                new_version_id=str(new_version.id),
                error=str(audit_err),
            )

        logger.info(
            "Policy rolled back to version",
            policy_id=str(policy_id),
            rolled_back_to=target_version_number,
            new_version=new_version.version_number,
        )
        return new_version
