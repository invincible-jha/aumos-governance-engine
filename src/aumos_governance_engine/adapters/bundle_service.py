"""OPA bundle distribution service for the governance engine.

Implements Gap #199: OPA Bundle Distribution.

Builds .tar.gz bundles of active policies, supports ETag-based version
negotiation, and tracks OPA sidecar status. Bundles are streamed to
the OPA sidecar via the REST API or served for manual download.
"""

import gzip
import hashlib
import io
import json
import tarfile
import uuid
from datetime import UTC, datetime
from typing import Any

from aumos_common.auth import TenantContext
from aumos_common.database import BaseRepository
from aumos_common.observability import get_logger
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_governance_engine.core.models import GovernancePolicy, OPASidecarStatus

logger = get_logger(__name__)


class OPASidecarStatusRepository(BaseRepository[OPASidecarStatus]):
    """Repository for OPASidecarStatus persistence.

    Args:
        session: The primary DB async session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize with a database session.

        Args:
            session: The SQLAlchemy async session for the primary DB.
        """
        super().__init__(session, OPASidecarStatus)

    async def upsert(
        self,
        tenant: TenantContext,
        sidecar_name: str,
        opa_version: str | None,
        loaded_bundles: list[str],
        is_healthy: bool,
        bundle_etag: str | None = None,
    ) -> OPASidecarStatus:
        """Upsert sidecar status (create or update existing record).

        Args:
            tenant: The tenant context.
            sidecar_name: Unique sidecar identifier.
            opa_version: OPA version string.
            loaded_bundles: List of currently loaded bundle policy IDs.
            is_healthy: Whether OPA is healthy.
            bundle_etag: ETag of the last distributed bundle.

        Returns:
            The upserted OPASidecarStatus.
        """
        stmt = select(OPASidecarStatus).where(
            OPASidecarStatus.sidecar_name == sidecar_name,
            OPASidecarStatus.tenant_id == tenant.tenant_id,
        )
        result = await self._session.execute(stmt)
        existing = result.scalar_one_or_none()

        now = datetime.now(UTC)
        if existing:
            existing.opa_version = opa_version
            existing.loaded_bundles = loaded_bundles
            existing.is_healthy = is_healthy
            existing.last_health_check_at = now
            if bundle_etag:
                existing.bundle_etag = bundle_etag
            await self._session.flush()
            return existing

        status = OPASidecarStatus(
            tenant_id=tenant.tenant_id,
            sidecar_name=sidecar_name,
            opa_version=opa_version,
            loaded_bundles=loaded_bundles,
            is_healthy=is_healthy,
            last_health_check_at=now,
            bundle_etag=bundle_etag,
        )
        self._session.add(status)
        await self._session.flush()
        await self._session.refresh(status)
        return status

    async def list_all(self, tenant: TenantContext) -> list[OPASidecarStatus]:
        """List all sidecar status records for a tenant.

        Args:
            tenant: The tenant context.

        Returns:
            List of OPASidecarStatus records.
        """
        stmt = select(OPASidecarStatus).where(
            OPASidecarStatus.tenant_id == tenant.tenant_id,
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())


class BundleService:
    """Service for building and distributing OPA policy bundles.

    Implements Gap #199: assembles all active policies for a tenant into
    a .tar.gz bundle, computes an ETag for version negotiation, and
    tracks which bundles are loaded on each sidecar.

    Args:
        policy_session: Async session for querying active policies.
        sidecar_repo: Repository for OPASidecarStatus.
    """

    def __init__(
        self,
        policy_session: AsyncSession,
        sidecar_repo: OPASidecarStatusRepository,
    ) -> None:
        """Initialize BundleService.

        Args:
            policy_session: Async database session for policy queries.
            sidecar_repo: OPASidecarStatusRepository instance.
        """
        self._session = policy_session
        self._sidecar_repo = sidecar_repo

    async def build_bundle(
        self,
        tenant: TenantContext,
    ) -> tuple[bytes, str]:
        """Build a .tar.gz bundle of all active policies for a tenant.

        The bundle contains one .rego file per active policy, organized
        under a data/ directory. The ETag is computed as SHA-256 of the
        bundle content for version negotiation.

        Args:
            tenant: The tenant context.

        Returns:
            Tuple of (bundle_bytes, etag) where bundle_bytes is the
            gzipped tar archive and etag is the SHA-256 hex digest.
        """
        # Fetch all active policies
        stmt = select(GovernancePolicy).where(
            GovernancePolicy.tenant_id == tenant.tenant_id,
            GovernancePolicy.status == "active",
            GovernancePolicy.policy_type == "opa_rego",
        )
        result = await self._session.execute(stmt)
        active_policies = list(result.scalars().all())

        # Build in-memory tar.gz
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            # Add a manifest file
            manifest: dict[str, Any] = {
                "tenant_id": str(tenant.tenant_id),
                "policy_count": len(active_policies),
                "built_at": datetime.now(UTC).isoformat(),
                "policies": [
                    {
                        "id": str(p.id),
                        "name": p.name,
                        "version": p.version,
                    }
                    for p in active_policies
                ],
            }
            manifest_bytes = json.dumps(manifest, indent=2).encode()
            manifest_info = tarfile.TarInfo(name=".manifest.json")
            manifest_info.size = len(manifest_bytes)
            tar.addfile(manifest_info, io.BytesIO(manifest_bytes))

            # Add each policy as a .rego file
            for policy in active_policies:
                if not policy.rego_content:
                    continue
                rego_bytes = policy.rego_content.encode()
                safe_name = policy.name.replace(" ", "_").replace("/", "_")
                file_name = f"data/{safe_name}_{policy.id}.rego"
                info = tarfile.TarInfo(name=file_name)
                info.size = len(rego_bytes)
                tar.addfile(info, io.BytesIO(rego_bytes))

        bundle_bytes = buf.getvalue()
        etag = hashlib.sha256(bundle_bytes).hexdigest()

        logger.info(
            "Built OPA bundle",
            tenant_id=str(tenant.tenant_id),
            policy_count=len(active_policies),
            bundle_size_bytes=len(bundle_bytes),
            etag=etag[:8],
        )
        return bundle_bytes, etag

    async def get_bundle_status(
        self,
        tenant: TenantContext,
    ) -> dict[str, Any]:
        """Get the current bundle status for a tenant.

        Computes the current ETag from active policies and returns
        all sidecar status records.

        Args:
            tenant: The tenant context.

        Returns:
            Dict with current_etag, sidecar_count, and sidecar_statuses.
        """
        _, current_etag = await self.build_bundle(tenant)
        sidecars = await self._sidecar_repo.list_all(tenant)

        return {
            "current_bundle_etag": current_etag,
            "sidecar_count": len(sidecars),
            "sidecars": [
                {
                    "sidecar_name": s.sidecar_name,
                    "opa_version": s.opa_version,
                    "is_healthy": s.is_healthy,
                    "loaded_bundle_etag": s.bundle_etag,
                    "is_up_to_date": s.bundle_etag == current_etag,
                    "last_health_check_at": (
                        s.last_health_check_at.isoformat()
                        if s.last_health_check_at
                        else None
                    ),
                }
                for s in sidecars
            ],
        }
