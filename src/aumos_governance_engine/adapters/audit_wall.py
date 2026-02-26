"""Audit Wall — separate PostgreSQL connection for the immutable audit trail.

This module is the ONLY place that connects to AUMOS_GOVERNANCE_AUDIT_DB_URL.
All other modules must use the primary DB session from aumos_common.database.

The Audit Wall uses a physically separate PostgreSQL instance with INSERT-only
credentials on gov_audit_trail_entries. No UPDATE or DELETE operations are
possible at either the application or database level.

Key exports:
- init_audit_db(...)       — Call at startup to initialize the audit engine
- close_audit_db()         — Call at shutdown to dispose the engine
- get_audit_db_session()   — FastAPI dependency for audit DB sessions
- AuditTrailRepository     — Repository with append-only write + read operations
"""

import uuid
from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, AsyncEngine, async_sessionmaker, create_async_engine

from aumos_common.auth import TenantContext
from aumos_common.errors import NotFoundError
from aumos_common.observability import get_logger

from aumos_governance_engine.core.models import AuditTrailEntry

logger = get_logger(__name__)

# Module-level engine and session factory — initialized by init_audit_db()
_audit_engine: AsyncEngine | None = None
_audit_session_factory: async_sessionmaker[AsyncSession] | None = None


async def init_audit_db(
    audit_db_url: str,
    pool_size: int = 5,
    max_overflow: int = 2,
    pool_timeout: int = 30,
) -> None:
    """Initialize the Audit Wall database engine and session factory.

    Must be called once at application startup (in the lifespan handler)
    before any audit trail writes can occur.

    Args:
        audit_db_url: PostgreSQL connection URL for the separate audit database.
            Must point to a different server than the primary DB.
        pool_size: Connection pool size.
        max_overflow: Max overflow connections above pool_size.
        pool_timeout: Seconds to wait for a connection before raising.
    """
    global _audit_engine, _audit_session_factory  # noqa: PLW0603

    logger.info(
        "Initializing Audit Wall engine",
        pool_size=pool_size,
        max_overflow=max_overflow,
    )

    _audit_engine = create_async_engine(
        audit_db_url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
        # Echo is explicitly disabled — audit queries must not log values
        echo=False,
        pool_pre_ping=True,
    )

    _audit_session_factory = async_sessionmaker(
        bind=_audit_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )

    logger.info("Audit Wall engine initialized")


async def close_audit_db() -> None:
    """Dispose the Audit Wall database engine.

    Must be called at application shutdown. After this call, no further
    audit trail writes can occur until init_audit_db() is called again.
    """
    global _audit_engine  # noqa: PLW0603

    if _audit_engine is not None:
        logger.info("Disposing Audit Wall engine")
        await _audit_engine.dispose()
        _audit_engine = None


async def get_audit_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an Audit Wall database session.

    This is the ONLY way to obtain a session for the audit database.
    Never create an audit DB session directly — always use this dependency.

    Yields:
        AsyncSession: A session connected to the Audit Wall database.

    Raises:
        RuntimeError: If init_audit_db() has not been called yet.
    """
    if _audit_session_factory is None:
        raise RuntimeError(
            "Audit Wall database has not been initialized. "
            "Call init_audit_db() in the application lifespan handler."
        )

    async with _audit_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


class AuditTrailRepository:
    """Append-only repository for AuditTrailEntry on the Audit Wall database.

    IMPORTANT: This repository connects to the SEPARATE Audit Wall PostgreSQL
    instance, not the primary database. It has no update() or delete() methods
    because the audit trail is immutable.

    The insert-only pattern is enforced at both the application level (this class
    has no mutation methods beyond append()) and at the database level (the
    PostgreSQL role used by AUMOS_GOVERNANCE_AUDIT_DB_URL should have only
    INSERT and SELECT grants on gov_audit_trail_entries in production).

    Args:
        session: An audit DB session from get_audit_db_session().
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize AuditTrailRepository with an audit DB session.

        Args:
            session: A SQLAlchemy async session connected to the Audit Wall DB.
        """
        self._session = session

    async def append(
        self,
        tenant_id: uuid.UUID,
        event_type: str,
        actor_id: uuid.UUID,
        resource_type: str,
        resource_id: uuid.UUID,
        action: str,
        details: dict[str, Any],
        timestamp: datetime,
        correlation_id: str | None = None,
    ) -> AuditTrailEntry:
        """Append an immutable audit trail entry to the Audit Wall.

        This is the ONLY write operation on the audit trail. No update()
        or delete() methods exist on this class. The entry is permanent
        once committed.

        Args:
            tenant_id: Owning tenant UUID.
            event_type: Dot-notation event type.
            actor_id: UUID of the actor.
            resource_type: Type of the affected resource.
            resource_id: UUID of the affected resource.
            action: Short action verb.
            details: Event-specific payload.
            timestamp: Event timestamp (UTC).
            correlation_id: Optional request correlation ID.

        Returns:
            The persisted AuditTrailEntry from the Audit Wall.
        """
        entry = AuditTrailEntry(
            tenant_id=tenant_id,
            event_type=event_type,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            details=details,
            timestamp=timestamp,
            source_service="aumos-governance-engine",
            correlation_id=correlation_id,
        )
        self._session.add(entry)
        await self._session.flush()
        await self._session.refresh(entry)

        logger.info(
            "Audit trail entry written",
            entry_id=str(entry.id),
            event_type=event_type,
            tenant_id=str(tenant_id),
            resource_type=resource_type,
            resource_id=str(resource_id),
            action=action,
        )

        return entry

    async def query(
        self,
        tenant: TenantContext,
        event_type_filter: str | None = None,
        resource_type_filter: str | None = None,
        resource_id_filter: uuid.UUID | None = None,
        actor_id_filter: uuid.UUID | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[AuditTrailEntry]:
        """Query the immutable audit trail with filters.

        Read operations are allowed on the audit trail. The query enforces
        tenant isolation — users only see entries for their own tenant.

        Args:
            tenant: The tenant context.
            event_type_filter: Optional event type prefix filter (startswith match).
            resource_type_filter: Optional exact resource type filter.
            resource_id_filter: Optional specific resource UUID.
            actor_id_filter: Optional specific actor UUID.
            start_time: Optional start of time range.
            end_time: Optional end of time range.
            page: Page number (1-indexed).
            page_size: Records per page.

        Returns:
            List of AuditTrailEntry records ordered by timestamp descending.
        """
        stmt = select(AuditTrailEntry).where(
            AuditTrailEntry.tenant_id == tenant.tenant_id,
        )

        if event_type_filter:
            stmt = stmt.where(AuditTrailEntry.event_type.startswith(event_type_filter))
        if resource_type_filter:
            stmt = stmt.where(AuditTrailEntry.resource_type == resource_type_filter)
        if resource_id_filter:
            stmt = stmt.where(AuditTrailEntry.resource_id == resource_id_filter)
        if actor_id_filter:
            stmt = stmt.where(AuditTrailEntry.actor_id == actor_id_filter)
        if start_time:
            stmt = stmt.where(AuditTrailEntry.timestamp >= start_time)
        if end_time:
            stmt = stmt.where(AuditTrailEntry.timestamp <= end_time)

        stmt = stmt.order_by(AuditTrailEntry.timestamp.desc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)

        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_id(
        self,
        entry_id: uuid.UUID,
        tenant: TenantContext,
    ) -> AuditTrailEntry:
        """Retrieve a single audit trail entry by ID.

        Args:
            entry_id: The audit trail entry UUID.
            tenant: The tenant context (enforces isolation).

        Returns:
            The AuditTrailEntry.

        Raises:
            NotFoundError: If not found.
        """
        stmt = select(AuditTrailEntry).where(
            AuditTrailEntry.id == entry_id,
            AuditTrailEntry.tenant_id == tenant.tenant_id,
        )
        result = await self._session.execute(stmt)
        entry = result.scalar_one_or_none()
        if entry is None:
            raise NotFoundError(resource="AuditTrailEntry", resource_id=str(entry_id))
        return entry
