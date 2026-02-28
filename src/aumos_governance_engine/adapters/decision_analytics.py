"""Decision log analytics adapter for the governance engine.

Implements Gap #197: Decision Log Analytics.

Persists every OPA policy evaluation to gov_policy_evaluation_logs and
provides DecisionAnalyticsService for querying aggregated metrics,
latency percentiles, and violation trends with Redis-based caching.
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from aumos_common.auth import TenantContext
from aumos_common.database import BaseRepository
from aumos_common.observability import get_logger
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_governance_engine.core.models import PolicyEvaluationLog

logger = get_logger(__name__)

_CACHE_TTL_SECONDS = 300  # 5-minute analytics cache


class PolicyEvaluationLogRepository(BaseRepository[PolicyEvaluationLog]):
    """Repository for PolicyEvaluationLog persistence.

    Args:
        session: The primary DB async session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize with a database session.

        Args:
            session: The SQLAlchemy async session for the primary DB.
        """
        super().__init__(session, PolicyEvaluationLog)

    async def append(
        self,
        tenant: TenantContext,
        policy_id: uuid.UUID,
        input_data: dict[str, Any],
        allow_result: bool,
        violations: list[str],
        latency_ms: float,
        actor_id: uuid.UUID | None = None,
        correlation_id: str | None = None,
    ) -> PolicyEvaluationLog:
        """Append an evaluation decision to the log.

        Hashes the input_data (SHA-256) for privacy — raw inputs are never
        stored. This enables deduplication and caching without PII exposure.

        Args:
            tenant: The tenant context.
            policy_id: The evaluated policy UUID.
            input_data: The raw input payload (hashed before storage).
            allow_result: Whether the policy allowed the request.
            violations: Violation strings from OPA.
            latency_ms: Evaluation latency in milliseconds.
            actor_id: Optional UUID of the triggering actor.
            correlation_id: Optional request correlation ID.

        Returns:
            The persisted PolicyEvaluationLog.
        """
        input_hash = hashlib.sha256(
            json.dumps(input_data, sort_keys=True).encode()
        ).hexdigest()

        log_entry = PolicyEvaluationLog(
            tenant_id=tenant.tenant_id,
            policy_id=policy_id,
            input_hash=input_hash,
            allow_result=allow_result,
            violations=violations,
            latency_ms=latency_ms,
            evaluated_at=datetime.now(UTC),
            actor_id=actor_id,
            correlation_id=correlation_id,
        )
        self._session.add(log_entry)
        await self._session.flush()
        return log_entry

    async def get_summary(
        self,
        tenant: TenantContext,
        policy_id: uuid.UUID,
        since: datetime | None = None,
    ) -> dict[str, Any]:
        """Aggregate decision summary for a policy.

        Args:
            tenant: The tenant context.
            policy_id: The policy UUID.
            since: Optional start of time range (defaults to 7 days ago).

        Returns:
            Dict with total_evaluations, allow_count, deny_count,
            allow_rate, avg_latency_ms.
        """
        if since is None:
            since = datetime.now(UTC) - timedelta(days=7)

        base = select(PolicyEvaluationLog).where(
            PolicyEvaluationLog.policy_id == policy_id,
            PolicyEvaluationLog.tenant_id == tenant.tenant_id,
            PolicyEvaluationLog.evaluated_at >= since,
        )

        total_stmt = select(func.count()).select_from(base.subquery())
        allow_stmt = select(func.count()).select_from(
            base.where(PolicyEvaluationLog.allow_result == True).subquery()  # noqa: E712
        )
        avg_lat_stmt = select(func.avg(PolicyEvaluationLog.latency_ms)).select_from(
            base.subquery()
        )

        total_res, allow_res, avg_lat_res = await self._session.execute(
            total_stmt
        ), await self._session.execute(allow_stmt), await self._session.execute(avg_lat_stmt)

        total = total_res.scalar() or 0
        allows = allow_res.scalar() or 0
        avg_latency = float(avg_lat_res.scalar() or 0.0)
        denies = total - allows

        return {
            "policy_id": str(policy_id),
            "total_evaluations": total,
            "allow_count": allows,
            "deny_count": denies,
            "allow_rate": round(allows / total, 4) if total > 0 else 0.0,
            "avg_latency_ms": round(avg_latency, 2),
            "since": since.isoformat(),
        }

    async def get_latency_percentiles(
        self,
        tenant: TenantContext,
        policy_id: uuid.UUID,
        since: datetime | None = None,
    ) -> dict[str, float]:
        """Compute P50/P95/P99 latency percentiles using PostgreSQL percentile_cont.

        Args:
            tenant: The tenant context.
            policy_id: The policy UUID.
            since: Optional start of time range (defaults to 24 hours).

        Returns:
            Dict with p50, p95, p99 latency values in milliseconds.
        """
        if since is None:
            since = datetime.now(UTC) - timedelta(hours=24)

        raw = text(
            """
            SELECT
                percentile_cont(0.50) WITHIN GROUP (ORDER BY latency_ms) AS p50,
                percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95,
                percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms) AS p99
            FROM gov_policy_evaluation_logs
            WHERE tenant_id = :tenant_id
              AND policy_id = :policy_id
              AND evaluated_at >= :since
            """
        )
        result = await self._session.execute(
            raw,
            {
                "tenant_id": str(tenant.tenant_id),
                "policy_id": str(policy_id),
                "since": since,
            },
        )
        row = result.fetchone()
        if row is None or row[0] is None:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0}
        return {
            "p50": round(float(row[0]), 2),
            "p95": round(float(row[1]), 2),
            "p99": round(float(row[2]), 2),
        }


class DecisionAnalyticsService:
    """Service providing analytics over the policy decision log.

    Implements Gap #197: aggregated metrics with Redis caching so analytics
    queries do not hit the hot-path database on every request.

    Args:
        eval_log_repo: PolicyEvaluationLogRepository for raw queries.
        redis_client: Optional Redis client for caching analytics results.
    """

    def __init__(
        self,
        eval_log_repo: PolicyEvaluationLogRepository,
        redis_client: Any | None = None,
    ) -> None:
        """Initialize DecisionAnalyticsService.

        Args:
            eval_log_repo: Repository for policy evaluation log queries.
            redis_client: Optional Redis client (if None, caching is disabled).
        """
        self._eval_log_repo = eval_log_repo
        self._redis = redis_client

    async def get_decision_summary(
        self,
        tenant: TenantContext,
        policy_id: uuid.UUID,
        since: datetime | None = None,
    ) -> dict[str, Any]:
        """Get an aggregated decision summary for a policy.

        Results are cached in Redis for 5 minutes when redis_client is provided.

        Args:
            tenant: The tenant context.
            policy_id: The policy UUID.
            since: Optional start of time range.

        Returns:
            Decision summary dict with total_evaluations, allow/deny counts,
            allow_rate, and avg_latency_ms.
        """
        cache_key = f"gov:analytics:summary:{tenant.tenant_id}:{policy_id}"
        if self._redis:
            try:
                cached = await self._redis.get(cache_key)
                if cached:
                    return json.loads(cached)
            except Exception as cache_err:
                logger.warning("Redis cache read failed", error=str(cache_err))

        summary = await self._eval_log_repo.get_summary(
            tenant=tenant,
            policy_id=policy_id,
            since=since,
        )

        if self._redis:
            try:
                await self._redis.setex(
                    cache_key,
                    _CACHE_TTL_SECONDS,
                    json.dumps(summary),
                )
            except Exception as cache_err:
                logger.warning("Redis cache write failed", error=str(cache_err))

        return summary

    async def get_latency_percentiles(
        self,
        tenant: TenantContext,
        policy_id: uuid.UUID,
        since: datetime | None = None,
    ) -> dict[str, float]:
        """Get P50/P95/P99 evaluation latency percentiles.

        Args:
            tenant: The tenant context.
            policy_id: The policy UUID.
            since: Optional start of time range.

        Returns:
            Dict with p50, p95, p99 in milliseconds.
        """
        cache_key = f"gov:analytics:latency:{tenant.tenant_id}:{policy_id}"
        if self._redis:
            try:
                cached = await self._redis.get(cache_key)
                if cached:
                    return json.loads(cached)
            except Exception as cache_err:
                logger.warning("Redis cache read failed", error=str(cache_err))

        percentiles = await self._eval_log_repo.get_latency_percentiles(
            tenant=tenant,
            policy_id=policy_id,
            since=since,
        )

        if self._redis:
            try:
                await self._redis.setex(
                    cache_key,
                    _CACHE_TTL_SECONDS,
                    json.dumps(percentiles),
                )
            except Exception as cache_err:
                logger.warning("Redis cache write failed", error=str(cache_err))

        return percentiles
