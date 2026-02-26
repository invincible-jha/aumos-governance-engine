"""AumOS Governance Engine service entry point.

Initializes the FastAPI application with:
- Primary database for governance policies, workflows, and evidence
- Audit Wall database connection for immutable audit trail
- OPA client for Rego policy evaluation
- Kafka publisher for governance domain events
- Redis client for policy evaluation result caching
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from aumos_common.app import create_app
from aumos_common.database import init_database
from aumos_common.observability import get_logger

from aumos_governance_engine.adapters.audit_wall import init_audit_db, close_audit_db
from aumos_governance_engine.adapters.kafka import GovernanceEventPublisher
from aumos_governance_engine.adapters.opa_client import OPAClient
from aumos_governance_engine.api.router import router
from aumos_governance_engine.settings import Settings

logger = get_logger(__name__)

settings = Settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown lifecycle.

    Initializes primary database, audit Wall database, OPA client, and
    Kafka publisher on startup. Closes all connections on shutdown.

    Args:
        app: The FastAPI application instance.

    Yields:
        None
    """
    # Startup — primary database
    logger.info("Initializing primary database", service=settings.service_name)
    init_database(settings.database)

    # Startup — Audit Wall (separate PostgreSQL instance)
    logger.info(
        "Initializing Audit Wall database",
        service=settings.service_name,
        pool_size=settings.audit_db_pool_size,
    )
    await init_audit_db(
        audit_db_url=settings.audit_db_url,
        pool_size=settings.audit_db_pool_size,
        max_overflow=settings.audit_db_max_overflow,
        pool_timeout=settings.audit_db_pool_timeout,
    )

    # Startup — OPA client (verify connectivity)
    opa_client = OPAClient(
        opa_url=settings.opa_url,
        eval_timeout_ms=settings.policy_eval_timeout_ms,
        bundle_prefix=settings.opa_bundle_prefix,
    )
    is_opa_healthy = await opa_client.health_check()
    if not is_opa_healthy:
        logger.warning(
            "OPA is not reachable at startup — policy evaluation will fail until OPA is available",
            opa_url=settings.opa_url,
        )

    # Startup — Kafka publisher
    logger.info("Initializing Kafka publisher", bootstrap_servers=settings.kafka.bootstrap_servers)
    publisher = GovernanceEventPublisher(bootstrap_servers=settings.kafka.bootstrap_servers)
    await publisher.start()

    # Store shared clients on app state for dependency injection
    app.state.opa_client = opa_client
    app.state.kafka_publisher = publisher
    app.state.settings = settings

    logger.info("Governance engine startup complete", opa_url=settings.opa_url)

    yield

    # Shutdown
    logger.info("Shutting down governance engine")
    await publisher.stop()
    await close_audit_db()
    logger.info("Governance engine shutdown complete")


app: FastAPI = create_app(
    service_name="aumos-governance-engine",
    version="0.1.0",
    settings=settings,
    lifespan=lifespan,
    health_checks=[
        # HealthCheck(name="postgres", check_fn=check_primary_db),
        # HealthCheck(name="postgres-audit", check_fn=check_audit_db),
        # HealthCheck(name="opa", check_fn=check_opa),
        # HealthCheck(name="kafka", check_fn=check_kafka),
    ],
)

app.include_router(router, prefix="/api/v1")
