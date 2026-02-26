"""GovernanceEventPublisher — Kafka domain event publishing for governance events.

Publishes structured governance domain events to Kafka topics after every
state-changing operation. Extends EventPublisher from aumos-common and adds
governance-specific event types.

Events published:
- governance.policy.created          — new policy created
- governance.policy.activated        — policy pushed to OPA and set active
- governance.policy.evaluated        — policy evaluation completed
- governance.compliance.workflow.created      — new compliance workflow
- governance.compliance.workflow.status_changed — workflow state transition
- governance.evidence.submitted      — new evidence record

All events include tenant_id and correlation_id for distributed tracing.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from aumos_common.events import EventPublisher
from aumos_common.observability import get_logger

logger = get_logger(__name__)

# Kafka topic names for governance events
TOPIC_GOVERNANCE_POLICY = "governance.policy"
TOPIC_GOVERNANCE_COMPLIANCE = "governance.compliance"
TOPIC_GOVERNANCE_EVIDENCE = "governance.evidence"
TOPIC_GOVERNANCE_AUDIT = "governance.audit"

# Default bootstrap servers (overridden by settings)
_DEFAULT_BOOTSTRAP_SERVERS = "localhost:9092"


class GovernanceEventPublisher:
    """Kafka event publisher for governance domain events.

    Wraps aumos-common EventPublisher and provides governance-specific
    publish methods with strongly typed event payloads.

    Args:
        bootstrap_servers: Comma-separated Kafka bootstrap server addresses.
    """

    def __init__(
        self,
        bootstrap_servers: str = _DEFAULT_BOOTSTRAP_SERVERS,
    ) -> None:
        """Initialize GovernanceEventPublisher.

        Args:
            bootstrap_servers: Kafka bootstrap servers.
        """
        self._bootstrap_servers = bootstrap_servers
        self._publisher: EventPublisher | None = None

    async def start(self) -> None:
        """Initialize the underlying Kafka producer.

        Must be called before any publish methods. Called in the lifespan
        startup handler in main.py.
        """
        self._publisher = EventPublisher(bootstrap_servers=self._bootstrap_servers)
        await self._publisher.start()
        logger.info("GovernanceEventPublisher started", bootstrap_servers=self._bootstrap_servers)

    async def stop(self) -> None:
        """Flush and close the Kafka producer.

        Must be called at application shutdown to ensure all buffered
        events are sent before the process exits.
        """
        if self._publisher is not None:
            await self._publisher.stop()
            logger.info("GovernanceEventPublisher stopped")

    def _build_envelope(
        self,
        event_type: str,
        tenant_id: uuid.UUID,
        payload: dict[str, Any],
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Build a standard governance event envelope.

        Args:
            event_type: Dot-notation event type string.
            tenant_id: Owning tenant UUID.
            payload: Event-specific data payload.
            correlation_id: Optional request correlation ID.

        Returns:
            Structured event envelope dict ready for Kafka.
        """
        return {
            "event_type": event_type,
            "tenant_id": str(tenant_id),
            "source_service": "aumos-governance-engine",
            "occurred_at": datetime.now(UTC).isoformat(),
            "correlation_id": correlation_id,
            "payload": payload,
        }

    async def publish_policy_created(
        self,
        tenant_id: uuid.UUID,
        policy_id: uuid.UUID,
        policy_name: str,
        policy_type: str,
        regulation_refs: list[str],
        correlation_id: str | None = None,
    ) -> None:
        """Publish a governance.policy.created event.

        Args:
            tenant_id: Owning tenant UUID.
            policy_id: New policy UUID.
            policy_name: Policy name.
            policy_type: Engine type.
            regulation_refs: Associated regulation codes.
            correlation_id: Optional request correlation ID.
        """
        event = self._build_envelope(
            event_type="governance.policy.created",
            tenant_id=tenant_id,
            payload={
                "policy_id": str(policy_id),
                "policy_name": policy_name,
                "policy_type": policy_type,
                "regulation_refs": regulation_refs,
            },
            correlation_id=correlation_id,
        )
        await self._publish(TOPIC_GOVERNANCE_POLICY, str(policy_id), event)

    async def publish_policy_activated(
        self,
        tenant_id: uuid.UUID,
        policy_id: uuid.UUID,
        policy_name: str,
        correlation_id: str | None = None,
    ) -> None:
        """Publish a governance.policy.activated event.

        Args:
            tenant_id: Owning tenant UUID.
            policy_id: Activated policy UUID.
            policy_name: Policy name.
            correlation_id: Optional request correlation ID.
        """
        event = self._build_envelope(
            event_type="governance.policy.activated",
            tenant_id=tenant_id,
            payload={
                "policy_id": str(policy_id),
                "policy_name": policy_name,
            },
            correlation_id=correlation_id,
        )
        await self._publish(TOPIC_GOVERNANCE_POLICY, str(policy_id), event)

    async def publish_policy_evaluated(
        self,
        tenant_id: uuid.UUID,
        policy_id: uuid.UUID,
        evaluation_result: bool,
        latency_ms: float,
        correlation_id: str | None = None,
    ) -> None:
        """Publish a governance.policy.evaluated event.

        Args:
            tenant_id: Owning tenant UUID.
            policy_id: Evaluated policy UUID.
            evaluation_result: True if policy allowed the action.
            latency_ms: OPA evaluation latency in milliseconds.
            correlation_id: Optional request correlation ID.
        """
        event = self._build_envelope(
            event_type="governance.policy.evaluated",
            tenant_id=tenant_id,
            payload={
                "policy_id": str(policy_id),
                "allowed": evaluation_result,
                "latency_ms": latency_ms,
            },
            correlation_id=correlation_id,
        )
        await self._publish(TOPIC_GOVERNANCE_POLICY, str(policy_id), event)

    async def publish_workflow_status_changed(
        self,
        tenant_id: uuid.UUID,
        workflow_id: uuid.UUID,
        regulation: str,
        old_status: str,
        new_status: str,
        correlation_id: str | None = None,
    ) -> None:
        """Publish a governance.compliance.workflow.status_changed event.

        Args:
            tenant_id: Owning tenant UUID.
            workflow_id: Workflow UUID.
            regulation: Regulation code.
            old_status: Previous status.
            new_status: New status.
            correlation_id: Optional request correlation ID.
        """
        event_type = "governance.compliance.workflow.created" if not old_status else "governance.compliance.workflow.status_changed"
        event = self._build_envelope(
            event_type=event_type,
            tenant_id=tenant_id,
            payload={
                "workflow_id": str(workflow_id),
                "regulation": regulation,
                "old_status": old_status,
                "new_status": new_status,
            },
            correlation_id=correlation_id,
        )
        await self._publish(TOPIC_GOVERNANCE_COMPLIANCE, str(workflow_id), event)

    async def publish_evidence_submitted(
        self,
        tenant_id: uuid.UUID,
        evidence_id: uuid.UUID,
        workflow_id: uuid.UUID,
        evidence_type: str,
        collector: str,
        correlation_id: str | None = None,
    ) -> None:
        """Publish a governance.evidence.submitted event.

        Args:
            tenant_id: Owning tenant UUID.
            evidence_id: Evidence record UUID.
            workflow_id: Associated workflow UUID.
            evidence_type: Evidence type classification.
            collector: auto or manual.
            correlation_id: Optional request correlation ID.
        """
        event = self._build_envelope(
            event_type="governance.evidence.submitted",
            tenant_id=tenant_id,
            payload={
                "evidence_id": str(evidence_id),
                "workflow_id": str(workflow_id),
                "evidence_type": evidence_type,
                "collector": collector,
            },
            correlation_id=correlation_id,
        )
        await self._publish(TOPIC_GOVERNANCE_EVIDENCE, str(evidence_id), event)

    async def _publish(
        self,
        topic: str,
        key: str,
        event: dict[str, Any],
    ) -> None:
        """Publish a structured event dict to a Kafka topic.

        If the publisher is not initialized (e.g., in tests), logs a warning
        and skips the publish rather than raising.

        Args:
            topic: Kafka topic name.
            key: Message partition key (typically a resource UUID string).
            event: Structured event payload dict.
        """
        if self._publisher is None:
            logger.warning(
                "GovernanceEventPublisher not started — skipping Kafka publish",
                topic=topic,
                event_type=event.get("event_type"),
            )
            return

        try:
            await self._publisher.publish(topic=topic, key=key, value=event)
            logger.debug(
                "Governance event published",
                topic=topic,
                event_type=event.get("event_type"),
                tenant_id=event.get("tenant_id"),
            )
        except Exception as exc:
            # Never let Kafka failures crash governance operations
            logger.error(
                "Failed to publish governance event",
                topic=topic,
                event_type=event.get("event_type"),
                error=str(exc),
            )
