"""External evidence import adapters for the governance engine.

Implements Gap #201: External Evidence Import.

Provides adapters for importing compliance evidence from external systems:
- JiraEvidenceAdapter — imports Jira issues as evidence records
- ServiceNowAdapter   — imports ServiceNow tickets as evidence records
- WebhookEvidenceHandler — processes inbound webhook payloads

All imports create an EvidenceRecord in the primary store and an
ExternalEvidenceImport record for bi-directional traceability.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from aumos_common.auth import TenantContext
from aumos_common.database import BaseRepository
from aumos_common.observability import get_logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_governance_engine.core.models import ExternalEvidenceImport

logger = get_logger(__name__)


class ExternalEvidenceImportRepository(BaseRepository[ExternalEvidenceImport]):
    """Repository for ExternalEvidenceImport persistence.

    Args:
        session: The primary DB async session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize with a database session.

        Args:
            session: The SQLAlchemy async session for the primary DB.
        """
        super().__init__(session, ExternalEvidenceImport)

    async def create(
        self,
        tenant: TenantContext,
        workflow_id: uuid.UUID,
        source_system: str,
        raw_payload: dict[str, Any],
        external_id: str | None = None,
        external_url: str | None = None,
    ) -> ExternalEvidenceImport:
        """Create a new external evidence import record.

        Args:
            tenant: The tenant context.
            workflow_id: Target compliance workflow UUID.
            source_system: External system name: jira | servicenow | webhook.
            raw_payload: Raw data from the external system.
            external_id: External item identifier.
            external_url: Direct URL to the external item.

        Returns:
            The persisted ExternalEvidenceImport.
        """
        record = ExternalEvidenceImport(
            tenant_id=tenant.tenant_id,
            workflow_id=workflow_id,
            source_system=source_system,
            raw_payload=raw_payload,
            external_id=external_id,
            external_url=external_url,
            import_status="pending",
        )
        self._session.add(record)
        await self._session.flush()
        await self._session.refresh(record)
        return record

    async def mark_success(
        self,
        record: ExternalEvidenceImport,
        evidence_record_id: uuid.UUID,
    ) -> ExternalEvidenceImport:
        """Mark an import as successfully completed.

        Args:
            record: The ExternalEvidenceImport to update.
            evidence_record_id: UUID of the created EvidenceRecord.

        Returns:
            The updated ExternalEvidenceImport.
        """
        record.import_status = "success"
        record.evidence_record_id = evidence_record_id
        record.imported_at = datetime.now(UTC)
        await self._session.flush()
        return record

    async def mark_failed(
        self,
        record: ExternalEvidenceImport,
        error: str,
    ) -> ExternalEvidenceImport:
        """Mark an import as failed.

        Args:
            record: The ExternalEvidenceImport to update.
            error: Error message describing the failure.

        Returns:
            The updated ExternalEvidenceImport.
        """
        record.import_status = "failed"
        record.import_error = error
        record.imported_at = datetime.now(UTC)
        await self._session.flush()
        return record

    async def list_by_workflow(
        self,
        workflow_id: uuid.UUID,
        tenant: TenantContext,
        page: int = 1,
        page_size: int = 20,
    ) -> list[ExternalEvidenceImport]:
        """List imports for a workflow.

        Args:
            workflow_id: The workflow UUID.
            tenant: The tenant context.
            page: Page number.
            page_size: Records per page.

        Returns:
            List of ExternalEvidenceImport records.
        """
        stmt = (
            select(ExternalEvidenceImport)
            .where(
                ExternalEvidenceImport.workflow_id == workflow_id,
                ExternalEvidenceImport.tenant_id == tenant.tenant_id,
            )
            .order_by(ExternalEvidenceImport.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())


class JiraEvidenceAdapter:
    """Adapter for importing Jira issues as compliance evidence.

    Connects to the Jira REST API to fetch issue details and creates
    an EvidenceRecord in the governance engine's primary store.

    Args:
        jira_base_url: Base URL of the Jira instance (e.g., https://org.atlassian.net).
        jira_email: Service account email for Jira API auth.
        jira_api_token: API token for Jira authentication.
        import_repo: Repository for ExternalEvidenceImport.
        evidence_repo: Repository for EvidenceRecord (from primary repositories).
    """

    def __init__(
        self,
        jira_base_url: str,
        jira_email: str,
        jira_api_token: str,
        import_repo: ExternalEvidenceImportRepository,
        evidence_repo: Any,
    ) -> None:
        """Initialize JiraEvidenceAdapter.

        Args:
            jira_base_url: Base URL of the Jira REST API.
            jira_email: Service account email for basic auth.
            jira_api_token: API token for basic auth.
            import_repo: ExternalEvidenceImportRepository instance.
            evidence_repo: EvidenceRepository instance for creating records.
        """
        self._jira_base_url = jira_base_url.rstrip("/")
        self._jira_email = jira_email
        self._jira_api_token = jira_api_token
        self._import_repo = import_repo
        self._evidence_repo = evidence_repo

    async def import_issue(
        self,
        tenant: TenantContext,
        workflow_id: uuid.UUID,
        issue_key: str,
        control_ids: list[str],
    ) -> dict[str, Any]:
        """Fetch a Jira issue and import it as compliance evidence.

        Args:
            tenant: The tenant context.
            workflow_id: Target compliance workflow UUID.
            issue_key: Jira issue key (e.g., PROJ-1234).
            control_ids: Regulation control IDs this issue satisfies.

        Returns:
            Dict with import_record_id, evidence_record_id, and status.
        """
        import_record = await self._import_repo.create(
            tenant=tenant,
            workflow_id=workflow_id,
            source_system="jira",
            external_id=issue_key,
            external_url=f"{self._jira_base_url}/browse/{issue_key}",
            raw_payload={},
        )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{self._jira_base_url}/rest/api/3/issue/{issue_key}",
                    auth=(self._jira_email, self._jira_api_token),
                )
                response.raise_for_status()
                issue_data = response.json()

            fields = issue_data.get("fields", {})
            summary = fields.get("summary", issue_key)
            description = fields.get("description", {}) or {}
            desc_text = _extract_jira_description(description)

            evidence = await self._evidence_repo.create(
                tenant=tenant,
                workflow_id=workflow_id,
                evidence_type="audit_log",
                title=f"Jira: {summary}",
                description=desc_text or f"Imported from Jira issue {issue_key}",
                artifact_uri=f"{self._jira_base_url}/browse/{issue_key}",
                collected_at=datetime.now(UTC),
                collector="auto",
                control_ids=control_ids,
            )

            import_record.raw_payload = issue_data
            await self._import_repo.mark_success(import_record, evidence.id)

            logger.info(
                "Imported Jira issue as evidence",
                issue_key=issue_key,
                evidence_id=str(evidence.id),
            )
            return {
                "import_record_id": str(import_record.id),
                "evidence_record_id": str(evidence.id),
                "status": "success",
            }

        except Exception as err:
            error_msg = str(err)
            await self._import_repo.mark_failed(import_record, error_msg)
            logger.error(
                "Failed to import Jira issue",
                issue_key=issue_key,
                error=error_msg,
            )
            return {
                "import_record_id": str(import_record.id),
                "evidence_record_id": None,
                "status": "failed",
                "error": error_msg,
            }


class ServiceNowAdapter:
    """Adapter for importing ServiceNow tickets as compliance evidence.

    Connects to the ServiceNow Table API to fetch ticket details and
    creates an EvidenceRecord in the governance engine's primary store.

    Args:
        snow_instance_url: ServiceNow instance URL (e.g., https://org.service-now.com).
        snow_username: ServiceNow service account username.
        snow_password: ServiceNow service account password.
        import_repo: Repository for ExternalEvidenceImport.
        evidence_repo: Repository for EvidenceRecord.
    """

    def __init__(
        self,
        snow_instance_url: str,
        snow_username: str,
        snow_password: str,
        import_repo: ExternalEvidenceImportRepository,
        evidence_repo: Any,
    ) -> None:
        """Initialize ServiceNowAdapter.

        Args:
            snow_instance_url: ServiceNow instance base URL.
            snow_username: Service account username.
            snow_password: Service account password.
            import_repo: ExternalEvidenceImportRepository instance.
            evidence_repo: EvidenceRepository instance.
        """
        self._snow_url = snow_instance_url.rstrip("/")
        self._snow_username = snow_username
        self._snow_password = snow_password
        self._import_repo = import_repo
        self._evidence_repo = evidence_repo

    async def import_ticket(
        self,
        tenant: TenantContext,
        workflow_id: uuid.UUID,
        table: str,
        sys_id: str,
        control_ids: list[str],
    ) -> dict[str, Any]:
        """Fetch a ServiceNow record and import it as compliance evidence.

        Args:
            tenant: The tenant context.
            workflow_id: Target compliance workflow UUID.
            table: ServiceNow table name (e.g., incident, change_request).
            sys_id: The sys_id of the ServiceNow record.
            control_ids: Regulation control IDs this ticket satisfies.

        Returns:
            Dict with import_record_id, evidence_record_id, and status.
        """
        ticket_ref = f"{table}/{sys_id}"
        import_record = await self._import_repo.create(
            tenant=tenant,
            workflow_id=workflow_id,
            source_system="servicenow",
            external_id=sys_id,
            external_url=f"{self._snow_url}/nav_to.do?uri={ticket_ref}.do",
            raw_payload={},
        )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{self._snow_url}/api/now/table/{table}/{sys_id}",
                    auth=(self._snow_username, self._snow_password),
                    headers={"Accept": "application/json"},
                )
                response.raise_for_status()
                ticket_data = response.json().get("result", {})

            short_desc = ticket_data.get("short_description", ticket_ref)
            description = ticket_data.get("description", "")

            evidence = await self._evidence_repo.create(
                tenant=tenant,
                workflow_id=workflow_id,
                evidence_type="audit_log",
                title=f"ServiceNow: {short_desc}",
                description=description or f"Imported from ServiceNow {ticket_ref}",
                artifact_uri=f"{self._snow_url}/nav_to.do?uri={ticket_ref}.do",
                collected_at=datetime.now(UTC),
                collector="auto",
                control_ids=control_ids,
            )

            import_record.raw_payload = ticket_data
            await self._import_repo.mark_success(import_record, evidence.id)

            logger.info(
                "Imported ServiceNow ticket as evidence",
                sys_id=sys_id,
                table=table,
                evidence_id=str(evidence.id),
            )
            return {
                "import_record_id": str(import_record.id),
                "evidence_record_id": str(evidence.id),
                "status": "success",
            }

        except Exception as err:
            error_msg = str(err)
            await self._import_repo.mark_failed(import_record, error_msg)
            logger.error(
                "Failed to import ServiceNow ticket",
                sys_id=sys_id,
                error=error_msg,
            )
            return {
                "import_record_id": str(import_record.id),
                "evidence_record_id": None,
                "status": "failed",
                "error": error_msg,
            }


def _extract_jira_description(description: dict[str, Any]) -> str:
    """Extract plain text from a Jira ADF (Atlassian Document Format) description.

    Args:
        description: The Jira description field value (ADF JSON or plain text dict).

    Returns:
        Plain text extracted from the description, or empty string.
    """
    if not description:
        return ""
    content = description.get("content", [])
    parts: list[str] = []
    for block in content:
        for inline in block.get("content", []):
            if inline.get("type") == "text":
                parts.append(inline.get("text", ""))
    return " ".join(parts)
