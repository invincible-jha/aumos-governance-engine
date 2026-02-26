"""Tests for API endpoints (router layer).

Tests the FastAPI routes by calling the service layer through dependency
injection overrides. Does not test service logic — that is in test_services.py.

Tests verify:
- Request validation (Pydantic schema enforcement)
- HTTP status codes
- Response schema shapes
- Auth dependency enforcement
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from aumos_governance_engine.api.router import (
    get_audit_service,
    get_compliance_service,
    get_evidence_service,
    get_policy_service,
    get_regulation_mapper_service,
    router,
)
from aumos_governance_engine.api.schemas import (
    ComplianceDashboardResponse,
    ComplianceWorkflowResponse,
    EvidenceRecordResponse,
    GovernancePolicyResponse,
    PolicyEvaluateResponse,
    RegulationListResponse,
)
from aumos_common.auth import get_current_user, TenantContext


def make_fake_policy_response(tenant_id: uuid.UUID) -> GovernancePolicyResponse:
    """Create a fake GovernancePolicyResponse for mock service return values."""
    return GovernancePolicyResponse(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        name="Test Policy",
        policy_type="opa_rego",
        rego_content="package test\ndefault allow = true",
        version=1,
        status="draft",
        regulation_refs=["iso42001"],
        description=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def make_fake_workflow_response(tenant_id: uuid.UUID) -> ComplianceWorkflowResponse:
    """Create a fake ComplianceWorkflowResponse for mock service return values."""
    return ComplianceWorkflowResponse(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        regulation="iso42001",
        name="ISO 42001 Assessment",
        status="initiated",
        evidence_count=0,
        last_assessment=None,
        next_due=None,
        assigned_to=None,
        notes=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def make_fake_evidence_response(tenant_id: uuid.UUID) -> EvidenceRecordResponse:
    """Create a fake EvidenceRecordResponse for mock service return values."""
    return EvidenceRecordResponse(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        workflow_id=uuid.uuid4(),
        evidence_type="audit_log",
        title="Test Evidence",
        description="Test description",
        artifact_uri="s3://bucket/test.json",
        collected_at=datetime.now(UTC),
        collector="manual",
        control_ids=["CC6.1"],
        status="pending_review",
        reviewed_by=None,
        reviewed_at=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


@pytest.fixture()
def test_app(mock_tenant: MagicMock) -> FastAPI:
    """Create a FastAPI test app with dependency overrides.

    Args:
        mock_tenant: The fake tenant context fixture.

    Returns:
        FastAPI app with mocked dependencies.
    """
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    # Override auth dependency
    app.dependency_overrides[get_current_user] = lambda: mock_tenant

    return app


@pytest.fixture()
def policy_service_mock(tenant_id: uuid.UUID) -> AsyncMock:
    """Create a mock PolicyService."""
    mock = AsyncMock()
    mock.create_policy.return_value = make_fake_policy_response(tenant_id)
    mock.get_policy.return_value = make_fake_policy_response(tenant_id)
    mock.list_policies.return_value = [make_fake_policy_response(tenant_id)]
    mock.activate_policy.return_value = make_fake_policy_response(tenant_id)
    mock.evaluate_policy.return_value = PolicyEvaluateResponse(
        policy_id=uuid.uuid4(),
        policy_name="Test Policy",
        allowed=True,
        violations=[],
        latency_ms=12.5,
        evaluated_at=datetime.now(UTC),
    )
    return mock


@pytest.fixture()
def compliance_service_mock(tenant_id: uuid.UUID) -> AsyncMock:
    """Create a mock ComplianceService."""
    mock = AsyncMock()
    mock.create_workflow.return_value = make_fake_workflow_response(tenant_id)
    mock.get_workflow.return_value = make_fake_workflow_response(tenant_id)
    mock.list_workflows.return_value = [make_fake_workflow_response(tenant_id)]
    mock.get_dashboard.return_value = ComplianceDashboardResponse(
        tenant_id=tenant_id,
        generated_at=datetime.now(UTC),
        regulations=[],
    )
    return mock


class TestPolicyEndpoints:
    """Tests for /policies endpoints."""

    @pytest.mark.asyncio()
    async def test_create_policy_returns_201(
        self,
        test_app: FastAPI,
        policy_service_mock: AsyncMock,
    ) -> None:
        """POST /policies with valid body returns 201 and policy response."""
        test_app.dependency_overrides[get_policy_service] = lambda: policy_service_mock

        async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/policies",
                json={
                    "name": "Model Promotion Gate",
                    "policy_type": "opa_rego",
                    "rego_content": "package test\ndefault allow = true",
                    "regulation_refs": ["iso42001"],
                },
            )

        assert response.status_code == 201
        body = response.json()
        assert body["name"] == "Test Policy"
        assert body["status"] == "draft"

    @pytest.mark.asyncio()
    async def test_create_policy_missing_name_returns_422(
        self,
        test_app: FastAPI,
        policy_service_mock: AsyncMock,
    ) -> None:
        """POST /policies without required name field returns 422."""
        test_app.dependency_overrides[get_policy_service] = lambda: policy_service_mock

        async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/policies",
                json={"policy_type": "opa_rego"},  # Missing name
            )

        assert response.status_code == 422

    @pytest.mark.asyncio()
    async def test_list_policies_returns_200(
        self,
        test_app: FastAPI,
        policy_service_mock: AsyncMock,
    ) -> None:
        """GET /policies returns 200 with list of policies."""
        test_app.dependency_overrides[get_policy_service] = lambda: policy_service_mock

        async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
            response = await client.get("/api/v1/policies")

        assert response.status_code == 200
        assert isinstance(response.json(), list)

    @pytest.mark.asyncio()
    async def test_evaluate_policy_returns_allow_decision(
        self,
        test_app: FastAPI,
        policy_service_mock: AsyncMock,
    ) -> None:
        """POST /policies/{id}/evaluate returns evaluation result."""
        test_app.dependency_overrides[get_policy_service] = lambda: policy_service_mock
        policy_id = uuid.uuid4()

        async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
            response = await client.post(
                f"/api/v1/policies/{policy_id}/evaluate",
                json={"input": {"model": {"risk_level": "low"}}},
            )

        assert response.status_code == 200
        body = response.json()
        assert "allowed" in body
        assert body["allowed"] is True


class TestComplianceEndpoints:
    """Tests for /compliance endpoints."""

    @pytest.mark.asyncio()
    async def test_create_workflow_returns_201(
        self,
        test_app: FastAPI,
        compliance_service_mock: AsyncMock,
    ) -> None:
        """POST /compliance/workflows returns 201 with workflow response."""
        test_app.dependency_overrides[get_compliance_service] = lambda: compliance_service_mock

        async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/compliance/workflows",
                json={
                    "regulation": "iso42001",
                    "name": "ISO 42001 Assessment 2026",
                },
            )

        assert response.status_code == 201
        body = response.json()
        assert body["regulation"] == "iso42001"
        assert body["status"] == "initiated"

    @pytest.mark.asyncio()
    async def test_dashboard_returns_200(
        self,
        test_app: FastAPI,
        compliance_service_mock: AsyncMock,
    ) -> None:
        """GET /compliance/dashboard returns 200 with dashboard summary."""
        test_app.dependency_overrides[get_compliance_service] = lambda: compliance_service_mock

        async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
            response = await client.get("/api/v1/compliance/dashboard")

        assert response.status_code == 200
        body = response.json()
        assert "regulations" in body
        assert "generated_at" in body


class TestAuditTrailEndpoints:
    """Tests for /audit-trail endpoint."""

    @pytest.mark.asyncio()
    async def test_query_audit_trail_returns_200(
        self,
        test_app: FastAPI,
    ) -> None:
        """GET /audit-trail returns 200 with list of entries."""
        mock_audit_service = AsyncMock()
        mock_audit_service.query_trail.return_value = []
        test_app.dependency_overrides[get_audit_service] = lambda: mock_audit_service

        async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
            response = await client.get("/api/v1/audit-trail")

        assert response.status_code == 200
        assert response.json() == []


class TestRegulationEndpoints:
    """Tests for /regulations endpoints."""

    @pytest.mark.asyncio()
    async def test_list_regulations_returns_all_six(
        self,
        test_app: FastAPI,
    ) -> None:
        """GET /regulations returns all six supported regulations."""
        mock_reg_service = MagicMock()
        mock_reg_service.list_regulations.return_value = RegulationListResponse(
            regulations=[
                {"code": "soc2", "name": "SOC 2 Type II", "full_name": "...", "issuing_body": "AICPA",
                 "scope": "...", "ai_specific": False},
                {"code": "iso42001", "name": "ISO 42001:2023", "full_name": "...", "issuing_body": "ISO/IEC",
                 "scope": "...", "ai_specific": True},
            ]
        )
        test_app.dependency_overrides[get_regulation_mapper_service] = lambda: mock_reg_service

        async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
            response = await client.get("/api/v1/regulations")

        assert response.status_code == 200
        body = response.json()
        assert "regulations" in body

    @pytest.mark.asyncio()
    async def test_get_regulation_controls_returns_mappings(
        self,
        test_app: FastAPI,
    ) -> None:
        """GET /regulations/{reg}/controls returns control mappings."""
        from aumos_governance_engine.api.schemas import RegulationControlResponse

        mock_reg_service = AsyncMock()
        mock_reg_service.get_controls.return_value = [
            RegulationControlResponse(
                regulation="soc2",
                article_ref="CC6.1",
                requirement_text="Logical access controls",
                control_ids=["ACCESS_CONTROL"],
                automated=True,
                notes=None,
            )
        ]
        test_app.dependency_overrides[get_regulation_mapper_service] = lambda: mock_reg_service

        async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
            response = await client.get("/api/v1/regulations/soc2/controls")

        assert response.status_code == 200
        body = response.json()
        assert isinstance(body, list)
        assert body[0]["article_ref"] == "CC6.1"
