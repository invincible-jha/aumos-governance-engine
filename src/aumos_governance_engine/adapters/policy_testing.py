"""Policy testing framework adapter for the governance engine.

Implements Gap #194: Rego Policy Testing Framework.

Provides PolicyTestService for creating and running test suites against
OPA Rego policies. Test execution is parallelized with asyncio.gather()
and each run is written to the Audit Wall for compliance traceability.
"""

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from aumos_common.auth import TenantContext
from aumos_common.database import BaseRepository
from aumos_common.errors import NotFoundError
from aumos_common.observability import get_logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_governance_engine.core.models import PolicyTestCase, PolicyTestRun

logger = get_logger(__name__)


class PolicyTestCaseRepository(BaseRepository[PolicyTestCase]):
    """Repository for PolicyTestCase persistence.

    Args:
        session: The primary DB async session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize with a database session.

        Args:
            session: The SQLAlchemy async session for the primary DB.
        """
        super().__init__(session, PolicyTestCase)

    async def create(
        self,
        tenant: TenantContext,
        policy_id: uuid.UUID,
        name: str,
        input_data: dict[str, Any],
        expected_allow: bool,
        description: str | None = None,
        expected_violations: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> PolicyTestCase:
        """Create and persist a new policy test case.

        Args:
            tenant: The tenant context.
            policy_id: UUID of the policy under test.
            name: Human-readable test case name.
            input_data: JSON input payload.
            expected_allow: Expected allow/deny outcome.
            description: Optional scenario description.
            expected_violations: Optional list of expected violation substrings.
            tags: Optional grouping tags.

        Returns:
            The persisted PolicyTestCase.
        """
        test_case = PolicyTestCase(
            tenant_id=tenant.tenant_id,
            policy_id=policy_id,
            name=name,
            input_data=input_data,
            expected_allow=expected_allow,
            description=description,
            expected_violations=expected_violations or [],
            tags=tags or [],
        )
        self._session.add(test_case)
        await self._session.flush()
        await self._session.refresh(test_case)
        return test_case

    async def get_by_id(
        self,
        test_case_id: uuid.UUID,
        tenant: TenantContext,
    ) -> PolicyTestCase:
        """Retrieve a test case by ID.

        Args:
            test_case_id: The test case UUID.
            tenant: The tenant context.

        Returns:
            The PolicyTestCase.

        Raises:
            NotFoundError: If not found.
        """
        stmt = select(PolicyTestCase).where(
            PolicyTestCase.id == test_case_id,
            PolicyTestCase.tenant_id == tenant.tenant_id,
        )
        result = await self._session.execute(stmt)
        tc = result.scalar_one_or_none()
        if tc is None:
            raise NotFoundError(resource="PolicyTestCase", resource_id=str(test_case_id))
        return tc

    async def list_by_policy(
        self,
        policy_id: uuid.UUID,
        tenant: TenantContext,
        tags: list[str] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[PolicyTestCase]:
        """List test cases for a policy.

        Args:
            policy_id: The policy UUID.
            tenant: The tenant context.
            tags: Optional tag filter (any match).
            page: Page number (1-indexed).
            page_size: Records per page.

        Returns:
            List of PolicyTestCase records.
        """
        stmt = select(PolicyTestCase).where(
            PolicyTestCase.policy_id == policy_id,
            PolicyTestCase.tenant_id == tenant.tenant_id,
        )
        if tags:
            stmt = stmt.where(PolicyTestCase.tags.contains(tags))
        stmt = stmt.order_by(PolicyTestCase.created_at.desc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def delete(
        self,
        test_case_id: uuid.UUID,
        tenant: TenantContext,
    ) -> None:
        """Delete a test case by ID.

        Args:
            test_case_id: The test case UUID.
            tenant: The tenant context.

        Raises:
            NotFoundError: If not found.
        """
        tc = await self.get_by_id(test_case_id, tenant)
        await self._session.delete(tc)


class PolicyTestRunRepository(BaseRepository[PolicyTestRun]):
    """Repository for PolicyTestRun persistence.

    Args:
        session: The primary DB async session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize with a database session.

        Args:
            session: The SQLAlchemy async session for the primary DB.
        """
        super().__init__(session, PolicyTestRun)

    async def create(
        self,
        tenant: TenantContext,
        policy_id: uuid.UUID,
        test_case_ids: list[uuid.UUID],
        triggered_by: uuid.UUID,
    ) -> PolicyTestRun:
        """Create a new test run record in 'running' state.

        Args:
            tenant: The tenant context.
            policy_id: The policy being tested.
            test_case_ids: UUIDs of test cases to run.
            triggered_by: UUID of the triggering user.

        Returns:
            The persisted PolicyTestRun.
        """
        run = PolicyTestRun(
            tenant_id=tenant.tenant_id,
            policy_id=policy_id,
            test_case_ids=[str(tc_id) for tc_id in test_case_ids],
            triggered_by=triggered_by,
            status="running",
            total_cases=len(test_case_ids),
            passed_cases=0,
            failed_cases=0,
            error_cases=0,
            results=[],
            started_at=datetime.now(UTC),
        )
        self._session.add(run)
        await self._session.flush()
        await self._session.refresh(run)
        return run

    async def get_by_id(
        self,
        run_id: uuid.UUID,
        tenant: TenantContext,
    ) -> PolicyTestRun:
        """Retrieve a test run by ID.

        Args:
            run_id: The run UUID.
            tenant: The tenant context.

        Returns:
            The PolicyTestRun.

        Raises:
            NotFoundError: If not found.
        """
        stmt = select(PolicyTestRun).where(
            PolicyTestRun.id == run_id,
            PolicyTestRun.tenant_id == tenant.tenant_id,
        )
        result = await self._session.execute(stmt)
        run = result.scalar_one_or_none()
        if run is None:
            raise NotFoundError(resource="PolicyTestRun", resource_id=str(run_id))
        return run

    async def list_by_policy(
        self,
        policy_id: uuid.UUID,
        tenant: TenantContext,
        page: int = 1,
        page_size: int = 20,
    ) -> list[PolicyTestRun]:
        """List test runs for a policy.

        Args:
            policy_id: The policy UUID.
            tenant: The tenant context.
            page: Page number.
            page_size: Records per page.

        Returns:
            List of PolicyTestRun records.
        """
        stmt = (
            select(PolicyTestRun)
            .where(
                PolicyTestRun.policy_id == policy_id,
                PolicyTestRun.tenant_id == tenant.tenant_id,
            )
            .order_by(PolicyTestRun.started_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def complete(
        self,
        run: PolicyTestRun,
        passed: int,
        failed: int,
        errors: int,
        results: list[dict[str, Any]],
        final_status: str,
    ) -> PolicyTestRun:
        """Update a test run with completion data.

        Args:
            run: The PolicyTestRun to update.
            passed: Count of passing test cases.
            failed: Count of failing test cases.
            errors: Count of errored test cases.
            results: Per-test-case result details.
            final_status: Terminal status: passed | failed | error.

        Returns:
            The updated PolicyTestRun.
        """
        now = datetime.now(UTC)
        duration_ms = int((now - run.started_at).total_seconds() * 1000)
        run.passed_cases = passed
        run.failed_cases = failed
        run.error_cases = errors
        run.results = results
        run.status = final_status
        run.completed_at = now
        run.duration_ms = duration_ms
        await self._session.flush()
        await self._session.refresh(run)
        return run


class PolicyTestService:
    """Service for running Rego policy test suites.

    Implements Gap #194: parallel test execution against a temporary OPA policy
    upload. Each test case is evaluated independently; results are aggregated
    into a PolicyTestRun record and an Audit Wall entry is written.

    Args:
        test_case_repo: Repository for PolicyTestCase.
        test_run_repo: Repository for PolicyTestRun.
        opa_client: OPA REST API client.
        audit_trail_repo: Audit Wall repository (separate DB).
    """

    def __init__(
        self,
        test_case_repo: PolicyTestCaseRepository,
        test_run_repo: PolicyTestRunRepository,
        opa_client: Any,
        audit_trail_repo: Any,
    ) -> None:
        """Initialize PolicyTestService with injected dependencies.

        Args:
            test_case_repo: PolicyTestCaseRepository instance.
            test_run_repo: PolicyTestRunRepository instance.
            opa_client: OPA client implementing IOPAClient.
            audit_trail_repo: Audit trail repository for compliance writes.
        """
        self._test_case_repo = test_case_repo
        self._test_run_repo = test_run_repo
        self._opa_client = opa_client
        self._audit_trail_repo = audit_trail_repo

    async def run_tests(
        self,
        tenant: TenantContext,
        policy_id: uuid.UUID,
        rego_content: str,
        actor_id: uuid.UUID,
        test_case_ids: list[uuid.UUID] | None = None,
        correlation_id: str | None = None,
    ) -> PolicyTestRun:
        """Execute a test suite for a policy.

        Uploads the Rego content to a temporary isolated OPA path, runs all
        selected test cases in parallel via asyncio.gather(), then removes the
        temporary policy. Writes to the Audit Wall on completion.

        Args:
            tenant: The tenant context.
            policy_id: UUID of the GovernancePolicy under test.
            rego_content: The Rego source code to test.
            actor_id: UUID of the user triggering the run.
            test_case_ids: Optional subset of test case IDs. None = run all.
            correlation_id: Optional request correlation ID.

        Returns:
            The completed PolicyTestRun record.
        """
        # Fetch test cases
        if test_case_ids:
            test_cases = [
                await self._test_case_repo.get_by_id(tc_id, tenant)
                for tc_id in test_case_ids
            ]
        else:
            test_cases = await self._test_case_repo.list_by_policy(
                policy_id, tenant, page_size=500
            )

        all_ids = [tc.id for tc in test_cases]
        run = await self._test_run_repo.create(
            tenant=tenant,
            policy_id=policy_id,
            test_case_ids=all_ids,
            triggered_by=actor_id,
        )

        # Upload temp policy for isolated testing
        temp_policy_id = uuid.uuid4()
        try:
            await self._opa_client.upload_policy(temp_policy_id, rego_content)
        except Exception as upload_err:
            logger.warning(
                "Failed to upload temp OPA policy for testing",
                error=str(upload_err),
                policy_id=str(policy_id),
            )
            return await self._test_run_repo.complete(
                run=run,
                passed=0,
                failed=0,
                errors=len(test_cases),
                results=[
                    {
                        "test_case_id": str(tc.id),
                        "passed": False,
                        "error": f"OPA upload failed: {upload_err}",
                    }
                    for tc in test_cases
                ],
                final_status="error",
            )

        # Execute all test cases in parallel
        try:
            async def _eval_one(tc: PolicyTestCase) -> dict[str, Any]:
                """Evaluate a single test case against the temp policy.

                Args:
                    tc: The test case to evaluate.

                Returns:
                    Result dict with test_case_id, passed, actual_allow, error.
                """
                try:
                    opa_result = await self._opa_client.evaluate(
                        temp_policy_id, tc.input_data
                    )
                    actual_allow: bool = bool(opa_result.get("allow", False))
                    passed = actual_allow == tc.expected_allow
                    return {
                        "test_case_id": str(tc.id),
                        "name": tc.name,
                        "passed": passed,
                        "actual_allow": actual_allow,
                        "expected_allow": tc.expected_allow,
                        "violations": opa_result.get("violations", []),
                    }
                except Exception as eval_err:
                    return {
                        "test_case_id": str(tc.id),
                        "name": tc.name,
                        "passed": False,
                        "error": str(eval_err),
                    }

            raw_results = await asyncio.gather(*[_eval_one(tc) for tc in test_cases])
        finally:
            # Always clean up temp policy
            try:
                await self._opa_client.delete_policy(temp_policy_id)
            except Exception as cleanup_err:
                logger.warning(
                    "Failed to clean up temp OPA policy",
                    temp_policy_id=str(temp_policy_id),
                    error=str(cleanup_err),
                )

        results = list(raw_results)
        passed = sum(1 for r in results if r.get("passed"))
        errors = sum(1 for r in results if "error" in r)
        failed = len(results) - passed - errors
        final_status = "passed" if failed == 0 and errors == 0 else "failed"

        completed_run = await self._test_run_repo.complete(
            run=run,
            passed=passed,
            failed=failed,
            errors=errors,
            results=results,
            final_status=final_status,
        )

        # Write to Audit Wall
        try:
            await self._audit_trail_repo.append(
                tenant_id=tenant.tenant_id,
                event_type="governance.policy.test_run.completed",
                actor_id=actor_id,
                resource_type="policy_test_run",
                resource_id=completed_run.id,
                action="completed",
                details={
                    "policy_id": str(policy_id),
                    "total_cases": completed_run.total_cases,
                    "passed": passed,
                    "failed": failed,
                    "errors": errors,
                    "status": final_status,
                },
                timestamp=datetime.now(UTC),
                correlation_id=correlation_id,
            )
        except Exception as audit_err:
            logger.error(
                "Failed to write test run to Audit Wall",
                run_id=str(completed_run.id),
                error=str(audit_err),
            )

        logger.info(
            "Policy test run completed",
            run_id=str(completed_run.id),
            policy_id=str(policy_id),
            total=len(results),
            passed=passed,
            failed=failed,
            errors=errors,
            status=final_status,
        )
        return completed_run
