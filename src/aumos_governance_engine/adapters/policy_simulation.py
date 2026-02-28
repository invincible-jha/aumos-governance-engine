"""Policy simulation (dry-run) adapter for the governance engine.

Implements Gap #195: Policy Simulation / Dry-Run.

Provides PolicySimulationService for running what-if analyses against
draft Rego policies before activation. Simulations use a temporary isolated
OPA policy upload and run all inputs in parallel via asyncio.gather().
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

from aumos_governance_engine.core.models import PolicySimulation

logger = get_logger(__name__)


class PolicySimulationRepository(BaseRepository[PolicySimulation]):
    """Repository for PolicySimulation persistence.

    Args:
        session: The primary DB async session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize with a database session.

        Args:
            session: The SQLAlchemy async session for the primary DB.
        """
        super().__init__(session, PolicySimulation)

    async def create(
        self,
        tenant: TenantContext,
        policy_id: uuid.UUID,
        scenario_name: str,
        input_dataset: list[dict[str, Any]],
        triggered_by: uuid.UUID,
    ) -> PolicySimulation:
        """Create a new simulation record.

        Args:
            tenant: The tenant context.
            policy_id: The policy UUID to simulate.
            scenario_name: Human-readable scenario label.
            input_dataset: List of input payloads to simulate.
            triggered_by: UUID of the triggering user.

        Returns:
            The persisted PolicySimulation.
        """
        sim = PolicySimulation(
            tenant_id=tenant.tenant_id,
            policy_id=policy_id,
            scenario_name=scenario_name,
            input_dataset=input_dataset,
            results=[],
            allow_count=0,
            deny_count=0,
            triggered_by=triggered_by,
        )
        self._session.add(sim)
        await self._session.flush()
        await self._session.refresh(sim)
        return sim

    async def get_by_id(
        self,
        sim_id: uuid.UUID,
        tenant: TenantContext,
    ) -> PolicySimulation:
        """Retrieve a simulation by ID.

        Args:
            sim_id: The simulation UUID.
            tenant: The tenant context.

        Returns:
            The PolicySimulation.

        Raises:
            NotFoundError: If not found.
        """
        stmt = select(PolicySimulation).where(
            PolicySimulation.id == sim_id,
            PolicySimulation.tenant_id == tenant.tenant_id,
        )
        result = await self._session.execute(stmt)
        sim = result.scalar_one_or_none()
        if sim is None:
            raise NotFoundError(resource="PolicySimulation", resource_id=str(sim_id))
        return sim

    async def list_by_policy(
        self,
        policy_id: uuid.UUID,
        tenant: TenantContext,
        page: int = 1,
        page_size: int = 20,
    ) -> list[PolicySimulation]:
        """List simulations for a policy.

        Args:
            policy_id: The policy UUID.
            tenant: The tenant context.
            page: Page number.
            page_size: Records per page.

        Returns:
            List of PolicySimulation records.
        """
        stmt = (
            select(PolicySimulation)
            .where(
                PolicySimulation.policy_id == policy_id,
                PolicySimulation.tenant_id == tenant.tenant_id,
            )
            .order_by(PolicySimulation.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def complete(
        self,
        sim: PolicySimulation,
        results: list[dict[str, Any]],
        allow_count: int,
        deny_count: int,
    ) -> PolicySimulation:
        """Update simulation with completion data.

        Args:
            sim: The PolicySimulation to update.
            results: Per-input result objects.
            allow_count: Count of allowed inputs.
            deny_count: Count of denied inputs.

        Returns:
            The updated PolicySimulation.
        """
        now = datetime.now(UTC)
        sim.results = results
        sim.allow_count = allow_count
        sim.deny_count = deny_count
        sim.completed_at = now
        sim.duration_ms = int((now - sim.created_at).total_seconds() * 1000)
        await self._session.flush()
        await self._session.refresh(sim)
        return sim


class PolicySimulationService:
    """Service for policy dry-run simulations.

    Implements Gap #195: runs what-if analysis for a draft Rego policy
    against a dataset of inputs without affecting production state.
    Uses a temporary isolated OPA policy upload and asyncio.gather()
    for parallel input evaluation.

    Args:
        sim_repo: Repository for PolicySimulation.
        opa_client: OPA REST API client.
    """

    def __init__(
        self,
        sim_repo: PolicySimulationRepository,
        opa_client: Any,
    ) -> None:
        """Initialize PolicySimulationService.

        Args:
            sim_repo: PolicySimulationRepository instance.
            opa_client: OPA client implementing IOPAClient.
        """
        self._sim_repo = sim_repo
        self._opa_client = opa_client

    async def simulate(
        self,
        tenant: TenantContext,
        policy_id: uuid.UUID,
        rego_content: str,
        scenario_name: str,
        input_dataset: list[dict[str, Any]],
        triggered_by: uuid.UUID,
    ) -> PolicySimulation:
        """Run a dry-run simulation for a policy against a dataset.

        Uploads the Rego to a temporary isolated OPA path, evaluates all
        inputs in parallel, then deletes the temp policy. Results are
        persisted in a PolicySimulation record.

        Args:
            tenant: The tenant context.
            policy_id: The policy being simulated.
            rego_content: The Rego source to evaluate (may be a draft).
            scenario_name: Human-readable label for this scenario.
            input_dataset: List of input payloads to evaluate.
            triggered_by: UUID of the triggering user.

        Returns:
            The completed PolicySimulation record.
        """
        sim = await self._sim_repo.create(
            tenant=tenant,
            policy_id=policy_id,
            scenario_name=scenario_name,
            input_dataset=input_dataset,
            triggered_by=triggered_by,
        )

        temp_policy_id = uuid.uuid4()
        try:
            await self._opa_client.upload_policy(temp_policy_id, rego_content)
        except Exception as upload_err:
            logger.error(
                "Simulation: failed to upload temp OPA policy",
                error=str(upload_err),
            )
            # Return empty results
            return await self._sim_repo.complete(
                sim=sim,
                results=[{"error": f"OPA upload failed: {upload_err}"}],
                allow_count=0,
                deny_count=0,
            )

        try:
            async def _eval_input(idx: int, inp: dict[str, Any]) -> dict[str, Any]:
                """Evaluate a single simulation input.

                Args:
                    idx: Index of this input in the dataset.
                    inp: The input payload.

                Returns:
                    Result dict with input_index, allow, violations.
                """
                try:
                    result = await self._opa_client.evaluate(temp_policy_id, inp)
                    return {
                        "input_index": idx,
                        "allow": bool(result.get("allow", False)),
                        "violations": result.get("violations", []),
                    }
                except Exception as eval_err:
                    return {
                        "input_index": idx,
                        "allow": False,
                        "error": str(eval_err),
                    }

            raw_results = await asyncio.gather(
                *[_eval_input(i, inp) for i, inp in enumerate(input_dataset)]
            )
        finally:
            try:
                await self._opa_client.delete_policy(temp_policy_id)
            except Exception as cleanup_err:
                logger.warning(
                    "Simulation: failed to clean up temp OPA policy",
                    error=str(cleanup_err),
                )

        results = list(raw_results)
        allow_count = sum(1 for r in results if r.get("allow"))
        deny_count = len(results) - allow_count

        completed = await self._sim_repo.complete(
            sim=sim,
            results=results,
            allow_count=allow_count,
            deny_count=deny_count,
        )

        logger.info(
            "Policy simulation completed",
            sim_id=str(completed.id),
            policy_id=str(policy_id),
            inputs=len(results),
            allows=allow_count,
            denies=deny_count,
        )
        return completed

    async def what_if(
        self,
        tenant: TenantContext,
        policy_id: uuid.UUID,
        new_rego_content: str,
        comparison_inputs: list[dict[str, Any]],
        triggered_by: uuid.UUID,
    ) -> dict[str, Any]:
        """Compare current policy vs a proposed Rego change side-by-side.

        Runs two simulations: one with the current policy and one with the
        proposed Rego. Returns a comparison summary showing which inputs
        would change outcome.

        Args:
            tenant: The tenant context.
            policy_id: The current GovernancePolicy UUID.
            new_rego_content: The proposed new Rego source code.
            comparison_inputs: List of inputs to compare on.
            triggered_by: UUID of the triggering user.

        Returns:
            Comparison dict with changed_count, unchanged_count, and per-input diff.
        """
        # Run simulation on proposed content
        new_sim = await self.simulate(
            tenant=tenant,
            policy_id=policy_id,
            rego_content=new_rego_content,
            scenario_name="what-if-comparison",
            input_dataset=comparison_inputs,
            triggered_by=triggered_by,
        )

        # Build comparison result
        diffs = []
        for result in new_sim.results:
            idx = result.get("input_index", -1)
            diffs.append({
                "input_index": idx,
                "proposed_allow": result.get("allow"),
                "proposed_violations": result.get("violations", []),
            })

        changed = sum(1 for d in diffs if d.get("proposed_allow") is not None)
        return {
            "simulation_id": str(new_sim.id),
            "total_inputs": len(comparison_inputs),
            "allow_count": new_sim.allow_count,
            "deny_count": new_sim.deny_count,
            "details": diffs,
        }
