"""Compliance-as-Code engine for AumOS governance.

Evaluates AI systems against regulatory frameworks and returns
compliance status with evidence within 60 seconds.

Modules:
- engine: OPA policy evaluation orchestrator
- policy_registry: Policy loading, versioning, and hot-reload
- evidence_mapper: Map evaluation results to compliance evidence
- regulatory_inventory: Catalog of all supported regulations
"""
