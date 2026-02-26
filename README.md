# aumos-governance-engine

AI governance with policy-as-code, compliance workflows, and immutable Audit Wall architecture.
Part of the AumOS Enterprise composable AI platform.

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Architecture](#architecture)
4. [Quick Start](#quick-start)
5. [API Reference](#api-reference)
6. [Supported Regulations](#supported-regulations)
7. [Audit Wall Architecture](#audit-wall-architecture)
8. [OPA Policy Engine](#opa-policy-engine)
9. [Configuration](#configuration)
10. [Development](#development)

---

## Overview

`aumos-governance-engine` is the authoritative governance layer for all AumOS AI operations.
It provides AI governance as code using Open Policy Agent (OPA) Rego policies, multi-regulation
compliance workflow management, automated evidence collection, and an immutable audit trail
stored on physically separate infrastructure (the "Audit Wall").

This service gates AI model promotions, data pipeline operations, and agent actions across
the AumOS platform. Every policy evaluation, compliance state change, and governance action
is durably recorded in an append-only audit trail that cannot be modified after the fact.

---

## Key Features

- **Policy-as-Code with OPA Rego**: Write, version, and evaluate governance policies in
  Open Policy Agent's Rego language. Policies are stored in the database and pushed to OPA
  as bundles when activated.

- **Multi-Regulation Compliance Workflows**: Native support for SOC 2, ISO 27001:2022,
  HIPAA, ISO 42001:2023 (AI management systems), EU AI Act, and FedRAMP Moderate. Each
  regulation has a pre-built control mapping and assessment workflow.

- **Immutable Audit Wall**: All audit trail entries are written to a physically separate
  PostgreSQL instance with INSERT-only credentials. No UPDATE or DELETE operations are
  possible on the audit trail. This is the gold standard for tamper-evident governance logs.

- **Automated Evidence Collection**: Evidence records link compliance controls to artifacts
  stored in object storage. Both automated (system-generated) and manual evidence types are
  supported.

- **Regulation Mapping Engine**: Maps regulation articles to concrete technical controls
  with automation status. Identifies which controls can be automatically assessed.

- **Kafka Event Publishing**: All governance state changes are published as structured
  domain events consumed by observability, MLOps, and reporting services.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    aumos-governance-engine                       │
│                                                                  │
│  ┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐  │
│  │  FastAPI    │    │    Services     │    │   Adapters      │  │
│  │  /api/v1    │───▶│  PolicyService  │───▶│ PolicyRepo      │  │
│  │             │    │  ComplianceSvc  │    │ ComplianceRepo  │  │
│  │             │    │  AuditService   │    │ EvidenceRepo    │  │
│  │             │    │  EvidenceSvc    │    │ OPAClient       │  │
│  │             │    │  RegMapperSvc   │    │ KafkaPublisher  │  │
│  └─────────────┘    └─────────────────┘    │ AuditWall  ──┐  │  │
│                                            └─────────────┘│  │  │
└────────────────────────────────────────────────────────────│──┘  │
                                                             │
         ┌───────────────────────────────────────────────────┼────────────────────┐
         │                                                   │                    │
         ▼                                                   ▼                    ▼
  ┌──────────────┐                                  ┌──────────────┐    ┌──────────────┐
  │  Primary DB  │                                  │  Audit DB    │    │     OPA      │
  │  (Postgres)  │                                  │  (Separate   │    │   Sidecar    │
  │  gov_ tables │                                  │   Postgres)  │    │  :8181       │
  │  policies    │                                  │  APPEND-ONLY │    │  Rego eval   │
  │  workflows   │                                  │  audit_trail │    └──────────────┘
  │  evidence    │                                  └──────────────┘
  └──────────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- Access to AumOS internal PyPI (for `aumos-common` and `aumos-proto`)

### Local Development

```bash
# Clone and install
git clone https://github.com/aumos-enterprise/aumos-governance-engine
cd aumos-governance-engine
make install

# Configure environment
cp .env.example .env
# Edit .env — minimum required: AUMOS_GOVERNANCE_AUDIT_DB_URL

# Start infrastructure (postgres + postgres-audit + redis + kafka + opa)
make docker-run

# Run database migrations
make migrate

# Start the service
uvicorn aumos_governance_engine.main:app --reload
```

### Verify Setup

```bash
# Health check
curl http://localhost:8000/live

# Ready check (checks DB + OPA connections)
curl http://localhost:8000/ready

# List supported regulations
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/regulations
```

---

## API Reference

### Policies

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/policies` | Create a governance policy |
| `GET` | `/api/v1/policies` | List policies (paginated) |
| `GET` | `/api/v1/policies/{id}` | Get policy by ID |
| `PATCH` | `/api/v1/policies/{id}` | Update policy |
| `POST` | `/api/v1/policies/{id}/evaluate` | Evaluate policy against input data |

### Compliance

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/compliance/workflows` | Create compliance workflow |
| `GET` | `/api/v1/compliance/workflows` | List workflows |
| `GET` | `/api/v1/compliance/workflows/{id}` | Get workflow details |
| `GET` | `/api/v1/compliance/dashboard` | Compliance dashboard summary |

### Audit Trail

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/audit-trail` | Query immutable audit trail |

### Evidence

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/evidence` | Submit evidence record |
| `GET` | `/api/v1/evidence` | List evidence records |

### Regulations

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/regulations` | List supported regulations |
| `GET` | `/api/v1/regulations/{reg}/controls` | Get regulation control mappings |

---

## Supported Regulations

| Regulation | Code | Scope | Auto-Assessment |
|-----------|------|-------|----------------|
| SOC 2 Type II | `soc2` | Security, Availability, Processing Integrity | Partial |
| ISO 27001:2022 | `iso27001` | Information Security Management | Partial |
| HIPAA | `hipaa` | Healthcare data protection | Partial |
| ISO 42001:2023 | `iso42001` | AI Management Systems | Full |
| EU AI Act | `eu_ai_act` | AI systems risk classification | Partial |
| FedRAMP Moderate | `fedramp` | US Federal cloud services | Partial |

### Creating a Compliance Workflow

```bash
curl -X POST http://localhost:8000/api/v1/compliance/workflows \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "regulation": "iso42001",
    "name": "ISO 42001 Annual Assessment 2026"
  }'
```

---

## Audit Wall Architecture

The Audit Wall is the core security architecture of this service. It ensures that all
governance events are durably and immutably recorded.

### How It Works

1. **Separate PostgreSQL instance**: The audit trail (`gov_audit_trail_entries`) lives on
   a completely separate PostgreSQL server configured via `AUMOS_GOVERNANCE_AUDIT_DB_URL`.

2. **INSERT-only credentials**: The application connects to the audit DB with a PostgreSQL
   role that has only `INSERT` and `SELECT` privileges on `gov_audit_trail_entries`.
   No `UPDATE` or `DELETE` grants exist.

3. **No application-level deletes**: `AuditTrailRepository` has no `update()` or `delete()`
   methods. The codebase enforces immutability at the application layer.

4. **Replication and backup**: The audit DB should be configured with streaming replication
   to at least one standby and point-in-time recovery (PITR) enabled. Configure separately
   from the primary DB backup.

5. **Every governance action writes an entry**: Creating/activating a policy, changing
   workflow status, submitting evidence — all write an `AuditTrailEntry` before returning.

### Compensating Entries

If an audit entry contains an error, do NOT delete it. Write a new entry with
`event_type = "audit.correction"` and `details` pointing to the original entry ID.

---

## OPA Policy Engine

### Writing Rego Policies

Policies are stored as Rego content in the database and evaluated by OPA:

```rego
# Example: Require explainability for high-risk AI models
package aumos.governance.model_promotion

import future.keywords.if
import future.keywords.in

default allow = false

allow if {
    input.model.risk_level != "high"
}

allow if {
    input.model.risk_level == "high"
    input.model.has_explainability_report == true
    input.model.explainability_score >= 0.8
}

violations contains msg if {
    input.model.risk_level == "high"
    not input.model.has_explainability_report
    msg := "High-risk models require an explainability report"
}
```

### Creating and Activating a Policy

```bash
# Create policy
curl -X POST http://localhost:8000/api/v1/policies \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Model Promotion Gate",
    "policy_type": "opa_rego",
    "rego_content": "package aumos.governance.model_promotion\n...",
    "regulation_refs": ["iso42001", "eu_ai_act"]
  }'

# Evaluate policy
curl -X POST http://localhost:8000/api/v1/policies/{id}/evaluate \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "model": {
        "risk_level": "high",
        "has_explainability_report": true,
        "explainability_score": 0.85
      }
    }
  }'
```

---

## Configuration

All configuration is via environment variables. See `.env.example` for the full list.

### Key Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUMOS_GOVERNANCE_OPA_URL` | `http://localhost:8181` | OPA REST API endpoint |
| `AUMOS_GOVERNANCE_AUDIT_DB_URL` | *(required)* | Separate audit PostgreSQL URL |
| `AUMOS_GOVERNANCE_AUDIT_DB_POOL_SIZE` | `5` | Audit DB connection pool size |
| `AUMOS_GOVERNANCE_POLICY_EVAL_TIMEOUT_MS` | `200` | OPA evaluation timeout (ms) |
| `AUMOS_GOVERNANCE_EVIDENCE_ARTIFACT_BUCKET` | `aumos-governance-evidence` | Evidence artifact storage |
| `AUMOS_DATABASE_URL` | *(required)* | Primary PostgreSQL URL |
| `AUMOS_KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka brokers |

---

## Development

### Running Tests

```bash
make test           # Full test suite with coverage
make test-quick     # Fast run, stop on first failure
make lint           # Ruff check and format check
make typecheck      # mypy strict mode
make format         # Auto-format with ruff
```

### Adding a New Regulation

1. Add the regulation code to the `Regulation` enum in `core/models.py`
2. Add control mappings in `adapters/repositories.py` `RegulationMappingRepository`
3. Add static control data in `core/services.py` `RegulationMapperService._STATIC_MAPPINGS`
4. Write a migration to populate `gov_regulation_mappings` for the new regulation
5. Add tests in `tests/test_services.py`

### Adding a New Compliance Workflow State Transition

All state transitions must write an `AuditTrailEntry`. The pattern is:

```python
async def transition_workflow(
    self,
    workflow_id: uuid.UUID,
    new_status: str,
    tenant: TenantContext,
    actor_id: uuid.UUID,
) -> ComplianceWorkflow:
    workflow = await self._workflow_repo.get_by_id(workflow_id, tenant)
    old_status = workflow.status
    workflow = await self._workflow_repo.update_status(workflow_id, new_status, tenant)
    await self._audit_service.record(
        tenant_id=tenant.tenant_id,
        event_type="compliance.workflow.status_changed",
        actor_id=actor_id,
        resource_type="compliance_workflow",
        resource_id=workflow_id,
        action="status_changed",
        details={"old_status": old_status, "new_status": new_status},
    )
    return workflow
```
