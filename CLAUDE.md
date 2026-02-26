# CLAUDE.md — AumOS Governance Engine

## Project Overview

AumOS Enterprise is a composable enterprise AI platform with 9 products + 2 services
across 62 repositories. This repo (`aumos-governance-engine`) is part of **Tier 3: Trust
and Compliance Layer**: AI governance, policy enforcement, and regulatory compliance engines.

**Release Tier:** B: Open Core
**Product Mapping:** Product 7 — AI Governance and Compliance
**Phase:** 3B (Months 18-24)

## Repo Purpose

`aumos-governance-engine` provides AI governance with policy-as-code using Open Policy Agent
(OPA) Rego, multi-regulation compliance workflow management (SOC 2, ISO 27001, HIPAA, ISO
42001, EU AI Act, FedRAMP), and an immutable Audit Wall architecture where all audit trail
entries are written to a physically separate PostgreSQL instance to prevent tampering. This
repo is the authoritative governance layer for all AumOS AI operations.

## Architecture Position

```
aumos-common ──────────────────────────────────────────────┐
aumos-proto  ──────────────────────────────────────────────┤
aumos-auth-gateway ────────────────────────────────────────┼─→ aumos-governance-engine
                                                           │       ↓ publishes to Kafka
                                                           │       ↓ evaluates OPA policies
                                                           │       ↓ writes Audit Wall (separate DB)
                                                           └── ← all repos needing governance
```

**Upstream dependencies (this repo IMPORTS from):**
- `aumos-common` — auth, database, events, errors, config, health, pagination
- `aumos-proto` — Protobuf message definitions for governance Kafka events
- `aumos-auth-gateway` — JWT validation and tenant context

**Downstream dependents (other repos IMPORT from this):**
- All AumOS repos that need policy evaluation — they call `/api/v1/policies/{id}/evaluate`
- `aumos-observability` — consumes governance events from Kafka
- `aumos-mlops-lifecycle` — governance gating for model promotion
- `aumos-data-pipeline` — data governance policy enforcement
- `aumos-agent-framework` — AI agent governance and control policies

## Tech Stack (DO NOT DEVIATE)

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.11+ | Runtime |
| FastAPI | 0.110+ | REST API framework |
| SQLAlchemy | 2.0+ (async) | ORM for primary DB |
| asyncpg | 0.29+ | PostgreSQL async driver |
| Pydantic | 2.6+ | Data validation, settings, API schemas |
| httpx | 0.27+ | OPA REST API client (async) |
| confluent-kafka | 2.3+ | Kafka event publishing |
| structlog | 24.1+ | Structured JSON logging |
| OpenTelemetry | 1.23+ | Distributed tracing |
| pytest | 8.0+ | Testing framework |
| ruff | 0.3+ | Linting and formatting |
| mypy | 1.8+ | Type checking |
| OPA | 0.60+ | Open Policy Agent (external service, not a Python dep) |

## Coding Standards

### ABSOLUTE RULES (violations will break integration with other repos)

1. **Import aumos-common, never reimplement.** If aumos-common provides it, use it.
   ```python
   # CORRECT
   from aumos_common.auth import get_current_tenant, get_current_user
   from aumos_common.database import get_db_session, Base, AumOSModel, BaseRepository
   from aumos_common.events import EventPublisher, Topics
   from aumos_common.errors import NotFoundError, ErrorCode
   from aumos_common.config import AumOSSettings
   from aumos_common.health import create_health_router
   from aumos_common.pagination import PageRequest, PageResponse, paginate
   from aumos_common.app import create_app

   # WRONG — never reimplement these
   # from jose import jwt
   # from sqlalchemy import create_engine
   # import logging
   ```

2. **Type hints on EVERY function.** No exceptions.

3. **Pydantic models for ALL API inputs/outputs.** Never return raw dicts.

4. **RLS tenant isolation via aumos-common.** Never write raw SQL that bypasses RLS.

5. **Structured logging via structlog.** Never use print() or logging.getLogger().

6. **Publish domain events to Kafka after state changes.**

7. **Async by default.** All I/O operations must be async.

8. **Google-style docstrings** on all public classes and functions.

### AUDIT WALL RULES (CRITICAL — NEVER VIOLATE)

The Audit Wall is the most security-critical component of this repo.

1. **AuditTrailRepository connects ONLY to AUMOS_GOVERNANCE_AUDIT_DB_URL.** Never use the
   primary database session for audit writes.

2. **No UPDATE or DELETE on audit tables.** The audit trail is immutable and append-only.
   If you need to "correct" an entry, write a new compensating entry.

3. **Separate credentials.** The audit DB uses `AUMOS_GOVERNANCE_AUDIT_DB_URL` with its own
   admin credentials. The primary app DB URL must never have write access to the audit DB.

4. **Every state-changing API call writes to the audit trail.** Policy create/update,
   workflow status change, evidence submission — all must produce an AuditTrailEntry.

5. **audit_wall.py is the only file that imports the audit DB session.** No other module
   should have a dependency on `get_audit_db_session`.

### OPA Integration Rules

1. **OPA is a sidecar/external service.** Do not bundle OPA binary. Use `opa_client.py`
   which calls the OPA REST API at `AUMOS_GOVERNANCE_OPA_URL`.

2. **Rego content is stored in gov_governance_policies.** When a policy is activated,
   `opa_client.py` uploads the Rego bundle to OPA's `/v1/policies/{id}` endpoint.

3. **Policy evaluation is synchronous and must complete in <200ms.** OPA is optimized for
   this. If evaluation exceeds 200ms, log a warning and include latency in the response.

4. **Never trust OPA evaluation results without validating the response schema.** Use
   Pydantic to validate OPA responses.

### Style Rules

- Max line length: **120 characters**
- Import order: stdlib → third-party → aumos-common → local
- Linter: `ruff` (select E, W, F, I, N, UP, ANN, B, A, COM, C4, PT, RUF)
- Type checker: `mypy` strict mode
- Formatter: `ruff format`

### File Structure Convention

```
src/aumos_governance_engine/
├── __init__.py
├── main.py                        # FastAPI app entry point
├── settings.py                    # AUMOS_GOVERNANCE_ prefix
├── api/
│   ├── __init__.py
│   ├── router.py                  # All API endpoints
│   └── schemas.py                 # Request/response Pydantic models
├── core/
│   ├── __init__.py
│   ├── models.py                  # gov_ prefix SQLAlchemy ORM models
│   ├── interfaces.py              # Protocol-based abstract interfaces
│   └── services.py                # PolicyService, ComplianceService,
│                                  # AuditService, EvidenceService,
│                                  # RegulationMapperService
└── adapters/
    ├── __init__.py
    ├── repositories.py            # PolicyRepository, ComplianceWorkflowRepository,
    │                              # AuditTrailRepository, EvidenceRepository
    ├── kafka.py                   # GovernanceEventPublisher
    ├── opa_client.py              # OPA REST API client
    └── audit_wall.py              # Separate audit DB session + write logic
```

## API Conventions

- All endpoints under `/api/v1/` prefix
- Auth: Bearer JWT token (validated by aumos-common)
- Tenant: `X-Tenant-ID` header (set by auth middleware)
- Request ID: `X-Request-ID` header (auto-generated if missing)
- Pagination: `?page=1&page_size=20&sort_by=created_at&sort_order=desc`
- Errors: Standard `ErrorResponse` from aumos-common
- Content-Type: `application/json` (always)

## Database Conventions

- **Primary DB table prefix:** `gov_` (e.g., `gov_governance_policies`)
- **Audit DB tables:** also `gov_` prefix but on a physically separate PostgreSQL instance
- ALL tenant-scoped tables: extend `AumOSModel` (gets id, tenant_id, created_at, updated_at)
- RLS policy on every tenant table (created in migration)
- The `gov_audit_trail_entries` table lives on the AUDIT DB, never on the primary DB
- Migration naming: `{timestamp}_gov_{description}.py`

## Kafka Events Published

- `governance.policy.created` — when a new policy is created
- `governance.policy.activated` — when a policy is activated (OPA bundle uploaded)
- `governance.policy.evaluated` — when a policy evaluation is completed
- `governance.compliance.workflow.created` — new compliance workflow
- `governance.compliance.workflow.status_changed` — workflow state transitions
- `governance.evidence.submitted` — new evidence record
- `governance.audit.entry.written` — every audit trail write (for replication)

## Environment Variables

All standard env vars are in `aumos_common.config.AumOSSettings`.
Governance-specific vars use prefix `AUMOS_GOVERNANCE_`.

Key governance variables:
- `AUMOS_GOVERNANCE_OPA_URL` — OPA REST API endpoint (default: http://localhost:8181)
- `AUMOS_GOVERNANCE_AUDIT_DB_URL` — SEPARATE PostgreSQL instance for audit trail
- `AUMOS_GOVERNANCE_AUDIT_DB_POOL_SIZE` — Connection pool size for audit DB
- `AUMOS_GOVERNANCE_POLICY_EVAL_TIMEOUT_MS` — OPA evaluation timeout (default: 200)
- `AUMOS_GOVERNANCE_EVIDENCE_ARTIFACT_BUCKET` — S3/GCS bucket for evidence artifacts

## Supported Regulations

| Regulation | Code | Type |
|-----------|------|------|
| SOC 2 Type II | `soc2` | Security/availability |
| ISO 27001:2022 | `iso27001` | Information security |
| HIPAA | `hipaa` | Healthcare data |
| ISO 42001:2023 | `iso42001` | AI management systems |
| EU AI Act | `eu_ai_act` | AI regulation (EU) |
| FedRAMP Moderate | `fedramp` | US federal cloud |

## What Claude Code Should NOT Do

1. **Do NOT reimplement anything in aumos-common.** Use JWT parsing, tenant context, DB
   sessions, Kafka publishing, error handling, logging, health checks, and pagination from
   aumos-common.
2. **Do NOT use print().** Use `get_logger(__name__)`.
3. **Do NOT return raw dicts from API endpoints.** Use Pydantic models.
4. **Do NOT write raw SQL.** Use SQLAlchemy ORM with BaseRepository.
5. **Do NOT hardcode configuration.** Use Pydantic Settings with env vars.
6. **Do NOT skip type hints.** Every function signature must be typed.
7. **Do NOT import AGPL/GPL licensed packages** into this repo.
8. **Do NOT put business logic in API routes.** Routes call services; services contain logic.
9. **Do NOT write UPDATE or DELETE operations on audit trail tables.** The audit trail is
   immutable. All writes to `gov_audit_trail_entries` are append-only.
10. **Do NOT use the primary DB session for audit trail writes.** Always use
    `get_audit_db_session` from `audit_wall.py`.
11. **Do NOT call OPA directly from services.** Always go through `OPAClient` from
    `opa_client.py`.

## Repo-Specific Context

### OPA (Open Policy Agent) Integration
OPA evaluates Rego policies via its REST API. The governance engine stores Rego source in
the primary DB and pushes bundles to OPA when policies are activated. OPA is deployed as a
Docker sidecar with its own data directory and bundle endpoint.

### Audit Wall Architecture
The Audit Wall is the key differentiator of this repo. It uses two PostgreSQL instances:
1. **Primary DB** (`AUMOS_DATABASE_URL`): governance policies, compliance workflows,
   evidence records, regulation mappings.
2. **Audit DB** (`AUMOS_GOVERNANCE_AUDIT_DB_URL`): exclusively for `gov_audit_trail_entries`.
   The DB user has INSERT-only permissions on this table — no SELECT from the main app
   (a separate read-only user is used for queries). This makes the audit trail tamper-evident.

### Regulation Mapping Engine
`RegulationMapperService` maintains a static + database-backed mapping of regulations to
control IDs. The static baseline is embedded in the service for the six supported regulations.
Tenants can extend mappings via the database. Control IDs follow the NIST CSF naming pattern.

### Performance Requirements
- Policy evaluation: <200ms p99 (OPA is fast; this is a hard SLA)
- Audit trail write: <50ms p99 (separate DB, append-only, no locks)
- Compliance dashboard: <500ms p99 (aggregation query with caching)
