# Contributing to aumos-governance-engine

Thank you for contributing to AumOS Enterprise. This guide covers everything you need
to get started and ensure your contributions meet our standards.

## Getting Started

1. Fork the repository (external contributors) or clone directly (AumOS team members)
2. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/bug-description
   ```
3. Make your changes following the standards below
4. Submit a pull request targeting `main`

## Development Setup

### Prerequisites

- Python 3.11 or 3.12
- Docker and Docker Compose
- Access to AumOS internal PyPI (for `aumos-common` and `aumos-proto`)

### Install

```bash
# Install all dependencies including dev tools
make install

# Copy and configure environment
cp .env.example .env
# Edit .env — at minimum, set AUMOS_GOVERNANCE_AUDIT_DB_URL to a separate DB instance

# Start local infrastructure (postgres, postgres-audit, redis, kafka, opa)
make docker-run

# Run database migrations (primary DB)
make migrate
```

### Verify Setup

```bash
make lint       # Should pass with no errors
make typecheck  # Should pass with no errors
make test       # Should pass with coverage >= 80%

# Verify OPA is running
make opa-check
```

## Code Standards

All code in this repository must follow the standards defined in [CLAUDE.md](CLAUDE.md).
Key requirements:

- **Type hints on every function** — no exceptions
- **Pydantic models for all API inputs/outputs** — never return raw dicts
- **Structured logging** — use `get_logger(__name__)`, never `print()`
- **Async by default** — all I/O must be async
- **Import from aumos-common** — never reimplement shared utilities
- **Google-style docstrings** on all public classes and methods
- **Max line length: 120 characters**

Run `make lint` and `make typecheck` before every commit.

## Audit Wall Rules — CRITICAL

The Audit Wall is the most security-sensitive component in this repository.

1. **Never add UPDATE or DELETE operations to `AuditTrailRepository`**. The audit trail is
   immutable. If this is needed for a bug fix, escalate to the platform team.

2. **Never write to `gov_audit_trail_entries` from the primary DB session**. Always use
   `get_audit_db_session` from `adapters/audit_wall.py`.

3. **Every API endpoint that changes state must produce an AuditTrailEntry**. This is a
   compliance requirement. If you add a new state-changing endpoint, include the audit
   write in your PR and mention it in the PR description.

4. **Audit DB credentials are separate from primary DB credentials**. In production, the
   audit DB user has only `INSERT` and `SELECT` grants. Never grant `UPDATE` or `DELETE`.

## PR Process

1. Ensure all CI checks pass (lint, typecheck, test, docker build, license check)
2. Fill out the PR template completely
3. For any change that modifies audit trail behavior, explicitly call this out in the PR
   description and request a review from the security team
4. Request review from at least one member of `@aumos/platform-team`
5. Squash merge only — keep history clean
6. Delete your branch after merge

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add FedRAMP control mapping for AC-2 through AC-6
fix: resolve race condition in concurrent audit trail writes
refactor: extract OPA bundle upload into separate method
docs: update Audit Wall architecture section in README
test: add integration tests for ComplianceService state transitions
chore: bump httpx to 0.28.0
```

Commit messages explain **WHY**, not just what changed.

## License Compliance — CRITICAL

AumOS Enterprise is licensed under Apache 2.0. Our enterprise customers have strict
requirements that prohibit AGPL and GPL licensed code in our platform.

### What You MUST NOT Do

- **NEVER add a dependency with a GPL or AGPL license**, even indirectly
- **NEVER copy GPL/AGPL code** into this repository
- **NEVER wrap a GPL/AGPL tool** without explicit written approval from legal

### Approved Licenses

The following licenses are approved for dependencies:

- MIT
- BSD (2-clause or 3-clause)
- Apache Software License 2.0
- ISC
- Python Software Foundation (PSF)
- Mozilla Public License 2.0 (MPL 2.0) — with restrictions, check with team

### Checking License Before Adding a Dependency

```bash
pip install pip-licenses
pip install <new-package>
pip-licenses --packages <new-package>
```

## Testing Requirements

- All new features must include tests
- Coverage must remain >= 80% for `core/` modules
- Coverage must remain >= 60% for `adapters/`
- Use `testcontainers` for integration tests requiring real infrastructure
- Mock OPA responses in unit tests using `pytest-mock`
- Any change to audit trail behavior must have a specific test verifying immutability

```bash
make test
pytest tests/test_services.py -v
pytest tests/ --cov --cov-report=html
```

## Code of Conduct

We are committed to providing a welcoming and respectful environment for all contributors.
All participants are expected to:

- Be respectful and constructive in all interactions
- Focus on what is best for the project and platform
- Accept feedback graciously and provide it thoughtfully
- Report unacceptable behavior to the platform team

Violations may result in removal from the project.
