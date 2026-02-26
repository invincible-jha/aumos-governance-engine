"""Adapters — external integrations for the governance engine.

Contains:
- repositories.py  — SQLAlchemy repositories for primary DB
- audit_wall.py    — Separate audit DB session and AuditTrailRepository
- opa_client.py    — OPA REST API client
- kafka.py         — GovernanceEventPublisher
"""

__all__: list[str] = []
