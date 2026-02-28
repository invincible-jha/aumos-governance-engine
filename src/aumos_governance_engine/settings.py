"""Service-specific settings for aumos-governance-engine.

All standard AumOS configuration is inherited from AumOSSettings (database URL,
Kafka bootstrap servers, Keycloak config, Redis URL, etc.).

Governance-specific settings use the AUMOS_GOVERNANCE_ prefix and cover:
- Audit Wall (separate PostgreSQL instance)
- OPA (Open Policy Agent) integration
- Evidence artifact storage
- Policy evaluation timeouts
"""

from pydantic import Field
from pydantic_settings import SettingsConfigDict

from aumos_common.config import AumOSSettings


class Settings(AumOSSettings):
    """Settings for aumos-governance-engine.

    Inherits all standard AumOS settings and adds governance-specific
    configuration for the Audit Wall, OPA, and compliance workflows.

    Environment variable prefix: AUMOS_GOVERNANCE_
    """

    service_name: str = "aumos-governance-engine"

    # -------------------------------------------------------------------------
    # Audit Wall — separate PostgreSQL instance for immutable audit trail
    # -------------------------------------------------------------------------

    audit_db_url: str = Field(
        description="PostgreSQL connection URL for the SEPARATE audit database (Audit Wall). "
        "Must be a different server from the primary AUMOS_DATABASE_URL. "
        "The DB user should have only INSERT and SELECT grants on gov_audit_trail_entries.",
    )
    audit_db_pool_size: int = Field(
        default=5,
        description="Connection pool size for the audit DB. Keep small — audit writes are append-only.",
    )
    audit_db_max_overflow: int = Field(
        default=2,
        description="Max overflow connections above audit_db_pool_size.",
    )
    audit_db_pool_timeout: int = Field(
        default=30,
        description="Seconds to wait for an audit DB connection before raising an error.",
    )

    # -------------------------------------------------------------------------
    # OPA (Open Policy Agent) integration
    # -------------------------------------------------------------------------

    opa_url: str = Field(
        default="http://localhost:8181",
        description="OPA REST API endpoint. OPA runs as a sidecar alongside this service.",
    )
    policy_eval_timeout_ms: int = Field(
        default=200,
        description="Hard timeout for OPA policy evaluation in milliseconds. "
        "Evaluations exceeding this threshold trigger a warning log.",
    )
    opa_bundle_prefix: str = Field(
        default="aumos/governance",
        description="Prefix for OPA policy bundle paths. "
        "Policies are uploaded to /v1/policies/{prefix}/{policy_id}.",
    )

    # -------------------------------------------------------------------------
    # Evidence artifact storage (S3-compatible)
    # -------------------------------------------------------------------------

    evidence_artifact_bucket: str = Field(
        default="aumos-governance-evidence",
        description="S3-compatible bucket name for evidence artifact storage.",
    )
    evidence_artifact_endpoint: str = Field(
        default="",
        description="S3-compatible endpoint URL. Leave empty for AWS S3.",
    )
    evidence_artifact_access_key: str = Field(
        default="",
        description="Access key for evidence artifact storage.",
    )
    evidence_artifact_secret_key: str = Field(
        default="",
        description="Secret key for evidence artifact storage.",
    )

    # -------------------------------------------------------------------------
    # Compliance assessment configuration
    # -------------------------------------------------------------------------

    assessment_cron: str = Field(
        default="0 2 * * *",
        description="Cron expression for when automated compliance assessments run.",
    )
    reg_mapping_cache_ttl: int = Field(
        default=3600,
        description="TTL in seconds for regulation mapping cache entries.",
    )

    # -------------------------------------------------------------------------
    # Gap 201 — External evidence import (Jira + ServiceNow)
    # -------------------------------------------------------------------------

    jira_base_url: str = Field(
        default="",
        description="Jira instance base URL for evidence import (e.g., https://org.atlassian.net).",
    )
    jira_email: str = Field(
        default="",
        description="Service account email for Jira API basic auth.",
    )
    jira_api_token: str = Field(
        default="",
        description="API token for Jira authentication.",
    )
    servicenow_instance_url: str = Field(
        default="",
        description="ServiceNow instance URL for evidence import (e.g., https://org.service-now.com).",
    )
    servicenow_username: str = Field(
        default="",
        description="ServiceNow service account username.",
    )
    servicenow_password: str = Field(
        default="",
        description="ServiceNow service account password.",
    )

    # -------------------------------------------------------------------------
    # Gap 197 — Decision analytics Redis caching
    # -------------------------------------------------------------------------

    analytics_cache_ttl_seconds: int = Field(
        default=300,
        description="TTL in seconds for decision analytics cache entries in Redis.",
    )

    model_config = SettingsConfigDict(env_prefix="AUMOS_GOVERNANCE_")
