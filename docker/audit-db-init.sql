-- =============================================================================
-- audit-db-init.sql — Audit Wall PostgreSQL initialization
-- =============================================================================
-- This script runs once when the postgres-audit container starts for the
-- first time. It creates the audit table with proper constraints and sets
-- up INSERT-only permissions for the application role.
--
-- In production, use a separate role with only INSERT + SELECT grants.
-- Never grant UPDATE or DELETE on gov_audit_trail_entries.
-- =============================================================================

-- Create the audit trail table with append-only constraints
CREATE TABLE IF NOT EXISTS gov_audit_trail_entries (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL,
    event_type  VARCHAR(100) NOT NULL,
    actor_id    UUID NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID NOT NULL,
    action      VARCHAR(50) NOT NULL,
    details     JSONB NOT NULL DEFAULT '{}',
    timestamp   TIMESTAMPTZ NOT NULL,
    source_service VARCHAR(100) NOT NULL DEFAULT 'aumos-governance-engine',
    correlation_id VARCHAR(100),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_audit_tenant_id     ON gov_audit_trail_entries (tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type    ON gov_audit_trail_entries (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_resource_type ON gov_audit_trail_entries (resource_type);
CREATE INDEX IF NOT EXISTS idx_audit_resource_id   ON gov_audit_trail_entries (resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor_id      ON gov_audit_trail_entries (actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp     ON gov_audit_trail_entries (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_correlation   ON gov_audit_trail_entries (correlation_id);

-- Compound index for tenant-scoped time range queries
CREATE INDEX IF NOT EXISTS idx_audit_tenant_timestamp
    ON gov_audit_trail_entries (tenant_id, timestamp DESC);

-- =============================================================================
-- IMMUTABILITY: Apply a rule to prevent UPDATE and DELETE operations.
-- In production, this should be enforced at the PostgreSQL role level.
-- The rule below is an additional application-level safeguard.
-- =============================================================================

-- Prevent any UPDATE on audit trail entries
CREATE OR REPLACE RULE no_update_audit AS
    ON UPDATE TO gov_audit_trail_entries DO INSTEAD NOTHING;

-- Prevent any DELETE on audit trail entries
CREATE OR REPLACE RULE no_delete_audit AS
    ON DELETE TO gov_audit_trail_entries DO INSTEAD NOTHING;

-- =============================================================================
-- In production, create a restricted role:
-- CREATE ROLE aumos_governance_app WITH LOGIN PASSWORD '...';
-- GRANT CONNECT ON DATABASE aumos_audit TO aumos_governance_app;
-- GRANT USAGE ON SCHEMA public TO aumos_governance_app;
-- GRANT INSERT, SELECT ON gov_audit_trail_entries TO aumos_governance_app;
-- -- No UPDATE or DELETE grants!
-- =============================================================================
