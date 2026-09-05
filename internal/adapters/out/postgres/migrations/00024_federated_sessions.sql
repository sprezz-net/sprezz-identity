-- +goose Up
-- +goose StatementBegin

-- 1. Rectify the outbound_handshake_sessions table structure
-- Enforces partition boundaries while evicting the redundant transient token column
ALTER TABLE outbound_handshake_sessions
    ADD COLUMN partition_id BIGINT NOT NULL,
    ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN callback_uri TEXT,
    DROP COLUMN IF EXISTS access_token;

ALTER TABLE outbound_handshake_sessions
    ADD CONSTRAINT fk_outbound_handshake_partition
    FOREIGN KEY (tenant_id, partition_id)
    REFERENCES partitions(tenant_id, id)
    ON DELETE RESTRICT;

-- 2. CREATE THE DEDICATED FEDERATED STATE STORAGE TABLE (Option B)
-- This fully isolates upstream cryptos from your native session metadata
CREATE TABLE federated_sessions (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    partition_id BIGINT NOT NULL,
    session_id VARCHAR(255) NOT NULL, -- References your local active session table
    identity_provider_id UUID NOT NULL,
    upstream_subject VARCHAR(255) NOT NULL,

    -- Upstream token payload bucket (Cleaned: uniform, un-prefixed token trackers)
    upstream_access_token TEXT,
    upstream_id_token TEXT,           -- Crucial for id_token_hint allocations during SLO callbacks
    upstream_refresh_token TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,  -- Tied to upstream token validation lifecycles

    -- Strict Multi-Tenant relational integrity constraints
    CONSTRAINT fk_fed_session_tenant_partition
        FOREIGN KEY (tenant_id, partition_id)
        REFERENCES partitions(tenant_id, id)
        ON DELETE RESTRICT
);

-- Indexing for lightning-fast O(1) back-channel SLO lookups from upstream webhooks
CREATE INDEX idx_fed_sessions_lookup
    ON federated_sessions (tenant_id, identity_provider_id, upstream_subject);

CREATE INDEX idx_fed_sessions_expiry
    ON federated_sessions (expires_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS federated_sessions;

ALTER TABLE outbound_handshake_sessions
    DROP CONSTRAINT IF EXISTS fk_outbound_handshake_partition,
    DROP COLUMN IF EXISTS callback_uri,
    DROP COLUMN IF EXISTS created_at,
    DROP COLUMN IF EXISTS partition_id,
    ADD COLUMN access_token TEXT; -- Restores the column layout signature for historic rolling consistency

-- +goose StatementEnd
