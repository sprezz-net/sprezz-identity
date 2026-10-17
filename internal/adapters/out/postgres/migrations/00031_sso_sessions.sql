-- +goose Up
-- +goose StatementBegin

-- Browser single-sign-on sessions. The cookie holds an opaque random secret; only its SHA-256 hash is stored
-- (token_hash), so a database leak cannot be replayed. "id" is the public session identifier used as the OIDC
-- "sid" claim and for client session links; it is never the cookie value.
-- Logging out deletes the row, so a missing row always means "not signed in".
CREATE TABLE sso_sessions (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    id UUID NOT NULL UNIQUE,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    partition_id BIGINT NOT NULL REFERENCES partitions(id) ON DELETE CASCADE,
    user_profile_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
    identity_provider_id UUID REFERENCES identity_providers(id) ON DELETE SET NULL,
    acr VARCHAR(255) NOT NULL DEFAULT '',
    amr TEXT[] NOT NULL DEFAULT '{}',
    auth_time TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    idle_expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Log out everywhere / block a user.
CREATE INDEX idx_sso_sessions_user ON sso_sessions (tenant_id, user_profile_id);
-- Tenant deactivation and partition clean-up.
CREATE INDEX idx_sso_sessions_tenant ON sso_sessions (tenant_id, partition_id);
-- Housekeeping sweep.
CREATE INDEX idx_sso_sessions_expiry ON sso_sessions (expires_at, idle_expires_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS sso_sessions;

-- +goose StatementEnd
