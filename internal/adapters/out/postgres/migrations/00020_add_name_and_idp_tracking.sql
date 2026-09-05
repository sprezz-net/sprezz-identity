-- +goose Up
-- +goose StatementBegin
ALTER TABLE user_profiles
    ADD COLUMN first_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN last_name TEXT NOT NULL DEFAULT '';

ALTER TABLE refresh_tokens
    ADD COLUMN identity_provider_id UUID,
    ADD COLUMN identity_provider_alias TEXT,
    ADD COLUMN session_id TEXT;

ALTER TABLE auth_sessions
    ADD COLUMN identity_provider_id UUID,
    ADD COLUMN identity_provider_alias TEXT;

-- Enforce explicit relational indexing for fast multi-tenant isolation lookups
CREATE INDEX idx_refresh_tokens_idp_session
    ON refresh_tokens (identity_provider_id, session_id);

CREATE INDEX idx_auth_sessions_idp
    ON auth_sessions (identity_provider_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_auth_sessions_idp;
DROP INDEX IF EXISTS idx_refresh_tokens_idp_session;

ALTER TABLE auth_sessions
    DROP COLUMN IF EXISTS identity_provider_alias,
    DROP COLUMN IF EXISTS identity_provider_id;

ALTER TABLE refresh_tokens
    DROP COLUMN IF EXISTS session_id,
    DROP COLUMN IF EXISTS identity_provider_alias,
    DROP COLUMN IF EXISTS identity_provider_id;

ALTER TABLE user_profiles
    DROP COLUMN IF EXISTS last_name,
    DROP COLUMN IF EXISTS first_name;
-- +goose StatementEnd
