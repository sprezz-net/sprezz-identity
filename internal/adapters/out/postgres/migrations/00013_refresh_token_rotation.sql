-- +goose Up
ALTER TABLE applications ADD COLUMN enforce_rtr BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE applications SET enforce_rtr = TRUE WHERE client_type = 'public';

CREATE TABLE refresh_tokens (
    token_id VARCHAR(255) PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    scopes TEXT[] NOT NULL,
    token_family_id VARCHAR(255) NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- +goose Down
DROP TABLE IF EXISTS refresh_tokens CASCADE;
ALTER TABLE applications DROP COLUMN IF EXISTS enforce_rtr;
