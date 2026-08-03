-- +goose Up
-- Add state, nonce, and acr_values columns to existing session tables
ALTER TABLE auth_sessions ADD COLUMN state VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE auth_sessions ADD COLUMN nonce VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE auth_sessions ADD COLUMN acr_values VARCHAR(255) NOT NULL DEFAULT '';

ALTER TABLE interaction_sessions ADD COLUMN state VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE interaction_sessions ADD COLUMN nonce VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE interaction_sessions ADD COLUMN acr_values VARCHAR(255) NOT NULL DEFAULT '';

-- Create pushed_authorization_requests table for PAR (RFC 9126)
CREATE TABLE pushed_authorization_requests (
    request_uri VARCHAR(255) PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge VARCHAR(255) NOT NULL,
    code_challenge_method VARCHAR(50) NOT NULL,
    scopes TEXT[] NOT NULL,
    state VARCHAR(255) NOT NULL DEFAULT '',
    nonce VARCHAR(255) NOT NULL DEFAULT '',
    idp_hint VARCHAR(255) NOT NULL DEFAULT '',
    acr_values VARCHAR(255) NOT NULL DEFAULT '',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Create dpop_proofs table to prevent DPoP JWT replay attacks (RFC 9449)
CREATE TABLE dpop_proofs (
    jti VARCHAR(255) PRIMARY KEY,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS dpop_proofs;
DROP TABLE IF EXISTS pushed_authorization_requests;

ALTER TABLE interaction_sessions DROP COLUMN IF EXISTS acr_values;
ALTER TABLE interaction_sessions DROP COLUMN IF EXISTS nonce;
ALTER TABLE interaction_sessions DROP COLUMN IF EXISTS state;

ALTER TABLE auth_sessions DROP COLUMN IF EXISTS acr_values;
ALTER TABLE auth_sessions DROP COLUMN IF EXISTS nonce;
ALTER TABLE auth_sessions DROP COLUMN IF EXISTS state;
