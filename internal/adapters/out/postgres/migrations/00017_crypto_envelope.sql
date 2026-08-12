-- +goose Up
-- +goose StatementBegin

-- 1. Merge the Envelope DEK fields directly into your existing tenants table.
-- A tenant only ever requires one operational DEK over its corporate lifecycle.
ALTER TABLE tenants
ADD COLUMN encrypted_dek BYTEA,
ADD COLUMN dek_nonce BYTEA; -- 12-byte AES-GCM Initialization Vector (IV)

-- 2. Create the decoupled signing keys table utilizing native Postgres 18 capabilities.
CREATE TABLE tenant_signing_keys (
    -- Uses Postgres 18 native uuidv7() for chronological, fragment-free indexing
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id INT NOT NULL,
    kid VARCHAR(255) NOT NULL,
    algorithm VARCHAR(50) NOT NULL,       -- 'RS256' or 'EdDSA'
    encrypted_private_key BYTEA NOT NULL, -- Wrapped by the tenant's plain-text DEK
    public_jwk_json TEXT NOT NULL,        -- Streamed directly to network sockets for JWKS
    nonce BYTEA NOT NULL,                 -- 12-byte AES-GCM IV for this specific private key
    is_active_signing BOOLEAN NOT NULL DEFAULT FALSE,     -- Only ONE key signs at any given moment
    is_active_verification BOOLEAN NOT NULL DEFAULT TRUE, -- Unlimited multi-key validation window
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_signing_keys_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT,
    CONSTRAINT unique_tenant_kid UNIQUE (tenant_id, kid)
);

-- 3. High-Efficiency Partial Indexes for O(1) Lookups
-- These filter out dead/revoked keys from active B-tree nodes, optimizing RAM consumption.
CREATE INDEX idx_signing_keys_active_sign
ON tenant_signing_keys (tenant_id)
WHERE is_active_signing = TRUE;

CREATE INDEX idx_signing_keys_active_verify
ON tenant_signing_keys (tenant_id)
WHERE is_active_verification = TRUE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_signing_keys_active_verify;
DROP INDEX IF EXISTS idx_signing_keys_active_sign;
DROP TABLE IF EXISTS tenant_signing_keys;

ALTER TABLE tenants
DROP COLUMN IF EXISTS dek_nonce,
DROP COLUMN IF EXISTS encrypted_dek;
-- +goose StatementEnd
