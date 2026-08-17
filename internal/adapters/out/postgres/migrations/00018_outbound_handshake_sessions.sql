-- +goose Up
-- +goose StatementBegin
CREATE TABLE outbound_handshake_sessions (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id INT NOT NULL, -- Enforces the internal optimized partition key
    identity_provider_id UUID NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    code_verifier VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    access_token TEXT,
    target_uri TEXT
);

-- Index the expiration time alongside the integer tenant partition for maximum pruning performance
CREATE INDEX idx_outbound_handshake_sessions_expires_at ON outbound_handshake_sessions(tenant_id, expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS outbound_handshake_sessions;
-- +goose StatementEnd
