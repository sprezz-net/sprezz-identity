-- +goose Up
-- Create revoked_tokens table to support stateless JTI revocation (RFC 7009)
CREATE TABLE revoked_tokens (
    token_id VARCHAR(255) PRIMARY KEY,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS revoked_tokens;
