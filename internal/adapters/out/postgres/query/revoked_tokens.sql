-- name: RevokeToken :exec
-- Registers a unique token identifier in the real-time blacklist registry.
-- Idempotently ignores inserts on duplicate conflicts to prevent collision spikes.
INSERT INTO revoked_tokens (
    token_id,
    expires_at
)
VALUES (
    @token_id::varchar,
    @expires_at::timestamptz
)
ON CONFLICT (token_id) DO NOTHING;

-- name: IsTokenRevoked :one
-- Checks the real-time token blacklist registry to confirm active revocation states.
-- Discards expired block rows automatically by comparing against the database clock.
SELECT EXISTS (
    SELECT 1
    FROM revoked_tokens
    WHERE token_id = @token_id::varchar
      AND expires_at > NOW()
) AS is_revoked;
