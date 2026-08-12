-- name: GetActiveSigningKey :one
-- Fetches the single asymmetric key currently active for signing new tokens.
SELECT
    id AS kid,
    algorithm,
    encrypted_private_key,
    public_jwk_json,
    nonce
FROM tenant_signing_keys
WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1)
  AND is_active_signing = TRUE
LIMIT 1;

-- name: GetActiveVerificationKeys :many
-- Fetches all keys valid for token validation (overlapping lifecycle).
SELECT
    id AS kid,
    algorithm,
    public_jwk_json
FROM tenant_signing_keys
WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1)
  AND is_active_verification = TRUE
ORDER BY id DESC; -- Implicitly sorts by creation time due to native UUIDv7

-- name: InsertSigningKey :one
-- Inserts a new keypair generated at storage level by native Postgres 18 uuidv7().
INSERT INTO tenant_signing_keys (
    tenant_id,
    kid,
    algorithm,
    encrypted_private_key,
    public_jwk_json,
    nonce,
    is_active_signing,
    is_active_verification
) VALUES (
    (SELECT id FROM tenants WHERE tenant_uuid = $1),
    $2, -- Temporary placeholder for kid string matching, fallback to ID if required
    $3, $4, $5, $6, $7, $8
)
RETURNING id;

-- name: RotateSigningKeysTransaction :exec
-- Demotes the current active signing key to verification-only.
-- A new key should be inserted right after this execution within a database transaction.
UPDATE tenant_signing_keys
SET
    is_active_signing = FALSE
WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1)
  AND is_active_signing = TRUE;
