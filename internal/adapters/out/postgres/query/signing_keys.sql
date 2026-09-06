-- name: GetActiveSigningKey :one
-- Fetches the single asymmetric key currently active for signing new tokens.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    tsk.kid,
    tsk.algorithm,
    tsk.encrypted_private_key,
    tsk.public_jwk_json,
    tsk.nonce
FROM tenant_signing_keys tsk
INNER JOIN tenant t ON t.id = tsk.tenant_id
WHERE tsk.is_active_signing = TRUE
LIMIT 1;

-- name: GetActiveSigningKeys :many
-- Loads all private cryptographic keys currently required to sign stateless tokens.
-- Leverages a canonical CTE lookup to securely translate the public UUIDv4 perimeter anchor.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    tsk.kid,
    tsk.algorithm,
    tsk.encrypted_private_key,
    tsk.public_jwk_json,
    tsk.nonce
FROM tenant_signing_keys tsk
INNER JOIN tenant t ON t.id = tsk.tenant_id
WHERE tsk.is_active_signing = TRUE;

-- name: GetActiveVerificationKeys :many
-- Loads all keys valid for token validation (overlapping lifecycle).
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    tsk.kid,
    tsk.algorithm,
    tsk.public_jwk_json
FROM tenant_signing_keys tsk
INNER JOIN tenant t ON t.id = tsk.tenant_id
WHERE tsk.is_active_verification = TRUE
ORDER BY tsk.id DESC;

-- name: InsertSigningKey :one
-- Inserts a new keypair generated at storage level by native Postgres 18 uuidv7().
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
INSERT INTO tenant_signing_keys (
    tenant_id,
    kid,
    algorithm,
    encrypted_private_key,
    public_jwk_json,
    nonce,
    is_active_signing,
    is_active_verification
)
SELECT
    t.id,
    @kid::varchar,
    @algorithm::varchar,
    @encrypted_private_key::bytea,
    @public_jwk_json::varchar,
    @nonce::bytea,
    @is_active_signing::boolean,
    @is_active_verification::boolean
FROM tenant t
RETURNING id;

-- name: RotateSigningKeysTransaction :exec
-- Demotes the current active signing key to verification-only.
-- A new key should be inserted right after this execution within a database transaction.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
UPDATE tenant_signing_keys tsk
SET
    is_active_signing = FALSE
FROM tenant t
WHERE tsk.tenant_id = t.id
  AND tsk.is_active_signing = TRUE;
