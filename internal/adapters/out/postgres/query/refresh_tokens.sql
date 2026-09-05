-- name: SaveRefreshToken :exec
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
)
INSERT INTO refresh_tokens (
    token_id,
    tenant_id,
    client_id,
    subject,
    scopes,
    token_family_id,
    is_used,
    expires_at,
    identity_provider_id,
    identity_provider_alias,
    session_id
)
SELECT
    @token_id,
    tenant.id,
    @client_id,
    @subject,
    @scopes,
    @token_family_id,
    @is_used,
    @expires_at::timestamptz,
    @identity_provider_id::uuid,
    @identity_provider_alias,
    @session_id
FROM tenant;

-- name: GetRefreshToken :one
SELECT
    rt.token_id,
    rt.client_id,
    rt.subject,
    rt.scopes,
    rt.token_family_id,
    rt.is_used,
    rt.expires_at,
    rt.created_at,
    rt.identity_provider_id,
    rt.identity_provider_alias,
    rt.session_id,
    t.tenant_uuid
FROM refresh_tokens rt
JOIN tenants t ON t.id = rt.tenant_id
WHERE rt.token_id = $1
LIMIT 1;

-- name: RevokeRefreshTokens :exec
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid LIMIT 1
)
DELETE FROM refresh_tokens
WHERE tenant_id = tenant.id
  AND subject = @subject
  AND client_id = @client_id;

-- name: MarkRefreshTokenUsed :exec
UPDATE refresh_tokens
SET is_used = TRUE
WHERE token_id = @token_id;

-- name: RevokeRefreshTokenFamily :exec
DELETE FROM refresh_tokens
WHERE token_family_id = @token_family_id;

-- name: PurgeRefreshTokensByTenant :exec
DELETE FROM refresh_tokens
WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid);
