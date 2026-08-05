-- name: SaveRefreshToken :execresult
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = $1
)
INSERT INTO refresh_tokens (
    token_id,
    tenant_id,
    client_id,
    subject,
    scopes,
    token_family_id,
    is_used,
    expires_at
)
SELECT
    $2,
    tenant.id,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8
FROM tenant;

-- name: GetRefreshToken :one
SELECT
    rt.token_id,
    t.tenant_uuid AS tenant_uuid,
    rt.client_id,
    rt.subject,
    rt.scopes,
    rt.token_family_id,
    rt.is_used,
    rt.expires_at,
    rt.created_at
FROM refresh_tokens AS rt
JOIN tenants AS t ON t.id = rt.tenant_id
WHERE rt.token_id = $1
LIMIT 1;

-- name: MarkRefreshTokenUsed :execresult
UPDATE refresh_tokens
SET is_used = TRUE
WHERE token_id = $1;

-- name: RevokeRefreshTokenFamily :execresult
DELETE FROM refresh_tokens
WHERE token_family_id = $1;
