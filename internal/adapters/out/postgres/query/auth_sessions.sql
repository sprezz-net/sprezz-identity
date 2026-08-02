-- name: SaveAuthSession :execresult
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = $1
)
INSERT INTO auth_sessions (
    code,
    tenant_id,
    client_id,
    subject,
    code_challenge,
    challenge_method,
    redirect_uri,
    scopes,
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
    $8,
    $9
FROM tenant;

-- name: ConsumeAuthSession :one
WITH deleted AS (
    DELETE FROM auth_sessions
    WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1)
      AND code = $2
    RETURNING
        code,
        client_id,
        subject,
        code_challenge,
        challenge_method,
        redirect_uri,
        scopes,
        expires_at
)
SELECT
    code,
    client_id,
    subject,
    code_challenge,
    challenge_method,
    redirect_uri,
    scopes,
    expires_at
FROM deleted
LIMIT 1;
