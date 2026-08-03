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
    expires_at,
    session_id,
    state,
    nonce,
    acr_values
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
    $9,
    $10,
    $11,
    $12,
    $13
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
        expires_at,
        session_id,
        state,
        nonce,
        acr_values
)
SELECT
    code,
    client_id,
    subject,
    code_challenge,
    challenge_method,
    redirect_uri,
    scopes,
    expires_at,
    session_id,
    state,
    nonce,
    acr_values
FROM deleted
LIMIT 1;

-- name: SavePAR :execresult
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = $1
)
INSERT INTO pushed_authorization_requests (
    request_uri,
    tenant_id,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    scopes,
    state,
    nonce,
    idp_hint,
    acr_values,
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
    $9,
    $10,
    $11,
    $12
FROM tenant;

-- name: ConsumePAR :one
WITH deleted AS (
    DELETE FROM pushed_authorization_requests
    WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1)
      AND request_uri = $2
    RETURNING
        request_uri,
        client_id,
        redirect_uri,
        code_challenge,
        code_challenge_method,
        scopes,
        state,
        nonce,
        idp_hint,
        acr_values,
        expires_at
)
SELECT
    request_uri,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    scopes,
    state,
    nonce,
    idp_hint,
    acr_values,
    expires_at
FROM deleted
LIMIT 1;
