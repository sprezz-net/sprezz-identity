-- name: SaveAuthSession :exec
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
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
    acr_values,
    identity_provider_id,
    identity_provider_alias
)
SELECT
    @code,
    tenant.id,
    @client_id,
    @subject,
    @code_challenge,
    @challenge_method,
    @redirect_uri,
    @scopes,
    @expires_at::timestamptz,
    @session_id,
    @state,
    @nonce,
    @acr_values,
    @identity_provider_id::uuid,
    @identity_provider_alias
FROM tenant;

-- name: ConsumeAuthSession :one
WITH deleted AS (
    DELETE FROM auth_sessions
    WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid)
      AND code = @code
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
        acr_values,
        identity_provider_id,
        identity_provider_alias
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
    acr_values,
    identity_provider_id,
    identity_provider_alias
FROM deleted
LIMIT 1;

-- name: RevokeSession :exec
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
DELETE FROM auth_sessions
WHERE tenant_id = tenant.id
  AND subject = @subject
  AND client_id = @client_id;

-- name: PurgeAuthSessionsByTenant :exec
DELETE FROM auth_sessions
WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid);
