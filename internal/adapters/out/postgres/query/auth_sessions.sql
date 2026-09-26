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
WITH deleted_session AS (
    DELETE FROM auth_sessions
    WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid LIMIT 1)
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
    ds.code,
    ds.client_id,
    ds.subject,
    ds.code_challenge,
    ds.challenge_method,
    ds.redirect_uri,
    ds.scopes,
    ds.expires_at,
    ds.session_id,
    ds.state,
    ds.nonce,
    ds.acr_values,
    ds.identity_provider_id,
    ds.identity_provider_alias,
    COALESCE(idp.idp_type, '')::varchar AS identity_provider_type
FROM deleted_session ds
LEFT JOIN identity_providers idp ON ds.identity_provider_id = idp.id;

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
