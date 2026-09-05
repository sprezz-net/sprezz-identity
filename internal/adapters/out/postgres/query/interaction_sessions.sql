-- name: SaveInteractionSession :exec
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid -- Safe named configuration parameter
    LIMIT 1
)
INSERT INTO interaction_sessions (
    id,
    tenant_id,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    idp_hint,
    expires_at,
    state,
    nonce,
    acr_values
)
SELECT
    @id::uuid,
    tenant.id,
    @client_id,
    @redirect_uri,
    @code_challenge,
    @code_challenge_method,
    @idp_hint,
    @expires_at::timestamptz,
    @state,
    @nonce,
    @acr_values
FROM tenant;

-- name: ConsumeInteractionSession :one
WITH deleted AS (
    DELETE FROM interaction_sessions
    WHERE id = @id::uuid
      AND tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid LIMIT 1) -- Enforces named consistency
    RETURNING
        id,
        client_id,
        redirect_uri,
        code_challenge,
        code_challenge_method,
        idp_hint,
        expires_at,
        state,
        nonce,
        acr_values,
        (SELECT tenant_uuid FROM tenants WHERE id = tenant_id) AS tenant_uuid
)
SELECT
    id,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    idp_hint,
    expires_at,
    state,
    nonce,
    acr_values,
    tenant_uuid
FROM deleted
LIMIT 1;

-- name: GetInteractionSession :one
SELECT
    id,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    idp_hint,
    expires_at,
    state,
    nonce,
    acr_values,
    (SELECT tenant_uuid FROM tenants WHERE id = tenant_id) AS tenant_uuid
FROM interaction_sessions
WHERE id = @id::uuid
  AND tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid LIMIT 1);
