-- name: SavePAR :exec
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid -- Safe named configuration parameter
    LIMIT 1
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
    @request_uri,
    tenant.id,
    @client_id,
    @redirect_uri,
    @code_challenge,
    @code_challenge_method,
    @scopes,
    @state,
    @nonce,
    @idp_hint,
    @acr_values,
    @expires_at::timestamptz -- Explicit type casting preserved cleanly
FROM tenant;

-- name: ConsumePAR :one
WITH deleted AS (
    DELETE FROM pushed_authorization_requests
    WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid) -- Enforces named parameter consistency
      AND request_uri = @request_uri
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
