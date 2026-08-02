-- name: GetTenantIDByUUID :one
SELECT id
FROM tenants
WHERE tenant_uuid = $1
LIMIT 1;

-- name: SaveClient :execresult
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = $1
)
INSERT INTO applications (
    id,
    tenant_id,
    client_id,
    client_secret_hash,
    client_name,
    redirect_uris,
    post_logout_redirect_uris,
    front_channel_logout_uri,
    back_channel_logout_uri,
    grant_types,
    response_types,
    idp_signing_algorithm,
    access_token_lifetime,
    refresh_token_lifetime,
    id_token_lifetime,
    allowed_scopes,
    default_scopes,
    allowed_idps,
    default_idp,
    allowed_audiences
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
    $13,
    $14,
    $15,
    $16,
    $17,
    $18,
    $19,
    $20
FROM tenant
ON CONFLICT (tenant_id, client_id)
DO UPDATE SET
    client_secret_hash = EXCLUDED.client_secret_hash,
    client_name = EXCLUDED.client_name,
    redirect_uris = EXCLUDED.redirect_uris,
    post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
    front_channel_logout_uri = EXCLUDED.front_channel_logout_uri,
    back_channel_logout_uri = EXCLUDED.back_channel_logout_uri,
    grant_types = EXCLUDED.grant_types,
    response_types = EXCLUDED.response_types,
    idp_signing_algorithm = EXCLUDED.idp_signing_algorithm,
    access_token_lifetime = EXCLUDED.access_token_lifetime,
    refresh_token_lifetime = EXCLUDED.refresh_token_lifetime,
    id_token_lifetime = EXCLUDED.id_token_lifetime,
    allowed_scopes = EXCLUDED.allowed_scopes,
    default_scopes = EXCLUDED.default_scopes,
    allowed_idps = EXCLUDED.allowed_idps,
    default_idp = EXCLUDED.default_idp,
    allowed_audiences = EXCLUDED.allowed_audiences;

-- name: GetClient :one
SELECT
    a.id,
    a.tenant_id,
    a.client_id,
    a.client_secret_hash,
    a.client_name,
    a.redirect_uris,
    a.post_logout_redirect_uris,
    a.front_channel_logout_uri,
    a.back_channel_logout_uri,
    a.grant_types,
    a.response_types,
    a.idp_signing_algorithm,
    a.access_token_lifetime,
    a.refresh_token_lifetime,
    a.id_token_lifetime,
    a.allowed_scopes,
    a.default_scopes,
    a.allowed_idps,
    a.default_idp,
    a.allowed_audiences
FROM applications AS a
JOIN tenants AS t ON t.id = a.tenant_id
WHERE t.tenant_uuid = $1
  AND a.client_id = $2
LIMIT 1;
