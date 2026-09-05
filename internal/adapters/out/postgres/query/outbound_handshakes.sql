-- name: SaveOutboundHandshake :exec
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
)
INSERT INTO outbound_handshake_sessions (
    id,
    tenant_id,
    partition_id,
    identity_provider_id,
    client_id,
    code_verifier,
    created_at,
    expires_at,
    target_uri,
    callback_uri
)
SELECT
    @state_token,
    tenant.id,
    @partition_id::bigint,
    @identity_provider_id::uuid,
    @client_id,
    @code_verifier,
    @created_at::timestamptz,
    @expires_at::timestamptz,
    @target_uri::text,
    @callback_uri::text
FROM tenant;

-- name: ConsumeOutboundHandshake :one
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
)
DELETE FROM outbound_handshake_sessions ohs
WHERE ohs.id = @state_token
  AND ohs.tenant_id = (SELECT id FROM tenant)
RETURNING
    ohs.id,
    ohs.partition_id,
    ohs.identity_provider_id,
    ohs.client_id,
    ohs.code_verifier,
    ohs.created_at,
    ohs.expires_at,
    ohs.target_uri,
    ohs.callback_uri;

-- name: PruneExpiredOutboundHandshakes :exec
DELETE FROM outbound_handshake_sessions
WHERE expires_at <= NOW();
