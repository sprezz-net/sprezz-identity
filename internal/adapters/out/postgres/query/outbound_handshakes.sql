-- name: SaveOutboundHandshake :exec
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = $1
)
INSERT INTO outbound_handshake_sessions (
    id, tenant_id, identity_provider_id, client_id, code_verifier, expires_at, access_token, target_uri
)
SELECT
    $2,
    tenant.id,
    $3, $4, $5, $6, $7, $8
FROM tenant;

-- name: GetOutboundHandshake :one
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = $1
)
SELECT
    ohs.id, -- Fixed: Qualify column target to eliminate selection ambiguity
    ohs.identity_provider_id,
    ohs.client_id,
    ohs.code_verifier,
    ohs.expires_at,
    ohs.access_token,
    ohs.target_uri
FROM outbound_handshake_sessions ohs
WHERE ohs.id = $2
  AND ohs.tenant_id = (SELECT id FROM tenant);

-- name: DeleteOutboundHandshake :exec
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = $1
)
DELETE FROM outbound_handshake_sessions
WHERE outbound_handshake_sessions.id = $2
  AND outbound_handshake_sessions.tenant_id = (SELECT id FROM tenant);

-- name: PruneExpiredOutboundHandshakes :exec
DELETE FROM outbound_handshake_sessions
WHERE expires_at <= NOW();
