-- name: SaveFederatedSession :exec
-- Saves or updates a federated upstream cryptographic session state securely [5.7]
WITH tenant_context AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
INSERT INTO federated_sessions (
    id,
    tenant_id,
    partition_id,
    session_id,
    identity_provider_id,
    upstream_subject,
    upstream_access_token,
    upstream_id_token,
    upstream_refresh_token,
    created_at,
    expires_at
) VALUES (
    @id::uuid,
    (SELECT id FROM tenant_context),
    @partition_id::bigint,
    @session_id::varchar,
    @identity_provider_id::uuid,
    @upstream_subject::varchar,
    @upstream_access_token::text,
    @upstream_id_token::text,
    @upstream_refresh_token::text,
    @created_at::timestamptz,
    @expires_at::timestamptz
)
ON CONFLICT (id) DO UPDATE SET
    upstream_access_token = EXCLUDED.upstream_access_token,
    upstream_id_token = EXCLUDED.upstream_id_token,
    upstream_refresh_token = EXCLUDED.upstream_refresh_token,
    expires_at = EXCLUDED.expires_at;

-- name: GetFederatedSessionByLocalSessionID :one
-- Retrieves upstream token data using our native session ID tracking reference [7.3]
WITH tenant_context AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    fs.id,
    fs.tenant_id,
    fs.partition_id,
    fs.session_id,
    fs.identity_provider_id,
    fs.upstream_subject,
    fs.upstream_access_token,
    fs.upstream_id_token,
    fs.upstream_refresh_token,
    fs.created_at,
    fs.expires_at
FROM federated_sessions fs
JOIN tenant_context tc ON fs.tenant_id = tc.id
WHERE fs.partition_id = @partition_id::bigint
  AND fs.session_id = @session_id::varchar
LIMIT 1;

-- name: FindFederatedSessionByUpstreamSubject :one
-- Coordinates incoming upstream Back-Channel SLO calls using provider claims [7.2]
WITH tenant_context AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    fs.id,
    fs.tenant_id,
    fs.partition_id,
    fs.session_id,
    fs.identity_provider_id,
    fs.upstream_subject,
    fs.upstream_access_token,
    fs.upstream_id_token,
    fs.upstream_refresh_token,
    fs.created_at,
    fs.expires_at
FROM federated_sessions fs
JOIN tenant_context tc ON fs.tenant_id = tc.id
WHERE fs.identity_provider_id = @identity_provider_id::uuid
  AND fs.upstream_subject = @upstream_subject::varchar
LIMIT 1;

-- name: DeleteFederatedSession :exec
-- Explicitly purges a single federated mapping layer during targeted single-logouts [7.1]
WITH tenant_context AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
DELETE FROM federated_sessions fs
USING tenant_context tc
WHERE fs.tenant_id = tc.id
  AND fs.partition_id = @partition_id::bigint
  AND fs.session_id = @session_id::varchar;

-- name: PruneExpiredFederatedSessions :execrows
-- Clears out obsolete upstream tokens matching your 15-minute background cleaning intervals [6.3]
DELETE FROM federated_sessions
WHERE expires_at <= @now::timestamptz;
