-- name: SaveSSOSession :exec
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
INSERT INTO sso_sessions (
    token_hash,
    id,
    tenant_id,
    partition_id,
    user_profile_id,
    state,
    identity_provider_id,
    acr,
    amr,
    auth_time,
    created_at,
    last_seen_at,
    expires_at,
    idle_expires_at
)
SELECT
    @token_hash::bytea,
    @id::uuid,
    tenant.id,
    @partition_id::bigint,
    sqlc.narg('user_profile_id')::uuid,
    @state::sso_session_state,
    sqlc.narg('identity_provider_id')::uuid,
    @acr::text,
    @amr::text[],
    @auth_time::timestamptz,
    @created_at::timestamptz,
    @last_seen_at::timestamptz,
    @expires_at::timestamptz,
    @idle_expires_at::timestamptz
FROM tenant;

-- name: GetLiveSSOSession :one
-- One primary-key read per browser request, for a pending or an active session. Expired and idle sessions are
-- invisible, even before housekeeping runs. Callers decide what a pending session may be used for.
SELECT
    s.token_hash,
    s.id,
    t.tenant_uuid,
    s.partition_id,
    s.user_profile_id,
    s.state,
    s.identity_provider_id,
    s.acr,
    s.amr,
    s.auth_time,
    s.created_at,
    s.last_seen_at,
    s.expires_at,
    s.idle_expires_at
FROM sso_sessions s
JOIN tenants t ON t.id = s.tenant_id
WHERE s.token_hash = @token_hash::bytea
  AND t.tenant_uuid = @tenant_uuid::uuid
  AND s.expires_at > @now::timestamptz
  AND s.idle_expires_at > @now::timestamptz;

-- name: PromoteSSOSession :execrows
-- Turns a pending session into an active one under a fresh secret. It only matches a pending session of this tenant
-- and partition that has not expired, so a replayed or stolen promotion changes nothing.
UPDATE sso_sessions
SET token_hash = @new_token_hash::bytea,
    state = 'ACTIVE',
    user_profile_id = @user_profile_id::uuid,
    identity_provider_id = sqlc.narg('identity_provider_id')::uuid,
    acr = @acr::text,
    amr = @amr::text[],
    auth_time = @auth_time::timestamptz,
    last_seen_at = @last_seen_at::timestamptz,
    expires_at = @expires_at::timestamptz,
    idle_expires_at = @idle_expires_at::timestamptz
WHERE id = @id::uuid
  AND state = 'PENDING'
  AND partition_id = @partition_id::bigint
  AND expires_at > @now::timestamptz
  AND tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid LIMIT 1);

-- name: TouchSSOSession :exec
UPDATE sso_sessions
SET last_seen_at = @last_seen_at::timestamptz,
    idle_expires_at = @idle_expires_at::timestamptz
WHERE token_hash = @token_hash::bytea
  AND state = 'ACTIVE'
  AND tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid LIMIT 1);

-- name: DeleteSSOSessionByID :exec
DELETE FROM sso_sessions
WHERE id = @id::uuid
  AND tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid LIMIT 1);

-- name: DeleteSSOSessionsByUser :exec
DELETE FROM sso_sessions
WHERE user_profile_id = @user_profile_id::uuid
  AND tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid LIMIT 1);

-- name: PurgeSSOSessionsByTenant :exec
DELETE FROM sso_sessions
WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid LIMIT 1);
