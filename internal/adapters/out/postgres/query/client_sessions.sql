-- name: RecordClientSessionLink :exec
-- Appends an idempotent entry linking an active browser SSO session to a client application footprint.
-- Uses ON CONFLICT DO NOTHING to ensure zero index bloating if a client re-authorizes within the same session.
INSERT INTO client_sessions (
    tenant_id,
    session_id,
    client_id,
    associated_at
) VALUES (
    @tenant_id::uuid,
    @session_id::varchar,
    @client_id::varchar,
    @associated_at::timestamptz
)
ON CONFLICT (tenant_id, session_id, client_id) DO NOTHING;

-- name: GetApplicationsLogoutContextBySession :many
-- Resolves only the specific applications and logout URIs utilized during the active session lifecycle.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    a.id,
    a.tenant_id,
    a.profile_id,
    a.group_id,
    a.application_name,
    a.is_enabled,
    a.client_id,
    a.client_secret_hash,
    a.is_dynamic,
    a.created_at,
    a.updated_at,
    a.last_used_at,
    ag.front_channel_logout_uri,
    ag.back_channel_logout_uri,
    ap.signing_algorithm
FROM client_sessions cs
JOIN tenant t ON t.id = cs.tenant_id
JOIN applications a ON a.tenant_id = cs.tenant_id AND a.client_id = cs.client_id
JOIN application_groups ag ON ag.tenant_id = a.tenant_id AND ag.id = a.group_id
JOIN application_profiles ap ON ap.tenant_id = a.tenant_id AND ap.id = a.profile_id
WHERE cs.session_id = @session_id::varchar
  AND a.is_enabled = TRUE;

-- name: PruneClientSessionsByExpiry :exec
-- Sweeps and removes client session records that no longer point to an active, valid session context.
-- Invoked by the background worker on 15-minute ticks to preserve O(log N) index traversal speeds.
DELETE FROM client_sessions
WHERE session_id NOT IN (
    SELECT session_id FROM auth_sessions
);
