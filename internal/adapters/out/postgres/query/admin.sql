-- name: GetDynamicApplicationsSummary :many
-- Feeds your high-volume Fleet Monitoring view page
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = $1
    LIMIT 1
)
SELECT
    a.id,
    a.client_id,
    a.application_name,
    a.is_enabled,
    a.created_at,
    a.updated_at,
    a.last_used_at,
    p.id AS profile_id,
    p.profile_name,
    g.id AS group_id,
    g.group_name
FROM applications a
JOIN tenant ON a.tenant_id = tenant.id
JOIN application_profiles p ON a.profile_id = p.id AND a.tenant_id = p.tenant_id
JOIN application_groups g ON a.group_id = g.id AND a.tenant_id = g.tenant_id
WHERE a.is_dynamic = TRUE
ORDER BY a.last_used_at DESC;

-- name: GetStaticApplicationsSummary :many
-- Feeds your Administrative Integration view page
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = $1
    LIMIT 1
)
SELECT
    a.id,
    a.client_id,
    a.application_name,
    a.is_enabled,
    a.created_at,
    a.updated_at,
    a.last_used_at,
    p.id AS profile_id,
    p.profile_name,
    g.id AS group_id,
    g.group_name
FROM applications a
JOIN tenant ON a.tenant_id = tenant.id
JOIN application_profiles p ON a.profile_id = p.id AND a.tenant_id = p.tenant_id
JOIN application_groups g ON a.group_id = g.id AND a.tenant_id = g.tenant_id
WHERE a.is_dynamic = FALSE
ORDER BY a.application_name ASC;
