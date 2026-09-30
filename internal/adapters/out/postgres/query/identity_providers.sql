-- name: GetIdentityProviders :many
-- GetIdentityProviders resolves all identity provider configurations assigned to a given tenant.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    id,
    tenant_id,
    idp_type,
    enabled,
    alias_name AS alias,
    name,
    partition_id,
    issuer,
    is_system,
    config,
    created_at,
    updated_at
FROM identity_providers
WHERE tenant_id = (SELECT id FROM tenant)
ORDER BY created_at DESC;

-- name: GetIdentityProvidersByUUIDs :many
-- GetIdentityProvidersByUUIDs executes a high-performance slice filter matching explicit allowed IDP primary keys.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    id,
    tenant_id,
    idp_type,
    enabled,
    alias_name AS alias,
    name,
    partition_id,
    issuer,
    is_system,
    config,
    created_at,
    updated_at
FROM identity_providers
WHERE tenant_id = (SELECT id FROM tenant)
  AND id = ANY(@idp_uuids::uuid[]);

-- name: GetPartitionsWithProviders :many
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    p.id AS partition_id,
    p.alias_name AS partition_name,
    COALESCE(
        json_agg(
            json_build_object(
                'id', idp.id,
                'alias', idp.alias_name,
                'idp_type', idp.idp_type,
                'enabled', idp.enabled,
                'partition_id', idp.partition_id
            )
        ) FILTER (WHERE idp.id IS NOT NULL),
        '[]'::json
    )::json AS providers_json
FROM partitions p
INNER JOIN tenant t ON p.tenant_id = t.id
LEFT JOIN identity_providers idp ON p.id = idp.partition_id AND idp.enabled = TRUE
GROUP BY p.id, p.alias_name
ORDER BY p.alias_name ASC;

-- name: GetIdentityProvidersByTypeAndPartition :many
-- Resolves all identity provider configuration records assigned to a target partition sandbox.
-- This accurately accounts for partitions hosting multiple simultaneous external OIDC providers.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    ip.id,
    ip.tenant_id,
    ip.idp_type,
    ip.enabled,
    ip.alias_name AS alias,
    ip.name,
    ip.partition_id,
    ip.issuer,
    ip.is_system,
    ip.config,
    ip.created_at,
    ip.updated_at
FROM identity_providers ip
INNER JOIN tenant t ON t.id = ip.tenant_id
WHERE ip.partition_id = @partition_id::bigint
  AND ip.idp_type = @idp_type::varchar;

-- name: GetIdentityProviderByAlias :one
-- GetIdentityProviderByAlias pulls a singular active trust configuration path matching a text identifier string.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    id,
    tenant_id,
    idp_type,
    enabled,
    alias_name AS alias,
    name,
    partition_id,
    issuer,
    is_system,
    config,
    created_at,
    updated_at
FROM identity_providers
WHERE tenant_id = (SELECT id FROM tenant)
  AND alias_name = @idp_alias
LIMIT 1;

-- name: GetIdentityProviderByUUID :one
-- GetIdentityProviderByUUID resolves a singular provider configuration using its unique identifier key.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    id,
    tenant_id,
    idp_type,
    enabled,
    alias_name AS alias,
    name,
    partition_id,
    issuer,
    is_system,
    config,
    created_at,
    updated_at
FROM identity_providers
WHERE tenant_id = (SELECT id FROM tenant)
  AND id = @idp_uuid::uuid
LIMIT 1;

-- name: GetEnabledIdentityProviders :many
-- GetEnabledIdentityProviders filters active upstream trust configuration paths for endpoint resolution.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    id,
    tenant_id,
    idp_type,
    enabled,
    alias_name AS alias,
    name,
    partition_id,
    issuer,
    is_system,
    config,
    created_at,
    updated_at
FROM identity_providers
WHERE tenant_id = (SELECT id FROM tenant)
  AND enabled = TRUE
ORDER BY alias_name ASC;

-- name: CreateIdentityProvider :exec
-- CreateIdentityProvider inserts a new identity provider or updates an existing one on conflict.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
INSERT INTO identity_providers (
    id,
    tenant_id,
    idp_type,
    enabled,
    alias_name,
    config,
    name,
    partition_id,
    issuer,
    is_system
)
SELECT
    @id::uuid,
    t.id,
    @idp_type,
    @enabled::boolean,
    @alias_name,
    @config::jsonb,
    @name,
    @partition_id::bigint,
    NULLIF(@issuer::varchar, ''),
    @is_system::boolean
FROM tenant t
ON CONFLICT (tenant_id, partition_id, idp_type, alias_name) DO UPDATE SET
    enabled = EXCLUDED.enabled,
    config = EXCLUDED.config,
    name = EXCLUDED.name,
    issuer = EXCLUDED.issuer,
    -- One-way ratchet: an upsert can flag a provider as system-managed but never clear the flag.
    is_system = identity_providers.is_system OR EXCLUDED.is_system;

-- name: GetIdentityProviderUsage :many
-- GetIdentityProviderUsage reports, for every provider of a tenant, how many user identities are linked to it, which
-- application groups allow it, and when a user last signed in through it.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    ip.id AS provider_id,
    COALESCE((
        SELECT COUNT(*) FROM user_identities ui WHERE ui.identity_provider_id = ip.id
    ), 0)::bigint AS linked_users,
    (
        SELECT MAX(ui.last_login_at) FROM user_identities ui WHERE ui.identity_provider_id = ip.id
    )::timestamptz AS last_login_at,
    COALESCE((
        SELECT ARRAY_AGG(ag.id ORDER BY ag.group_name)
        FROM application_group_idps agi
        JOIN application_groups ag ON ag.id = agi.group_id
        WHERE agi.idp_id = ip.id
    ), '{}'::uuid[])::uuid[] AS group_ids,
    COALESCE((
        SELECT ARRAY_AGG(ag.group_name ORDER BY ag.group_name)
        FROM application_group_idps agi
        JOIN application_groups ag ON ag.id = agi.group_id
        WHERE agi.idp_id = ip.id
    ), '{}'::text[])::text[] AS group_names
FROM identity_providers ip
WHERE ip.tenant_id = (SELECT id FROM tenant);
