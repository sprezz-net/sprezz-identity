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
    config,
    created_at,
    updated_at
FROM identity_providers
WHERE tenant_id = (SELECT id FROM tenant)
  AND id = ANY(@idp_uuids::uuid[]);

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
    config,
    created_at,
    updated_at
FROM identity_providers
WHERE tenant_id = (SELECT id FROM tenant)
  AND enabled = TRUE
ORDER BY alias_name ASC;
