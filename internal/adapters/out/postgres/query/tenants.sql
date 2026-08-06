-- name: ResolveTenantByDomain :one
SELECT tenant_uuid, name, domain_name, is_active, created_at, config, default_partition, updated_at
FROM tenants
WHERE domain_name = $1
LIMIT 1;

-- name: ResolveTenantByUUID :one
SELECT tenant_uuid, name, domain_name, is_active, created_at, config, default_partition, updated_at
FROM tenants
WHERE tenant_uuid = $1
LIMIT 1;

-- name: CreateTenant :execresult
INSERT INTO tenants (tenant_uuid, name, domain_name, is_active, created_at, config, default_partition)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_uuid) DO UPDATE SET
    name = EXCLUDED.name,
    domain_name = EXCLUDED.domain_name,
    is_active = EXCLUDED.is_active,
    config = EXCLUDED.config,
    default_partition = EXCLUDED.default_partition;
