-- name: ResolveTenantByDomain :one
SELECT tenant_uuid, name, domain_name, is_active, created_at, predefined_scopes, predefined_audiences
FROM tenants
WHERE domain_name = $1
LIMIT 1;

-- name: ResolveTenantByUUID :one
SELECT tenant_uuid, name, domain_name, is_active, created_at, predefined_scopes, predefined_audiences
FROM tenants
WHERE tenant_uuid = $1
LIMIT 1;

-- name: CreateTenant :execresult
INSERT INTO tenants (tenant_uuid, name, domain_name, is_active, created_at, predefined_scopes, predefined_audiences)
VALUES ($1, $2, $3, $4, $5, $6, $7);
