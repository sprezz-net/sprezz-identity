-- name: ResolveTenantByDomain :one
SELECT tenant_uuid, name, domain_name, is_active, created_at, config, default_partition, updated_at, encrypted_dek, dek_nonce
FROM tenants
WHERE domain_name = $1
LIMIT 1;

-- name: ResolveTenantByUUID :one
SELECT tenant_uuid, name, domain_name, is_active, created_at, config, default_partition, updated_at, encrypted_dek, dek_nonce
FROM tenants
WHERE tenant_uuid = $1
LIMIT 1;

-- name: CreateTenant :execresult
INSERT INTO tenants (tenant_uuid, name, domain_name, is_active, created_at, config, default_partition, encrypted_dek, dek_nonce)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (tenant_uuid) DO UPDATE SET
    name = EXCLUDED.name,
    domain_name = EXCLUDED.domain_name,
    is_active = EXCLUDED.is_active,
    config = EXCLUDED.config,
    default_partition = EXCLUDED.default_partition,
    encrypted_dek = COALESCE(EXCLUDED.encrypted_dek, tenants.encrypted_dek),
    dek_nonce = COALESCE(EXCLUDED.dek_nonce, tenants.dek_nonce);

-- name: UpdateTenantDEK :exec
UPDATE tenants
SET
    encrypted_dek = $2,
    dek_nonce = $3,
    updated_at = NOW()
WHERE tenant_uuid = $1;
