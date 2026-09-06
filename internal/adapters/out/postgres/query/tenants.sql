-- name: GetTenantIDByUUID :one
-- GetTenantIDByUUID resolves the internal sequential primary key integer
-- ID for an application tenant using its public tracking UUID boundary.
SELECT id
FROM tenants
WHERE tenant_uuid = @tenant_uuid::uuid
LIMIT 1;

-- name: ResolveTenantByDomain :one
-- ResolveTenantByDomain loads the complete operational context metadata
-- record for a tenant using its unique canonical host domain string.
SELECT tenant_uuid, name, domain_name, is_active, created_at, config, default_partition, updated_at, encrypted_dek, dek_nonce
FROM tenants
WHERE domain_name = @domain_name
LIMIT 1;

-- name: ResolveTenantByUUID :one
-- ResolveTenantByUUID loads the complete operational context metadata
-- record for a tenant using its public tracking UUID boundary.
SELECT tenant_uuid, name, domain_name, is_active, created_at, config, default_partition, updated_at, encrypted_dek, dek_nonce
FROM tenants
WHERE tenant_uuid = @tenant_uuid::uuid
LIMIT 1;

-- name: CreateTenant :one
-- CreateTenant inserts or updates a core tenant profile partition block,
-- returning its assigned internal auto-incrementing integer key.
INSERT INTO tenants (
    tenant_uuid,
    name,
    domain_name,
    is_active,
    created_at,
    config,
    default_partition,
    encrypted_dek,
    dek_nonce
)
VALUES (
    @tenant_uuid::uuid,
    @name,
    @domain_name,
    @is_active,
    @created_at::timestamptz,
    @config,
    NULLIF(@default_partition::bigint, 0),
    @encrypted_dek,
    @dek_nonce
)
ON CONFLICT (tenant_uuid) DO UPDATE SET
    name = EXCLUDED.name,
    domain_name = EXCLUDED.domain_name,
    is_active = EXCLUDED.is_active,
    config = EXCLUDED.config,
    default_partition = EXCLUDED.default_partition,
    encrypted_dek = COALESCE(EXCLUDED.encrypted_dek, tenants.encrypted_dek),
    dek_nonce = COALESCE(EXCLUDED.dek_nonce, tenants.dek_nonce)
RETURNING id;

-- name: UpdateTenantDEK :exec
-- UpdateTenantDEK mutates the cryptographic Data Encryption Key (DEK) blobs
-- assigned to protect a tenant's field secrets.
UPDATE tenants
SET
    encrypted_dek = @encrypted_dek,
    dek_nonce = @dek_nonce,
    updated_at = NOW()
WHERE tenant_uuid = @tenant_uuid::uuid;

-- name: UpdateTenantDefaultPartition :exec
-- UpdateTenantDefaultPartition sets the default partition foreign key link column
-- on the root tenant record to wrap up the self-linking side effect pass.
UPDATE tenants
SET default_partition = @default_partition::bigint
WHERE tenant_uuid = @tenant_uuid::uuid;
