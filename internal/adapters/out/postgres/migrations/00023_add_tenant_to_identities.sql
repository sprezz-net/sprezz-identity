-- +goose Up
-- +goose StatementBegin

-- 1. Add tenant_id and partition_id as nullable fields initially to permit safe data backfilling
ALTER TABLE identities
    ADD COLUMN tenant_id INTEGER,
    ADD COLUMN partition_id BIGINT;

-- 2. Transactionally backfill existing records by mapping transitively through identity provider configurations
UPDATE identities i
SET
    tenant_id = ip.tenant_id,
    partition_id = ip.partition_id
FROM identity_providers ip
WHERE ip.id = i.identity_provider_id;

-- 3. Enforce strict structural invariants by applying NOT NULL constraints
ALTER TABLE identities
    ALTER COLUMN tenant_id SET NOT NULL,
    ALTER COLUMN partition_id SET NOT NULL;

-- 4. Drop the historic, single-column foreign key constraint to make room for the optimized integrity wall
ALTER TABLE identities
    DROP CONSTRAINT IF EXISTS fk_identities_identity_provider,
    DROP CONSTRAINT IF EXISTS fk_identities_tenant_provider_integrity;

-- 4.5 Ensure identity_providers has a unique constraint covering (tenant_id, partition_id, id) to satisfy foreign key rules
ALTER TABLE identity_providers
    ADD CONSTRAINT uq_identity_providers_tenant_partition_id UNIQUE (tenant_id, partition_id, id);

-- 5. Establish the multi-column relational integrity safety wall.
-- This structurally guarantees an identity cannot point to a provider belonging to a different tenant OR partition.
ALTER TABLE identities
    ADD CONSTRAINT fk_identities_tenant_partition_provider_integrity
    FOREIGN KEY (tenant_id, partition_id, identity_provider_id)
    REFERENCES identity_providers (tenant_id, partition_id, id)
    ON DELETE CASCADE;

-- 6. Build the composite primary lookup index to maximize the speed of authentication gating check hot-paths
CREATE INDEX idx_identities_hot_path_lookup
    ON identities (tenant_id, partition_id, identity_provider_id, external_identity_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- 1. Remove the high-performance multi-tenant composite lookup index
DROP INDEX IF EXISTS idx_identities_hot_path_lookup;

-- 2. Drop the multi-column relational integrity constraint
ALTER TABLE identities
    DROP CONSTRAINT IF EXISTS fk_identities_tenant_partition_provider_integrity;

-- 2.5 Drop the unique constraint from identity_providers
ALTER TABLE identity_providers
    DROP CONSTRAINT IF EXISTS uq_identity_providers_tenant_partition_id;

-- 3. Restore the classic single-column foreign key restriction
ALTER TABLE identities
    ADD CONSTRAINT fk_identities_identity_provider
    FOREIGN KEY (identity_provider_id)
    REFERENCES identity_providers (id)
    ON DELETE CASCADE;

-- 4. Completely eliminate the denormalized multi-tenancy optimization columns from the schema table
ALTER TABLE identities
    DROP COLUMN IF EXISTS tenant_id,
    DROP COLUMN IF EXISTS partition_id;

-- +goose StatementEnd
