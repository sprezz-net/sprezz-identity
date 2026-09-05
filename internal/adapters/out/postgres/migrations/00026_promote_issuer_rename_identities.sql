-- +goose Up
-- +goose StatementBegin
-- PHASE 1: Promote issuer property to a real relational column
ALTER TABLE identity_providers
ADD COLUMN issuer VARCHAR(255) NULL;

-- Move values from JSONB config column to native issuer column and remove it from config
UPDATE identity_providers
SET issuer = config ->> 'issuer',
    config = config - 'issuer'
WHERE config ? 'issuer';

-- Enforce strict partition isolation rules (Maximum 1 Username-Password IDP per Partition)
ALTER TABLE identity_providers
ADD CONSTRAINT unique_tenant_partition_issuer UNIQUE (tenant_id, partition_id, issuer);

-- Create a high-speed B-Tree index for lightning-fast lookups during inbound federation callback passes
CREATE INDEX idx_identity_providers_tenant_partition_issuer ON identity_providers (tenant_id, partition_id, issuer);

-- PHASE 2: Structural vocab realignment matching the Go domain model name
ALTER TABLE identities RENAME TO user_identities;

-- Rename primary keys and indices to match the new table name perfectly
ALTER INDEX IF EXISTS identities_pkey RENAME TO user_identities_pkey;
ALTER INDEX IF EXISTS idx_identities_tenant_partition RENAME TO idx_user_identities_tenant_partition;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- REVERSED PHASE 2: Downgrade user_identities back to legacy identities name
ALTER INDEX IF EXISTS idx_user_identities_tenant_partition RENAME TO idx_identities_tenant_partition;
ALTER INDEX IF EXISTS user_identities_pkey RENAME TO identities_pkey;
ALTER TABLE user_identities RENAME TO identities;

-- REVERSED PHASE 1: Strip issuer parameters from identity_providers
DROP INDEX IF EXISTS idx_identity_providers_tenant_partition_issuer;
ALTER TABLE identity_providers DROP CONSTRAINT IF EXISTS unique_tenant_partition_issuer;

-- Restore issuer value back into config JSONB
UPDATE identity_providers
SET config = COALESCE(config, '{}'::jsonb) || jsonb_build_object('issuer', issuer)
WHERE issuer IS NOT NULL;

ALTER TABLE identity_providers DROP COLUMN issuer;
-- +goose StatementEnd
