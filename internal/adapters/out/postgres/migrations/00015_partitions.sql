-- +goose Up
-- 1. Create partitions table
CREATE TABLE partitions (
    id BIGSERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    alias_name VARCHAR(255) NOT NULL,
    UNIQUE (tenant_id, alias_name)
);

-- 2. Add name and partition_id to identity_providers
ALTER TABLE identity_providers ADD COLUMN name VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE identity_providers ADD COLUMN partition_id BIGINT;

-- 3. Add partition_id to user_profiles
ALTER TABLE user_profiles ADD COLUMN partition_id BIGINT;

-- 4. Add default_partition to tenants
ALTER TABLE tenants ADD COLUMN default_partition BIGINT;

-- 5. Populate partitions for existing tenants and link them
-- +goose StatementBegin
DO $$
DECLARE
    t_rec RECORD;
    default_part_id BIGINT;
    sprezz_part_id BIGINT;
BEGIN
    FOR t_rec IN SELECT id FROM tenants LOOP
        -- Insert default partition with the name of the tenant
        INSERT INTO partitions (tenant_id, name, alias_name)
        SELECT t_rec.id, t.name, 'default'
        FROM tenants t
        WHERE t.id = t_rec.id
        RETURNING id INTO default_part_id;

        -- Insert Sprezz Admin partition
        INSERT INTO partitions (tenant_id, name, alias_name)
        VALUES (t_rec.id, 'Sprezz Admin', 'sprezz_admin')
        RETURNING id INTO sprezz_part_id;

        -- Update tenant's default partition
        UPDATE tenants
        SET default_partition = default_part_id
        WHERE id = t_rec.id;

        -- Update existing user profiles for this tenant
        UPDATE user_profiles
        SET partition_id = default_part_id
        WHERE tenant_id = t_rec.id;

        -- Update existing identity providers for this tenant
        UPDATE identity_providers
        SET partition_id = default_part_id
        WHERE tenant_id = t_rec.id;
    END LOOP;
END $$;
-- +goose StatementEnd

-- 6. Enforce NOT NULL constraints
ALTER TABLE identity_providers ALTER COLUMN partition_id SET NOT NULL;
ALTER TABLE user_profiles ALTER COLUMN partition_id SET NOT NULL;

-- 7. Add foreign key constraints
ALTER TABLE identity_providers ADD CONSTRAINT fk_identity_providers_partition FOREIGN KEY (partition_id) REFERENCES partitions(id) ON DELETE CASCADE;
ALTER TABLE user_profiles ADD CONSTRAINT fk_user_profiles_partition FOREIGN KEY (partition_id) REFERENCES partitions(id) ON DELETE CASCADE;
ALTER TABLE tenants ADD CONSTRAINT fk_tenants_default_partition FOREIGN KEY (default_partition) REFERENCES partitions(id) ON DELETE SET NULL;

-- 8. Drop old unique constraints/indexes on user_profiles
ALTER TABLE user_profiles DROP CONSTRAINT IF EXISTS user_profiles_tenant_id_preferred_username_key;
ALTER TABLE user_profiles DROP CONSTRAINT IF EXISTS user_profiles_tenant_id_email_key;

-- Add new unique constraints
ALTER TABLE user_profiles ADD CONSTRAINT uq_user_profiles_tenant_partition_username UNIQUE (tenant_id, partition_id, preferred_username);
ALTER TABLE user_profiles ADD CONSTRAINT uq_user_profiles_tenant_partition_email UNIQUE (tenant_id, partition_id, email);

-- 9. Recreate unique constraint for identity_providers
ALTER TABLE identity_providers DROP CONSTRAINT IF EXISTS uq_tenant_idp_type_alias;
ALTER TABLE identity_providers ADD CONSTRAINT uq_identity_providers_tenant_partition_type_alias UNIQUE (tenant_id, partition_id, idp_type, alias_name);

-- +goose Down
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS fk_tenants_default_partition;
ALTER TABLE user_profiles DROP CONSTRAINT IF EXISTS fk_user_profiles_partition;
ALTER TABLE identity_providers DROP CONSTRAINT IF EXISTS fk_identity_providers_partition;

ALTER TABLE user_profiles DROP CONSTRAINT IF EXISTS uq_user_profiles_tenant_partition_username;
ALTER TABLE user_profiles DROP CONSTRAINT IF EXISTS uq_user_profiles_tenant_partition_email;
ALTER TABLE user_profiles ADD CONSTRAINT user_profiles_tenant_id_preferred_username_key UNIQUE (tenant_id, preferred_username);
ALTER TABLE user_profiles ADD CONSTRAINT user_profiles_tenant_id_email_key UNIQUE (tenant_id, email);

ALTER TABLE identity_providers DROP CONSTRAINT IF EXISTS uq_identity_providers_tenant_partition_type_alias;
ALTER TABLE identity_providers ADD CONSTRAINT uq_tenant_idp_type_alias UNIQUE (tenant_id, idp_type, alias_name);

ALTER TABLE tenants DROP COLUMN IF EXISTS default_partition;
ALTER TABLE user_profiles DROP COLUMN IF EXISTS partition_id;
ALTER TABLE identity_providers DROP COLUMN IF EXISTS partition_id;
ALTER TABLE identity_providers DROP COLUMN IF EXISTS name;

DROP TABLE IF EXISTS partitions CASCADE;
