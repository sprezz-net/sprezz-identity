-- +goose Up
-- +goose StatementBegin

-- 1. Create high-efficiency structural join table for allowed client identity provider rules
CREATE TABLE IF NOT EXISTS application_group_idps (
    group_id   UUID NOT NULL,
    idp_id     UUID NOT NULL,
    tenant_id  UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Composite primary key blocks duplicate mapping tracks automatically
    PRIMARY KEY (group_id, idp_id)
);

-- 2. Data Migration Phase: Unnest the character varying array elements and cast to UUID
INSERT INTO application_group_idps (group_id, idp_id, tenant_id)
SELECT
    id AS group_id,
    unnested_idp::UUID AS idp_id,
    tenant_id
FROM (
    SELECT
        id,
        tenant_id,
        -- Natively expand the text array entries into vertical rows
        UNNEST(allowed_idps) AS unnested_idp
    FROM application_groups
    WHERE allowed_idps IS NOT NULL AND allowed_idps <> '{}'
) subquery
-- Defensive filter against unexpected empty strings inside the array elements
WHERE unnested_idp IS NOT NULL AND unnested_idp <> ''
ON CONFLICT (group_id, idp_id) DO NOTHING;

-- 3. Add type-safe default identity provider tracking to your core groups registry
ALTER TABLE application_groups
    ADD COLUMN IF NOT EXISTS default_idp_id UUID DEFAULT NULL;

-- 4. Data Migration Phase for Defaults: Cast text field to type-safe UUID column
UPDATE application_groups
SET default_idp_id = default_idp::UUID
WHERE default_idp IS NOT NULL AND default_idp <> '';

-- 5. Establish structural integrity constraints now that data is clean and isolated
ALTER TABLE application_groups
    ADD CONSTRAINT fk_application_groups_default_idp
    FOREIGN KEY (default_idp_id)
    REFERENCES identity_providers(id)
    ON DELETE RESTRICT;

ALTER TABLE application_group_idps
    ADD CONSTRAINT fk_app_group_idps_group
        FOREIGN KEY (group_id)
        REFERENCES application_groups(id)
        ON DELETE CASCADE;

ALTER TABLE application_group_idps
    ADD CONSTRAINT fk_app_group_idps_idp
        FOREIGN KEY (idp_id)
        REFERENCES identity_providers(id)
        ON DELETE RESTRICT;

-- 6. Create optimized composite coverage index matching your storage port's fetch profile
CREATE INDEX IF NOT EXISTS idx_app_group_idps_lookup
    ON application_group_idps (tenant_id, group_id);

-- 7. Cleanup Phase: Drop old legacy fields safely
ALTER TABLE application_groups DROP COLUMN IF EXISTS allowed_idps;
ALTER TABLE application_groups DROP COLUMN IF EXISTS default_idp;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- 1. Restore the legacy character varying field arrays and structures exactly
ALTER TABLE application_groups ADD COLUMN IF NOT EXISTS allowed_idps CHARACTER VARYING(255)[] DEFAULT NULL;
ALTER TABLE application_groups ADD COLUMN IF NOT EXISTS default_idp CHARACTER VARYING(255) DEFAULT NULL;

-- 2. Reverse Migration Phase: Re-aggregate join rows back into native text arrays
UPDATE application_groups ag
SET allowed_idps = (
    SELECT ARRAY_AGG(idp_id::text)::CHARACTER VARYING(255)[]
    FROM application_group_idps
    WHERE group_id = ag.id
);

-- 3. Restore the default provider column values back to its text representation
UPDATE application_groups ag
SET default_idp = default_idp_id::text
WHERE default_idp_id IS NOT NULL;

-- 4. Tear down performance lookups and operational safety locks
DROP INDEX IF EXISTS idx_app_group_idps_lookup;

-- Split out into clean, individual commands to pass sqlc / goose parsers safely
ALTER TABLE application_groups DROP CONSTRAINT IF EXISTS fk_application_groups_default_idp;

-- 5. Remove join table tracking structures entirely
DROP TABLE IF EXISTS application_group_idps;

-- 6. Remove newly introduced tracking fields from base registries
ALTER TABLE application_groups DROP COLUMN IF EXISTS default_idp_id;

-- +goose StatementEnd
