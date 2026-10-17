-- +goose Up
-- +goose StatementBegin

-- An identity provider is addressed by its alias alone: the idp_hint of an authorize request, the login page and the
-- administrative console ("admin-sso") all resolve a provider by alias without naming a partition or a type. The
-- alias therefore has to identify exactly one provider in a tenant.
--
-- The existing key (tenant, partition, type, alias) stays: the upsert of a provider resolves its own row by it.
-- This adds the tenant-wide key on top, so the same alias can no longer exist twice in a tenant, whatever the type
-- or the partition.

-- Fail with a clear message, not a bare constraint violation, when existing data already breaks the rule.
DO $$
DECLARE
    clash RECORD;
BEGIN
    SELECT t.domain_name, ip.alias_name, count(*) AS providers INTO clash
    FROM identity_providers ip
    JOIN tenants t ON t.id = ip.tenant_id
    GROUP BY t.domain_name, ip.alias_name
    HAVING count(*) > 1
    LIMIT 1;

    IF FOUND THEN
        RAISE EXCEPTION 'tenant % has % identity providers with the alias %; rename all but one before upgrading',
            clash.domain_name, clash.providers, clash.alias_name;
    END IF;
END $$;

ALTER TABLE identity_providers ADD CONSTRAINT uq_identity_providers_tenant_alias UNIQUE (tenant_id, alias_name);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE identity_providers DROP CONSTRAINT IF EXISTS uq_identity_providers_tenant_alias;

-- +goose StatementEnd
