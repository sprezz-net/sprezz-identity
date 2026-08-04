-- +goose Up
-- Deduplicate by keeping the first/oldest row for each (tenant_id, idp_type, alias_name)
DELETE FROM identity_providers ip1
USING identity_providers ip2
WHERE ip1.id > ip2.id
  AND ip1.tenant_id = ip2.tenant_id
  AND ip1.idp_type = ip2.idp_type
  AND ip1.alias_name = ip2.alias_name;

-- Add UNIQUE constraint to prevent future duplication
ALTER TABLE identity_providers ADD CONSTRAINT uq_tenant_idp_type_alias
  UNIQUE (tenant_id, idp_type, alias_name);

-- +goose Down
ALTER TABLE identity_providers DROP CONSTRAINT IF EXISTS uq_tenant_idp_type_alias;
