-- +goose Up
-- +goose StatementBegin

-- Providers the platform itself depends on are flagged so the domain services refuse to edit or delete them:
--   * 'admin-sso': every tenant's admin console signs in through it, so it exists in every tenant;
--   * the local accounts provider of the system (admin) tenant, which backs the break-glass sign-in.
ALTER TABLE identity_providers ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE identity_providers
SET is_system = TRUE
WHERE (alias_name = 'admin-sso' AND idp_type = 'oidc')
   OR (idp_type = 'username-password' AND tenant_id IN (SELECT id FROM tenants WHERE is_system));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE identity_providers DROP COLUMN IF EXISTS is_system;

-- +goose StatementEnd
