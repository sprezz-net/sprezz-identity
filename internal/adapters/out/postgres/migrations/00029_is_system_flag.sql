-- +goose Up
-- +goose StatementBegin

-- System-managed objects are provisioned by the bootstrap service and protected from
-- destructive or lock-out-prone edits at the domain service layer.
ALTER TABLE tenants ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE application_profiles ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE application_groups ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE applications ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT FALSE;

-- Flag existing bootstrap rows. The 'admin_ui' application is the unique anchor of the admin tenant.
UPDATE tenants
SET is_system = TRUE
WHERE id IN (SELECT tenant_id FROM applications WHERE client_id = 'admin_ui');

UPDATE applications
SET is_system = TRUE
WHERE client_id = 'admin_ui';

UPDATE application_profiles
SET is_system = TRUE
WHERE id IN (SELECT profile_id FROM applications WHERE client_id = 'admin_ui');

UPDATE application_groups
SET is_system = TRUE
WHERE id IN (SELECT group_id FROM applications WHERE client_id = 'admin_ui')
   OR (
        group_name = 'sprezz_local_admin_group'
        AND tenant_id IN (SELECT tenant_id FROM applications WHERE client_id = 'admin_ui')
   );

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE applications DROP COLUMN IF EXISTS is_system;
ALTER TABLE application_groups DROP COLUMN IF EXISTS is_system;
ALTER TABLE application_profiles DROP COLUMN IF EXISTS is_system;
ALTER TABLE tenants DROP COLUMN IF EXISTS is_system;

-- +goose StatementEnd
