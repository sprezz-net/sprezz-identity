-- +goose Up
-- Drop the existing foreign key constraint that deletes audit logs automatically on tenant delete
ALTER TABLE audit_event_log
  DROP CONSTRAINT IF EXISTS audit_event_log_tenant_id_fkey;

-- Re-create the constraint with ON DELETE RESTRICT to block accidental hard deletes and preserve security trails
ALTER TABLE audit_event_log
  ADD CONSTRAINT audit_event_log_tenant_id_fkey
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

-- +goose Down
-- Revert back to cascade delete if necessary
ALTER TABLE audit_event_log
  DROP CONSTRAINT IF EXISTS audit_event_log_tenant_id_fkey;

ALTER TABLE audit_event_log
  ADD CONSTRAINT audit_event_log_tenant_id_fkey
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
