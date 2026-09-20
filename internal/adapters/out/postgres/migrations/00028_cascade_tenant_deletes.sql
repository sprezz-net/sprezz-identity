-- +goose Up
-- +goose StatementBegin

-- 1. Update tenant_signing_keys to ON DELETE CASCADE
ALTER TABLE tenant_signing_keys
    DROP CONSTRAINT IF EXISTS fk_signing_keys_tenant;

ALTER TABLE tenant_signing_keys
    ADD CONSTRAINT fk_signing_keys_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- 2. Update audit_event_log to ON DELETE CASCADE
ALTER TABLE audit_event_log
    DROP CONSTRAINT IF EXISTS audit_event_log_tenant_id_fkey;

ALTER TABLE audit_event_log
    ADD CONSTRAINT audit_event_log_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- 3. Add foreign key to outbound_handshake_sessions with ON DELETE CASCADE
ALTER TABLE outbound_handshake_sessions
    ADD CONSTRAINT fk_outbound_handshake_sessions_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- 4. Re-bind federated_sessions tracking constraints to support automated ON DELETE CASCADE cascades
ALTER TABLE federated_sessions
    DROP CONSTRAINT IF EXISTS fk_fed_session_tenant_partition;

ALTER TABLE federated_sessions
    ADD CONSTRAINT fk_fed_session_tenant_partition
    FOREIGN KEY (tenant_id, partition_id) REFERENCES partitions(tenant_id, id) ON DELETE CASCADE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- 1. Revert tenant_signing_keys to ON DELETE RESTRICT
ALTER TABLE tenant_signing_keys
    DROP CONSTRAINT IF EXISTS fk_signing_keys_tenant;

ALTER TABLE tenant_signing_keys
    ADD CONSTRAINT fk_signing_keys_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

-- 2. Revert audit_event_log to ON DELETE RESTRICT
ALTER TABLE audit_event_log
    DROP CONSTRAINT IF EXISTS audit_event_log_tenant_id_fkey;

ALTER TABLE audit_event_log
    ADD CONSTRAINT audit_event_log_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

-- 3. Remove foreign key on outbound_handshake_sessions
ALTER TABLE outbound_handshake_sessions
    DROP CONSTRAINT IF EXISTS fk_outbound_handshake_sessions_tenant;

-- 4. Revert federated_sessions constraint mapping back to original RESTRICT profile safeguards
ALTER TABLE federated_sessions
    DROP CONSTRAINT IF EXISTS fk_fed_session_tenant_partition;

ALTER TABLE federated_sessions
    ADD CONSTRAINT fk_fed_session_tenant_partition
    FOREIGN KEY (tenant_id, partition_id) REFERENCES partitions(tenant_id, id) ON DELETE RESTRICT;

-- +goose StatementEnd