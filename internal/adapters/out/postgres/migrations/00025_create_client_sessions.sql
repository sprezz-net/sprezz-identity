-- +goose Up
-- +goose StatementBegin
CREATE TABLE client_sessions (
    tenant_id UUID NOT NULL,
    session_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    associated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (tenant_id, session_id, client_id)
);

-- Index to optimize rapid session lookups during single logout (SLO) fanning-out
CREATE INDEX idx_client_sessions_lookup
ON client_sessions (tenant_id, session_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_client_sessions_lookup;
DROP TABLE IF EXISTS client_sessions;
-- +goose StatementEnd
