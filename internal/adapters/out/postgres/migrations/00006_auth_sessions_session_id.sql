-- +goose Up
ALTER TABLE auth_sessions ADD COLUMN session_id VARCHAR(255) NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE auth_sessions DROP COLUMN session_id;
