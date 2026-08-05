-- +goose Up
ALTER TABLE applications ADD COLUMN redirect_uri VARCHAR(512) NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE applications DROP COLUMN IF EXISTS redirect_uri;
