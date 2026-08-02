-- +goose Up
ALTER TABLE tenants ADD COLUMN predefined_audiences TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE applications ADD COLUMN allowed_audiences TEXT[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE applications DROP COLUMN allowed_audiences;
ALTER TABLE tenants DROP COLUMN predefined_audiences;
