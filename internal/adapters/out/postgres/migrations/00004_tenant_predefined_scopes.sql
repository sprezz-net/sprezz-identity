-- +goose Up
ALTER TABLE tenants ADD COLUMN predefined_scopes TEXT[] NOT NULL DEFAULT '{openid,profile,email,offline_access}';

-- +goose Down
ALTER TABLE tenants DROP COLUMN predefined_scopes;
