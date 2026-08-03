-- +goose Up
-- Add config JSONB column
ALTER TABLE tenants ADD COLUMN config JSONB NOT NULL DEFAULT '{}';

-- Migrate existing columns predefined_scopes and predefined_audiences to config json
UPDATE tenants
SET config = jsonb_build_object(
    'predefined_scopes', predefined_scopes,
    'predefined_audiences', predefined_audiences,
    'default_redirect_uri', '',
    'redirect_whitelist', '[]'::jsonb
);

-- Drop columns predefined_scopes and predefined_audiences
ALTER TABLE tenants DROP COLUMN predefined_scopes;
ALTER TABLE tenants DROP COLUMN predefined_audiences;

-- +goose Down
-- Recreate columns predefined_scopes and predefined_audiences
ALTER TABLE tenants ADD COLUMN predefined_scopes TEXT[] NOT NULL DEFAULT '{openid,profile,email,offline_access}';
ALTER TABLE tenants ADD COLUMN predefined_audiences TEXT[] NOT NULL DEFAULT '{}';

-- Restore columns from config JSON
UPDATE tenants
SET predefined_scopes = ARRAY(SELECT jsonb_array_elements_text(config->'predefined_scopes')),
    predefined_audiences = ARRAY(SELECT jsonb_array_elements_text(config->'predefined_audiences'));

-- Drop config JSONB column
ALTER TABLE tenants DROP COLUMN config;
