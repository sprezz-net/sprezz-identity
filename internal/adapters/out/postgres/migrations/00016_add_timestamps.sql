-- +goose Up
-- Create trigger function to update updated_at timestamp
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';
-- +goose StatementEnd

-- 1. applications
ALTER TABLE applications ADD COLUMN created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW();
ALTER TABLE applications ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW();
CREATE TRIGGER update_applications_updated_at
    BEFORE UPDATE ON applications
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- 2. identity_providers
ALTER TABLE identity_providers ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW();
CREATE TRIGGER update_identity_providers_updated_at
    BEFORE UPDATE ON identity_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- 3. passwords
ALTER TABLE passwords ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW();
CREATE TRIGGER update_passwords_updated_at
    BEFORE UPDATE ON passwords
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- 4. tenants
ALTER TABLE tenants ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW();
CREATE TRIGGER update_tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- 5. user_profiles
ALTER TABLE user_profiles ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW();
CREATE TRIGGER update_user_profiles_updated_at
    BEFORE UPDATE ON user_profiles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();


-- +goose Down
DROP TRIGGER IF EXISTS update_user_profiles_updated_at ON user_profiles;
ALTER TABLE user_profiles DROP COLUMN IF EXISTS updated_at;

DROP TRIGGER IF EXISTS update_tenants_updated_at ON tenants;
ALTER TABLE tenants DROP COLUMN IF EXISTS updated_at;

DROP TRIGGER IF EXISTS update_passwords_updated_at ON passwords;
ALTER TABLE passwords DROP COLUMN IF EXISTS updated_at;

DROP TRIGGER IF EXISTS update_identity_providers_updated_at ON identity_providers;
ALTER TABLE identity_providers DROP COLUMN IF EXISTS updated_at;

DROP TRIGGER IF EXISTS update_applications_updated_at ON applications;
ALTER TABLE applications DROP COLUMN IF EXISTS updated_at;
ALTER TABLE applications DROP COLUMN IF EXISTS created_at;

DROP FUNCTION IF EXISTS update_updated_at_column();
