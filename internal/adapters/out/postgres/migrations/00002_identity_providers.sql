-- +goose Up
-- Create user_profiles table
CREATE TABLE user_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    preferred_username VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, preferred_username),
    UNIQUE(tenant_id, email)
);

-- Create identity_providers table (if not exists, but we know it's referenced)
CREATE TABLE IF NOT EXISTS identity_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    idp_type VARCHAR(50) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    alias_name VARCHAR(255) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create passwords table
CREATE TABLE passwords (
    user_profile_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
    identity_provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_profile_id, identity_provider_id)
);

-- Create identities table
CREATE TABLE identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_profile_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
    identity_provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    external_identity_id VARCHAR(255) NOT NULL,
    login_count INTEGER NOT NULL DEFAULT 0,
    last_login_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_login_attempt TIMESTAMP WITH TIME ZONE,
    blocked BOOLEAN NOT NULL DEFAULT FALSE,
    coupled_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(user_profile_id, identity_provider_id)
);

-- Create interaction_sessions table
CREATE TABLE interaction_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge VARCHAR(255) NOT NULL,
    code_challenge_method VARCHAR(50) NOT NULL,
    idp_hint VARCHAR(255),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Alter applications table to add allowed_idps and default_idp
ALTER TABLE applications ADD COLUMN allowed_idps TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE applications ADD COLUMN default_idp VARCHAR(255);

-- +goose Down
ALTER TABLE applications DROP COLUMN default_idp;
ALTER TABLE applications DROP COLUMN allowed_idps;
DROP TABLE IF EXISTS interaction_sessions;
DROP TABLE IF EXISTS identities;
DROP TABLE IF EXISTS passwords;
DROP TABLE IF EXISTS identity_providers;
DROP TABLE IF EXISTS user_profiles;
