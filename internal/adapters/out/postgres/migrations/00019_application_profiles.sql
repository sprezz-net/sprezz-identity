-- +goose Up
-- +goose StatementBegin

-- 1. Create the central blueprint profile table with the auth method column added
CREATE TABLE application_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    profile_name VARCHAR(100) NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    token_endpoint_auth_method VARCHAR(50) NOT NULL DEFAULT 'client_secret_basic',
    grant_types VARCHAR(50)[] NOT NULL,
    response_types VARCHAR(50)[] NOT NULL,
    access_token_lifetime INTERVAL NOT NULL,
    refresh_token_lifetime INTERVAL NOT NULL,
    id_token_lifetime INTERVAL NOT NULL,
    enforce_rtr BOOLEAN NOT NULL DEFAULT TRUE,
    signing_algorithm VARCHAR(20) NOT NULL DEFAULT 'RS256',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_profile_tenant_id UNIQUE (id, tenant_id),
    CONSTRAINT uq_tenant_profile_name UNIQUE (tenant_id, profile_name)
);

-- 2. Create the application groups table
CREATE TABLE application_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_name VARCHAR(100) NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    redirect_uri TEXT NOT NULL DEFAULT '',
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    post_logout_redirect_uris TEXT[] DEFAULT '{}',
    front_channel_logout_uri TEXT DEFAULT '',
    back_channel_logout_uri TEXT DEFAULT '',
    allowed_scopes VARCHAR(100)[] DEFAULT '{openid,profile,email}' NOT NULL,
    default_scopes VARCHAR(100)[] DEFAULT '{openid}' NOT NULL,
    allowed_audiences VARCHAR(255)[] NOT NULL,
    allowed_idps VARCHAR(255)[] DEFAULT '{}' NOT NULL,
    default_idp VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_group_tenant_id UNIQUE (id, tenant_id),
    CONSTRAINT uq_tenant_group_name UNIQUE (tenant_id, group_name),
    CONSTRAINT chk_group_default_scopes_subset CHECK (default_scopes <@ allowed_scopes)
);

-- 3. Create a temporary staging profile table for migration processing
CREATE TEMP TABLE tmp_app_profiles_map (
    old_app_id UUID PRIMARY KEY,
    new_profile_id UUID NOT NULL
);

-- 4. Create a temporary staging table to link original application IDs directly to their new group IDs
CREATE TEMP TABLE tmp_app_groups_map (
    old_app_id UUID PRIMARY KEY,
    new_group_id UUID NOT NULL
);

-- 5. Extract and normalize unique profiles from the old applications data layout
WITH unique_profiles AS (
    SELECT DISTINCT ON (
        tenant_id, grant_types, response_types, client_type,
        access_token_lifetime, refresh_token_lifetime, id_token_lifetime, enforce_rtr, idp_signing_algorithm
    )
        id AS seed_app_id,
        tenant_id,
        grant_types,
        response_types,
        access_token_lifetime,
        refresh_token_lifetime,
        id_token_lifetime,
        enforce_rtr,
        idp_signing_algorithm,
        CASE
            WHEN client_type = 'public' THEN 'none'
            ELSE 'client_secret_basic'
        END as auth_method
    FROM applications
),
inserted_profiles AS (
    INSERT INTO application_profiles (
        tenant_id, profile_name, token_endpoint_auth_method, grant_types, response_types,
        access_token_lifetime, refresh_token_lifetime, id_token_lifetime, enforce_rtr, signing_algorithm
    )
    SELECT
        p.tenant_id,
        'profile_' || substring(p.seed_app_id::text from 1 for 8), -- Generates a unique traceable template name
        p.auth_method, p.grant_types::varchar(50)[], p.response_types::varchar(50)[],
        p.access_token_lifetime, p.refresh_token_lifetime, p.id_token_lifetime, p.enforce_rtr, p.idp_signing_algorithm
    FROM unique_profiles p
    RETURNING id, tenant_id, token_endpoint_auth_method, grant_types, response_types, access_token_lifetime, refresh_token_lifetime, id_token_lifetime, enforce_rtr, signing_algorithm
)
-- Map every existing application back to its newly generated profile assignment
INSERT INTO tmp_app_profiles_map (old_app_id, new_profile_id)
SELECT a.id, ip.id
FROM applications a
JOIN inserted_profiles ip ON
    a.tenant_id = ip.tenant_id AND
    a.grant_types = ip.grant_types::text[] AND
    a.response_types = ip.response_types::text[] AND
    a.access_token_lifetime = ip.access_token_lifetime AND
    a.refresh_token_lifetime = ip.refresh_token_lifetime AND
    a.id_token_lifetime = ip.id_token_lifetime AND
    a.enforce_rtr = ip.enforce_rtr AND
    a.idp_signing_algorithm = ip.signing_algorithm AND
    (CASE WHEN a.client_type = 'public' THEN 'none' ELSE 'client_secret_basic' END) = ip.token_endpoint_auth_method;

-- 6. Extract and normalize unique routing groups from the old applications data layout
WITH unique_groups AS (
    SELECT DISTINCT ON (
        tenant_id, redirect_uri, redirect_uris, post_logout_redirect_uris,
        front_channel_logout_uri, back_channel_logout_uri, allowed_scopes, default_scopes, allowed_audiences, allowed_idps, default_idp
    )
        id AS seed_app_id, tenant_id, redirect_uri, redirect_uris, post_logout_redirect_uris,
        front_channel_logout_uri, back_channel_logout_uri, allowed_scopes, default_scopes, allowed_audiences, allowed_idps, default_idp
    FROM applications
),
inserted_groups AS (
    INSERT INTO application_groups (
        tenant_id, group_name, redirect_uri, redirect_uris, post_logout_redirect_uris,
        front_channel_logout_uri, back_channel_logout_uri, allowed_scopes, default_scopes, allowed_audiences, allowed_idps, default_idp
    )
    SELECT
        g.tenant_id,
        'group_' || substring(g.seed_app_id::text from 1 for 8),
        g.redirect_uri, g.redirect_uris, g.post_logout_redirect_uris,
        g.front_channel_logout_uri, g.back_channel_logout_uri,
        g.allowed_scopes::varchar(100)[], g.default_scopes::varchar(100)[], g.allowed_audiences::varchar(255)[],
        g.allowed_idps, g.default_idp
    FROM unique_groups g
    RETURNING id, tenant_id, redirect_uri, redirect_uris, post_logout_redirect_uris, front_channel_logout_uri, back_channel_logout_uri, allowed_scopes, default_scopes, allowed_audiences, allowed_idps, default_idp
)
-- Map every existing application back to its newly generated routing group assignment
INSERT INTO tmp_app_groups_map (old_app_id, new_group_id)
SELECT a.id, ig.id
FROM applications a
JOIN inserted_groups ig ON
    a.tenant_id = ig.tenant_id AND
    a.redirect_uri = ig.redirect_uri AND
    a.redirect_uris::text[] = ig.redirect_uris::text[] AND
    a.post_logout_redirect_uris::text[] = ig.post_logout_redirect_uris::text[] AND
    a.front_channel_logout_uri = ig.front_channel_logout_uri AND
    a.back_channel_logout_uri = ig.back_channel_logout_uri AND
    a.allowed_scopes::text[] = ig.allowed_scopes::text[] AND
    a.default_scopes::text[] = ig.default_scopes::text[] AND
    a.allowed_audiences::text[] = ig.allowed_audiences::text[] AND
    a.allowed_idps::text[] = ig.allowed_idps::text[] AND
    (a.default_idp IS NOT DISTINCT FROM ig.default_idp);

-- 7. Rename the old applications table to create the new lean layout variant
ALTER TABLE applications RENAME TO old_applications;
DROP TRIGGER IF EXISTS update_applications_updated_at ON old_applications;

-- 8. Create the newly normalized applications table structure (Lightweight Identity Only)
CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    profile_id UUID NOT NULL,
    group_id UUID NOT NULL,
    application_name VARCHAR(255) NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255),
    is_dynamic BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_app_profile_tenant FOREIGN KEY (profile_id, tenant_id)
        REFERENCES application_profiles(id, tenant_id) ON DELETE RESTRICT,
    CONSTRAINT fk_app_group_tenant FOREIGN KEY (group_id, tenant_id)
        REFERENCES application_groups(id, tenant_id) ON DELETE RESTRICT
);

-- 9. Hydrate the clean applications records by combining our mapping tables
INSERT INTO applications (
    id, tenant_id, profile_id, group_id, application_name, client_id, client_secret_hash, is_dynamic, created_at, updated_at
)
SELECT
    oa.id,
    oa.tenant_id,
    pm.new_profile_id,
    gm.new_group_id,
    oa.client_name, -- Migrating the name into the single descriptive entry field
    oa.client_id,
    oa.client_secret_hash,
    false, -- Default configuration marker fallback
    oa.created_at,
    oa.updated_at
FROM old_applications oa
JOIN tmp_app_profiles_map pm ON oa.id = pm.old_app_id
JOIN tmp_app_groups_map gm ON oa.id = gm.old_app_id;

-- 10. Clean up our temporary data layout states safely
DROP TABLE old_applications CASCADE;

-- 11. Finalize with performance indexes
CREATE INDEX idx_applications_tenant_client ON applications USING btree (tenant_id, client_id);
CREATE INDEX idx_applications_profile_id ON applications USING btree (profile_id);
CREATE INDEX idx_applications_group_id ON applications USING btree (group_id);
CREATE INDEX idx_applications_dynamic_cleanup ON applications(tenant_id, last_used_at) WHERE is_dynamic = TRUE;

-- 12. Attach updating behaviors to your shared blueprints layout layers
CREATE TRIGGER update_application_profiles_updated_at
    BEFORE UPDATE ON application_profiles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_application_groups_updated_at
    BEFORE UPDATE ON application_groups
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_applications_updated_at
    BEFORE UPDATE ON applications
    FOR EACH ROW
    WHEN (
        -- Only fire if any configuration parameters actually changed
        OLD.application_name IS DISTINCT FROM NEW.application_name OR
        OLD.client_id IS DISTINCT FROM NEW.client_id OR
        OLD.client_secret_hash IS DISTINCT FROM NEW.client_secret_hash OR
        OLD.profile_id IS DISTINCT FROM NEW.profile_id OR
        OLD.group_id IS DISTINCT FROM NEW.group_id OR
        OLD.is_enabled IS DISTINCT FROM NEW.is_enabled
    )
    EXECUTE FUNCTION update_updated_at_column();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- 1. Create a temporary staging table to reconstruct the original flat layout
CREATE TEMP TABLE tmp_reconstructed_applications AS
SELECT
    a.id,
    a.tenant_id,
    a.client_id,
    a.client_secret_hash,
    a.application_name AS client_name, -- Map name back to client_name
    g.redirect_uris,
    g.post_logout_redirect_uris,
    g.front_channel_logout_uri,
    g.back_channel_logout_uri,
    p.grant_types::text[] AS grant_types, -- Cast types back to text array
    p.response_types::text[] AS response_types,
    p.signing_algorithm AS idp_signing_algorithm,
    p.access_token_lifetime,
    p.refresh_token_lifetime,
    p.id_token_lifetime,
    g.allowed_scopes::text[] AS allowed_scopes,
    g.default_scopes::text[] AS default_scopes,
    g.allowed_idps,
    g.default_idp,
    g.allowed_audiences::text[] AS allowed_audiences,
    CASE
        WHEN p.token_endpoint_auth_method = 'none' THEN 'public'::character varying(50)
        ELSE 'confidential'::character varying(50)
    END AS client_type, -- Convert auth method rule back to flat client_type scalar
    g.redirect_uri,
    p.enforce_rtr,
    a.created_at,
    a.updated_at
FROM applications a
JOIN application_profiles p ON a.profile_id = p.id
JOIN application_groups g ON a.group_id = g.id;

-- 2. Drop the 3 new tables cleanly using CASCADE to drop dependent indexes/FKs
DROP TRIGGER IF EXISTS update_applications_updated_at ON applications;
DROP TRIGGER IF EXISTS update_application_groups_updated_at ON application_groups;
DROP TRIGGER IF EXISTS update_application_profiles_updated_at ON application_profiles;
DROP TABLE IF EXISTS applications CASCADE;
DROP TABLE IF EXISTS application_groups CASCADE;
DROP TABLE IF EXISTS application_profiles CASCADE;

-- 3. Re-create the original flat applications table exactly as it was
CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    client_secret_hash VARCHAR(255),
    client_name VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    front_channel_logout_uri VARCHAR(512) DEFAULT '',
    back_channel_logout_uri VARCHAR(512) DEFAULT '',
    grant_types TEXT[] NOT NULL,
    response_types TEXT[] NOT NULL,
    idp_signing_algorithm VARCHAR(50) NOT NULL DEFAULT 'RS256',
    access_token_lifetime INTERVAL NOT NULL DEFAULT '1 hour',
    refresh_token_lifetime INTERVAL NOT NULL DEFAULT '30 days',
    id_token_lifetime INTERVAL NOT NULL DEFAULT '10 minutes',
    allowed_scopes TEXT[] NOT NULL,
    default_scopes TEXT[] NOT NULL DEFAULT '{openid}',
    allowed_idps TEXT[] NOT NULL DEFAULT '{}',
    default_idp VARCHAR(255),
    allowed_audiences TEXT[] NOT NULL DEFAULT '{}',
    client_type VARCHAR(50) NOT NULL DEFAULT 'confidential',
    redirect_uri VARCHAR(512) NOT NULL DEFAULT '',
    enforce_rtr BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, client_id),
    CONSTRAINT chk_default_scopes_subset CHECK (default_scopes <@ allowed_scopes),
    CONSTRAINT chk_client_type CHECK (client_type IN ('public', 'confidential', 'internal_ephemeral')),
    CONSTRAINT chk_ephemeral_null_secret CHECK (client_type <> 'internal_ephemeral' OR client_secret_hash IS NULL)
);

-- 4. Repopulate the old table with the merged data from our temporary staging area
INSERT INTO applications (
    id, tenant_id, client_id, client_secret_hash, client_name, redirect_uris,
    post_logout_redirect_uris, front_channel_logout_uri, back_channel_logout_uri,
    grant_types, response_types, idp_signing_algorithm, access_token_lifetime,
    refresh_token_lifetime, id_token_lifetime, allowed_scopes, default_scopes,
    allowed_idps, default_idp, allowed_audiences, client_type, redirect_uri,
    enforce_rtr, created_at, updated_at
)
SELECT
    id, tenant_id, client_id, client_secret_hash, client_name, redirect_uris,
    post_logout_redirect_uris, front_channel_logout_uri, back_channel_logout_uri,
    grant_types, response_types, idp_signing_algorithm, access_token_lifetime,
    refresh_token_lifetime, id_token_lifetime, allowed_scopes, default_scopes,
    allowed_idps, default_idp, allowed_audiences, client_type, redirect_uri,
    enforce_rtr, created_at, updated_at
FROM tmp_reconstructed_applications;

-- 5. Drop the temporary staging table
DROP TABLE IF EXISTS tmp_reconstructed_applications;

-- 6. Restore the unique index pattern if your previous architecture utilized it
CREATE UNIQUE INDEX IF NOT EXISTS applications_tenant_id_client_id_key ON applications USING btree (tenant_id, client_id);
CREATE TRIGGER update_applications_updated_at
    BEFORE UPDATE ON applications
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- +goose StatementEnd
