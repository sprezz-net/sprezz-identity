-- name: GetApplicationByClientID :one
-- GetApplicationByClientID resolves an application, its profile, and its group (including permitted IDP UUIDs) in a single database roundtrip.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    a.id AS app_id,
    a.tenant_id,
    a.client_id,
    a.client_secret_hash,
    a.application_name,
    a.is_enabled AS app_enabled,
    a.is_dynamic,
    a.created_at AS app_created_at,
    a.updated_at AS app_updated_at,
    a.last_used_at,
    p.id AS profile_id,
    p.profile_name,
    p.is_enabled AS profile_enabled,
    p.token_endpoint_auth_method,
    p.grant_types,
    p.response_types,
    p.access_token_lifetime,
    p.refresh_token_lifetime,
    p.id_token_lifetime,
    p.enforce_rtr,
    p.signing_algorithm,
    p.updated_at AS profile_updated_at,
    g.id AS group_id,
    g.group_name,
    g.is_enabled AS group_enabled,
    g.redirect_uri,
    g.redirect_uris,
    g.post_logout_redirect_uris,
    g.front_channel_logout_uri,
    g.back_channel_logout_uri,
    g.allowed_scopes,
    g.default_scopes,
    g.allowed_audiences,
    g.default_idp_id, -- Cleaned name pointing to the type-safe column link
    g.updated_at AS group_updated_at,
    -- Aggregate allowed provider UUIDs directly into a type-safe Go array slice
    COALESCE(
        (SELECT ARRAY_AGG(agi.idp_id)
         FROM application_group_idps agi
         WHERE agi.group_id = g.id),
        '{}'::uuid[]
    )::uuid[] AS allowed_idp_ids
FROM applications a
JOIN tenant ON a.tenant_id = tenant.id
JOIN application_profiles p ON a.profile_id = p.id AND a.tenant_id = p.tenant_id
JOIN application_groups g ON a.group_id = g.id AND a.tenant_id = g.tenant_id
WHERE a.client_id = @client_id
LIMIT 1;

-- name: RegisterApplication :one
-- RegisterApplication inserts a new client registration mapping tightly bound to a multi-tenant isolation anchor.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
INSERT INTO applications (
    id,
    tenant_id,
    profile_id,
    group_id,
    application_name,
    client_id,
    client_secret_hash,
    is_dynamic,
    is_enabled,
    created_at,
    updated_at,
    last_used_at
)
SELECT
    @id::uuid,
    tenant.id,
    @profile_id::uuid,
    @group_id::uuid,
    @application_name,
    @client_id,
    @client_secret_hash,
    @is_dynamic,
    @is_enabled,
    @created_at::timestamptz,
    @updated_at::timestamptz,
    @last_used_at::timestamptz
FROM tenant
RETURNING id;

-- name: UpdateApplication :exec
-- UpdateApplication modifies top-level client structural profile definitions.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
UPDATE applications a
SET
    application_name = @application_name,
    is_enabled = @is_enabled,
    profile_id = @profile_id::uuid,
    group_id = @group_id::uuid
FROM tenant
WHERE a.client_id = @client_id
  AND a.tenant_id = tenant.id;

-- name: GetProfileByName :one
-- GetProfileByName evaluates targeted token lifecycle thresholds assigned to an execution layout.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT id, tenant_id, profile_name, is_enabled, token_endpoint_auth_method, grant_types, response_types, access_token_lifetime, refresh_token_lifetime, id_token_lifetime, enforce_rtr, signing_algorithm, created_at, updated_at
FROM application_profiles
WHERE profile_name = @profile_name AND tenant_id = tenant.id
LIMIT 1;

-- name: GetGroupByName :one
-- GetGroupByName pulls basic routing whitelists and aggregates permission parameters matching clean variable names.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    g.id,
    g.tenant_id,
    g.group_name,
    g.is_enabled,
    g.redirect_uri,
    g.redirect_uris,
    g.post_logout_redirect_uris,
    g.front_channel_logout_uri,
    g.back_channel_logout_uri,
    g.allowed_scopes,
    g.default_scopes,
    g.allowed_audiences,
    g.default_idp_id,
    g.created_at,
    g.updated_at,
    COALESCE(
        (SELECT ARRAY_AGG(agi.idp_id)
         FROM application_group_idps agi
         WHERE agi.group_id = g.id),
        '{}'::uuid[]
    )::uuid[] AS allowed_idp_ids
FROM application_groups g
WHERE g.group_name = @group_name AND g.tenant_id = tenant.id
LIMIT 1;

-- name: GetApplicationsLogoutContextByTenant :many
-- GetApplicationsLogoutContextByTenant pulls lightweight registration metrics required to drive clean back-channel single sign-out trees.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    a.id,
    a.client_id,
    g.front_channel_logout_uri,
    g.back_channel_logout_uri,
    p.signing_algorithm
FROM applications a
JOIN tenant ON a.tenant_id = tenant.id
JOIN application_groups g ON a.group_id = g.id AND a.tenant_id = g.tenant_id
JOIN application_profiles p ON a.profile_id = p.id AND a.tenant_id = p.tenant_id
WHERE a.is_enabled = TRUE
  AND g.is_enabled = TRUE
  AND p.is_enabled = TRUE;

-- name: CreateApplicationProfile :exec
-- CreateApplicationProfile handles initial initialization parameters for structural lifetimes.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
INSERT INTO application_profiles (
    id,
    tenant_id,
    profile_name,
    is_enabled,
    token_endpoint_auth_method,
    grant_types,
    response_types,
    access_token_lifetime,
    id_token_lifetime,
    refresh_token_lifetime,
    enforce_rtr,
    signing_algorithm
)
SELECT
    @id::uuid,
    tenant.id,
    @profile_name,
    @is_enabled,
    @token_endpoint_auth_method,
    @grant_types,
    @response_types,
    (@access_token_lifetime::integer || ' seconds')::interval,
    (@id_token_lifetime::integer || ' seconds')::interval,
    (@refresh_token_lifetime::integer || ' seconds')::interval,
    @enforce_rtr,
    @signing_algorithm
FROM tenant;

-- name: CreateApplicationGroup :exec
-- CreateApplicationGroup records base attributes into your group table using the updated relational column suffix.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
INSERT INTO application_groups (
    id,
    tenant_id,
    group_name,
    is_enabled,
    allowed_scopes,
    default_scopes,
    allowed_audiences,
    default_idp_id, -- Cleaned name matching normalization schema updates
    redirect_uris,
    post_logout_redirect_uris
)
SELECT
    @id::uuid,
    tenant.id,
    @group_name,
    @is_enabled,
    @allowed_scopes,
    @default_scopes,
    @allowed_audiences,
    @default_idp_id::uuid, -- Type-safe UUID input parameter mapping
    @redirect_uris,
    @post_logout_redirect_uris
FROM tenant;

-- name: CreateApplication :exec
-- CreateApplication establishes core relational boundaries coupling structural definitions.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
INSERT INTO applications (
    id,
    tenant_id,
    profile_id,
    group_id,
    client_id,
    client_secret_hash,
    application_name
)
SELECT
    @id::uuid,
    tenant.id,
    @profile_id::uuid,
    @group_id::uuid,
    @client_id,
    @client_secret_hash,
    @application_name
FROM tenant;

-- name: DeleteApplication :exec
-- DeleteApplication executes hard deletions on individual application profiles.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
DELETE FROM applications
WHERE client_id = @client_id
  AND tenant_id = (SELECT id FROM tenant);

-- name: UpdateApplicationProfile :exec
-- UpdateApplicationProfile modifies token lifecycle parameters and cryptographic signature constraints.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
UPDATE application_profiles p
SET
    profile_name = @profile_name,
    is_enabled = @is_enabled,
    token_endpoint_auth_method = @token_endpoint_auth_method,
    grant_types = @grant_types,
    response_types = @response_types,
    access_token_lifetime = (@access_token_lifetime::integer || ' seconds')::interval,
    refresh_token_lifetime = (@refresh_token_lifetime::integer || ' seconds')::interval,
    id_token_lifetime = (@id_token_lifetime::integer || ' seconds')::interval,
    enforce_rtr = @enforce_rtr,
    signing_algorithm = @signing_algorithm,
    updated_at = NOW()
FROM tenant
WHERE p.id = @id::uuid
  AND p.tenant_id = tenant.id;

-- name: UpdateApplicationGroup :exec
-- UpdateApplicationGroup modifies top-level group boundaries and whitelist configurations.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
UPDATE application_groups g
SET
    group_name = @group_name,
    is_enabled = @is_enabled,
    allowed_scopes = @allowed_scopes,
    default_scopes = @default_scopes,
    allowed_audiences = @allowed_audiences,
    default_idp_id = @default_idp_id::uuid,
    redirect_uris = @redirect_uris,
    post_logout_redirect_uris = @post_logout_redirect_uris,
    updated_at = NOW()
FROM tenant
WHERE g.id = @id::uuid
  AND g.tenant_id = tenant.id;

-- name: BindIdentityProvidersToGroup :copyfrom
-- BindIdentityProvidersToGroup handles bulk binary COPY streaming directly into your normalized permissions join table [O(1) insertion loop optimization].
INSERT INTO application_group_idps (group_id, idp_id, tenant_id)
VALUES ($1, $2, $3);

-- name: ClearIdentityProvidersFromGroup :exec
-- ClearIdentityProvidersFromGroup drops permission relations before rewriting values during updates.
DELETE FROM application_group_idps
WHERE group_id = @group_id::uuid AND tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = @tenant_uuid::uuid LIMIT 1);
