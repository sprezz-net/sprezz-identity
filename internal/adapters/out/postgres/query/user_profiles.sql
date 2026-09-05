-- name: GetUserProfileByIDAndPartitionAlias :one
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    up.id,
    up.preferred_username,
    up.name,
    up.first_name,
    up.last_name,
    up.email,
    up.email_verified,
    up.partition_id,
    up.lifecycle_state,
    up.blocked,
    up.created_at,
    up.updated_at,
    @tenant_uuid::uuid AS tenant_uuid
FROM user_profiles up
CROSS JOIN tenant
INNER JOIN partitions p ON up.tenant_id = p.tenant_id AND up.partition_id = p.id
WHERE up.tenant_id = tenant.id
  AND p.alias_name = @partition_alias::varchar
  AND up.id = @id::uuid
LIMIT 1;

-- name: GetUserProfileByID :one
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    up.id,
    up.preferred_username,
    up.name,
    up.first_name,
    up.last_name,
    up.email,
    up.email_verified,
    up.partition_id,
    up.lifecycle_state,
    up.blocked,
    up.created_at,
    up.updated_at,
    @tenant_uuid::uuid AS tenant_uuid
FROM user_profiles up, tenant
WHERE up.tenant_id = tenant.id
  AND up.partition_id = @partition_id
LIMIT 1;

-- name: GetUserProfileByPreferredUsername :one
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    up.id, up.preferred_username, up.name, up.first_name, up.last_name, up.email, up.email_verified, up.partition_id, up.lifecycle_state, up.blocked, up.created_at, up.updated_at
FROM user_profiles up, tenant
WHERE up.tenant_id = tenant.id
  AND up.partition_id = @partition_id
  AND up.preferred_username = @preferred_username
LIMIT 1;

-- name: GetUserProfileByEmail :one
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    up.id, up.preferred_username, up.name, up.first_name, up.last_name, up.email, up.email_verified, up.partition_id, up.lifecycle_state, up.blocked, up.created_at, up.updated_at
FROM user_profiles up, tenant
WHERE up.tenant_id = tenant.id
  AND up.partition_id = @partition_id
  AND up.email = @email
LIMIT 1;

-- name: FindProfileByEmail :one
SELECT
    up.id,
    t.tenant_uuid,
    up.preferred_username,
    up.name,
    up.first_name,
    up.last_name,
    up.email,
    up.email_verified,
    up.partition_id,
    up.lifecycle_state,
    up.blocked,
    up.created_at,
    up.updated_at
FROM user_profiles up
JOIN tenants t ON t.id = up.tenant_id
WHERE up.partition_id = @partition_id
  AND up.email = @email
LIMIT 1;

-- name: CheckUserProfileCollision :one
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT EXISTS (
    SELECT 1 FROM user_profiles up, tenant
    WHERE up.tenant_id = tenant.id
      AND up.partition_id = @partition_id
      AND (up.preferred_username = @preferred_username OR up.email = @email)
);

-- name: CheckExactUsernameCollision :one
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT COUNT(*) FROM user_profiles up, tenant
WHERE up.tenant_id = tenant.id
  AND up.partition_id = @partition_id
  AND up.preferred_username = @preferred_username;

-- name: SaveUserProfile :exec
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
INSERT INTO user_profiles (
    id, tenant_id, preferred_username, name, first_name, last_name, email, email_verified, partition_id, lifecycle_state, blocked
)
SELECT
    @id::uuid, tenant.id, @preferred_username, @name, @first_name, @last_name, @email, @email_verified, @partition_id, @lifecycle_state, @blocked
FROM tenant;

-- name: GetUserProfilesByTenant :many
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    up.id, up.preferred_username, up.name, up.first_name, up.last_name, up.email, up.email_verified, up.partition_id, up.lifecycle_state, up.blocked, up.created_at, up.updated_at
FROM user_profiles up, tenant
WHERE up.tenant_id = tenant.id
  AND up.partition_id = @partition_id
ORDER BY up.preferred_username ASC;

-- name: DeleteUserProfile :exec
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
DELETE FROM user_profiles up
USING tenant
WHERE up.tenant_id = tenant.id
  AND up.partition_id = @partition_id
  AND up.id = @id::uuid;

-- name: UpdateUserProfile :exec
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
UPDATE user_profiles up
SET
    preferred_username = @preferred_username,
    name = @name,
    first_name = @first_name,
    last_name = @last_name,
    email = @email,
    email_verified = @email_verified,
    lifecycle_state = @lifecycle_state,
    blocked = @blocked
FROM tenant
WHERE up.tenant_id = tenant.id
  AND up.partition_id = @partition_id
  AND up.id = @id::uuid;

-- name: GetUserProfileByIdentifier :one
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    up.id,
    up.partition_id,
    up.preferred_username,
    up.name,
    up.first_name,
    up.last_name,
    up.email,
    up.email_verified,
    up.lifecycle_state,
    up.blocked,
    up.created_at,
    up.updated_at
FROM user_profiles up
INNER JOIN tenant t ON up.tenant_id = t.id
INNER JOIN user_identities ui ON ui.user_profile_id = up.id AND ui.partition_id = up.partition_id
WHERE up.partition_id = @partition_id::bigint
  AND ui.identity_provider_id = @identity_provider_id::uuid
  AND (LOWER(up.preferred_username) = LOWER(@identifier::varchar) OR LOWER(up.email) = LOWER(@identifier::varchar))
LIMIT 1;
