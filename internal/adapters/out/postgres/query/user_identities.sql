-- name: UpsertUserIdentity :exec
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
INSERT INTO user_identities (
    id,
    tenant_id,
    partition_id,
    user_profile_id,
    identity_provider_id,
    external_identity_id,
    login_count,
    last_login_at,
    coupled_at
)
SELECT
    @id::uuid,
    tenant.id,
    @partition_id::bigint,
    @user_profile_id::uuid,
    @identity_provider_id::uuid,
    @external_identity_id,
    @login_count,
    @last_login_at::timestamptz,
    @coupled_at::timestamptz
FROM tenant
ON CONFLICT (user_profile_id, identity_provider_id) DO UPDATE SET
    external_identity_id = EXCLUDED.external_identity_id,
    login_count = EXCLUDED.login_count,
    last_login_at = EXCLUDED.last_login_at,
    coupled_at = EXCLUDED.coupled_at;

-- name: GetUserIdentitiesByProfileID :many
-- Resolves all active external user identity linkage nodes bound to a target parent user profile.
-- Leverages a canonical CTE lookup to securely translate the public UUIDv4 perimeter anchor.
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    i.id,
    i.user_profile_id,
    i.identity_provider_id,
    i.external_identity_id,
    i.login_count,
    i.last_login_at,
    i.coupled_at
FROM user_identities i
INNER JOIN tenant t ON t.id = i.tenant_id
WHERE i.partition_id = @partition_id::bigint
  AND i.user_profile_id = @user_profile_id::uuid;

-- name: GetUserIdentityByProfileIDAndProviderID :one
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    i.id,
    i.user_profile_id,
    i.identity_provider_id,
    i.external_identity_id,
    i.login_count,
    i.last_login_at,
    i.coupled_at
FROM user_identities i, tenant
WHERE i.tenant_id = tenant.id
  AND i.partition_id = @partition_id::bigint
  AND i.user_profile_id = @user_profile_id::uuid
  AND i.identity_provider_id = @identity_provider_id::uuid
LIMIT 1;

-- name: GetUserIdentityByProviderAndExternalID :one
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    i.id,
    i.user_profile_id,
    i.identity_provider_id,
    i.external_identity_id,
    i.login_count,
    i.last_login_at,
    i.coupled_at
FROM user_identities i, tenant
WHERE i.tenant_id = tenant.id
  AND i.partition_id = @partition_id::bigint
  AND i.identity_provider_id = @identity_provider_id::uuid
  AND i.external_identity_id = @external_identity_id
LIMIT 1;

-- name: IncrementUserIdentityLoginTracker :exec
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
UPDATE user_identities i
SET
    login_count = i.login_count + 1,
    last_login_at = @last_login_at::timestamptz
FROM tenant
WHERE i.tenant_id = tenant.id
  AND i.partition_id = @partition_id::bigint
  AND i.id = @identity_id::uuid;

-- name: GetUserIdentityByIdentifier :one
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    i.id,
    i.user_profile_id,
    i.identity_provider_id,
    i.external_identity_id,
    i.login_count,
    i.last_login_at,
    i.coupled_at
FROM user_identities i
INNER JOIN user_profiles up ON i.user_profile_id = up.id AND i.partition_id = up.partition_id
INNER JOIN tenant t ON up.tenant_id = t.id
WHERE i.partition_id = @partition_id::bigint
  AND i.identity_provider_id = @identity_provider_id::uuid
  AND (LOWER(up.preferred_username) = LOWER(@identifier::varchar) OR LOWER(up.email) = LOWER(@identifier::varchar))
LIMIT 1;
