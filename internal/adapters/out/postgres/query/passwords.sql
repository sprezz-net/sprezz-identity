-- name: GetPasswordCredentialByProfileID :one
WITH tenant AS (
    SELECT id
    FROM tenants
    WHERE tenant_uuid = @tenant_uuid::uuid
    LIMIT 1
)
SELECT
    p.password_hash,
    p.failed_verification_count,
    p.last_verification_attempt,
    p.blocked_until,
    p.created_at,
    p.updated_at
FROM passwords p
JOIN identity_providers ip ON ip.id = p.identity_provider_id
WHERE ip.tenant_id = (SELECT id FROM tenant)
  AND ip.partition_id = @partition_id
  AND p.user_profile_id = @user_profile_id::uuid
  AND p.identity_provider_id = @identity_provider_id::uuid
LIMIT 1;

-- name: UpdatePasswordLockoutState :exec
UPDATE passwords
SET failed_verification_count = @failed_verification_count,
    last_verification_attempt = @last_verification_attempt::timestamptz,
    blocked_until = @blocked_until::timestamptz
WHERE user_profile_id = @user_profile_id::uuid
  AND identity_provider_id = @identity_provider_id::uuid;

-- name: ResetPasswordCounters :exec
UPDATE passwords
SET failed_verification_count = 0,
    blocked_until = NULL
WHERE user_profile_id = @user_profile_id::uuid
  AND identity_provider_id = @identity_provider_id::uuid;

