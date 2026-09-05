-- +goose Up
-- +goose StatementBegin

-- 1. Alter passwords table to add failed attempts, last attempt, and blocked_until
ALTER TABLE passwords ADD COLUMN failed_verification_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE passwords ADD COLUMN last_verification_attempt TIMESTAMP WITH TIME ZONE;
ALTER TABLE passwords ADD COLUMN blocked_until TIMESTAMP WITH TIME ZONE;

-- 2. Migrate existing lockout data from user_identities (previously identities) to passwords
UPDATE passwords p
SET failed_verification_count = i.failed_verification_count,
    last_verification_attempt = i.last_verification_attempt,
    blocked_until = CASE WHEN i.blocked THEN NOW() + INTERVAL '15 minutes' ELSE NULL END
FROM user_identities i
WHERE p.user_profile_id = i.user_profile_id 
  AND p.identity_provider_id = i.identity_provider_id;

-- 3. Alter user_identities table to drop metrics and make last_login_at nullable
ALTER TABLE user_identities DROP COLUMN failed_verification_count;
ALTER TABLE user_identities DROP COLUMN last_verification_attempt;
ALTER TABLE user_identities DROP COLUMN blocked;
ALTER TABLE user_identities ALTER COLUMN last_login_at DROP NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- 1. Restore columns on user_identities
ALTER TABLE user_identities ADD COLUMN failed_verification_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE user_identities ADD COLUMN last_verification_attempt TIMESTAMP WITH TIME ZONE;
ALTER TABLE user_identities ADD COLUMN blocked BOOLEAN NOT NULL DEFAULT FALSE;

-- 2. Set default values for last_login_at where they are null before making it NOT NULL again
UPDATE user_identities SET last_login_at = NOW() WHERE last_login_at IS NULL;
ALTER TABLE user_identities ALTER COLUMN last_login_at SET NOT NULL;

-- 3. Rollback data from passwords back to user_identities
UPDATE user_identities i
SET failed_verification_count = p.failed_verification_count,
    last_verification_attempt = p.last_verification_attempt,
    blocked = CASE WHEN p.blocked_until IS NOT NULL AND p.blocked_until > NOW() THEN TRUE ELSE FALSE END
FROM passwords p
WHERE p.user_profile_id = i.user_profile_id 
  AND p.identity_provider_id = i.identity_provider_id;

-- 4. Remove columns from passwords table
ALTER TABLE passwords DROP COLUMN failed_verification_count;
ALTER TABLE passwords DROP COLUMN last_verification_attempt;
ALTER TABLE passwords DROP COLUMN blocked_until;

-- +goose StatementEnd
