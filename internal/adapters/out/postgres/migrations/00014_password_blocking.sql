-- +goose Up
ALTER TABLE identities RENAME COLUMN last_login_attempt TO last_verification_attempt;
ALTER TABLE identities ADD COLUMN failed_verification_count INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE identities DROP COLUMN failed_verification_count;
ALTER TABLE identities RENAME COLUMN last_verification_attempt TO last_login_attempt;
