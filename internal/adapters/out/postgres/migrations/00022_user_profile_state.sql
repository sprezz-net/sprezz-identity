-- +goose Up
-- +goose StatementBegin

-- 1. Create the explicit lifecycle state enum
CREATE TYPE profile_lifecycle_state AS ENUM (
    'CREATED',
    'REQUESTED',
    'INVITED',
    'ACTIVATED',
    'DEACTIVATED'
);

-- 2. Modify the user_profiles table to incorporate the state machine
ALTER TABLE user_profiles
    ADD COLUMN lifecycle_state profile_lifecycle_state NOT NULL DEFAULT 'CREATED',
    ADD COLUMN blocked BOOLEAN NOT NULL DEFAULT FALSE;

-- 3. Add an index to optimize lookup gates during authentication workflows
CREATE INDEX idx_user_profiles_state_gate
    ON user_profiles (id, lifecycle_state, blocked);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- 1. Drop the verification index
DROP INDEX IF EXISTS idx_user_profiles_state_gate;

-- 2. Remove the state columns from the table
ALTER TABLE user_profiles
    DROP COLUMN IF EXISTS lifecycle_state,
    DROP COLUMN IF EXISTS blocked;

-- 3. Remove the custom enum type from the database schema
DROP TYPE IF EXISTS profile_lifecycle_state;

-- +goose StatementEnd
