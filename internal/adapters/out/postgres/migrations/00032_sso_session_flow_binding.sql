-- +goose Up
-- +goose StatementBegin

-- A sign-in in progress is a PENDING session: it has a cookie but no user yet. The login, sign-up and federation
-- callback only proceed when the browser presents the cookie of the pending session the flow was started with, so
-- a login URL or callback URL sent to another browser is refused. Signing in promotes the same row to ACTIVE
-- (with a fresh secret), so the flow rows that point at it stay valid.
CREATE TYPE sso_session_state AS ENUM ('PENDING', 'ACTIVE');

ALTER TABLE sso_sessions ALTER COLUMN user_profile_id DROP NOT NULL;
ALTER TABLE sso_sessions ADD COLUMN state sso_session_state NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE sso_sessions ADD CONSTRAINT sso_sessions_state_has_user CHECK (
    (state = 'ACTIVE' AND user_profile_id IS NOT NULL) OR (state = 'PENDING' AND user_profile_id IS NULL)
);

-- The flow rows are bound to the pending session. A session that is deleted or pruned takes its flows with it.
-- Rows created before this migration have no binding and can no longer be completed (they live minutes).
-- The interaction session also never stored its partition, so it was lost on every read. The cookie of the flow is
-- named after that partition. Rows from before this migration get 0 and cannot be completed anyway (no binding).
ALTER TABLE interaction_sessions ADD COLUMN partition_id BIGINT NOT NULL DEFAULT 0;
ALTER TABLE interaction_sessions ADD COLUMN session_id UUID REFERENCES sso_sessions(id) ON DELETE CASCADE;
ALTER TABLE outbound_handshake_sessions ADD COLUMN session_id UUID REFERENCES sso_sessions(id) ON DELETE CASCADE;

CREATE INDEX idx_interaction_sessions_session ON interaction_sessions (session_id);
CREATE INDEX idx_outbound_handshake_sessions_session ON outbound_handshake_sessions (session_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_outbound_handshake_sessions_session;
DROP INDEX IF EXISTS idx_interaction_sessions_session;
ALTER TABLE outbound_handshake_sessions DROP COLUMN IF EXISTS session_id;
ALTER TABLE interaction_sessions DROP COLUMN IF EXISTS session_id;
ALTER TABLE interaction_sessions DROP COLUMN IF EXISTS partition_id;

DELETE FROM sso_sessions WHERE state = 'PENDING';
ALTER TABLE sso_sessions DROP CONSTRAINT IF EXISTS sso_sessions_state_has_user;
ALTER TABLE sso_sessions DROP COLUMN IF EXISTS state;
DROP TYPE IF EXISTS sso_session_state;
ALTER TABLE sso_sessions ALTER COLUMN user_profile_id SET NOT NULL;

-- +goose StatementEnd
