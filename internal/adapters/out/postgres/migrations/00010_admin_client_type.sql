-- +goose Up
ALTER TABLE applications ADD COLUMN client_type VARCHAR(50) NOT NULL DEFAULT 'confidential';

ALTER TABLE applications ADD CONSTRAINT chk_client_type
  CHECK (client_type IN ('public', 'confidential', 'internal_ephemeral'));

ALTER TABLE applications ADD CONSTRAINT chk_ephemeral_null_secret
  CHECK (client_type <> 'internal_ephemeral' OR client_secret_hash IS NULL);

-- +goose Down
ALTER TABLE applications DROP CONSTRAINT IF EXISTS chk_ephemeral_null_secret;
ALTER TABLE applications DROP CONSTRAINT IF EXISTS chk_client_type;
ALTER TABLE applications DROP COLUMN IF EXISTS client_type;
