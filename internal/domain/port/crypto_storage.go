package port

import (
	"context"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

type CryptoStorage interface {
	GetTenantDEK(ctx context.Context, tenantUUID uuid.UUID) (encryptedDEK []byte, nonce []byte, err error)
	InsertTenantDEK(ctx context.Context, tenantUUID uuid.UUID, encryptedDEK, nonce []byte) error
	GetActiveSigningKeys(ctx context.Context, tenantUUID uuid.UUID) ([]model.SigningKey, error)
	GetActiveVerificationKeys(ctx context.Context, tenantUUID uuid.UUID) ([]model.SigningKey, error)
	InsertSigningKey(ctx context.Context, tenantUUID uuid.UUID, key model.SigningKey, encryptedPrivateKey, nonce []byte) (string, error)
	RotateSigningKeys(ctx context.Context, tenantUUID uuid.UUID) error
}
