package port

import (
	"context"

	"sprezz-identity/internal/domain/model"
)

type Crypto interface {
	// Token signing
	SignAccessToken(ctx context.Context, claims model.TokenClaims, alg model.SignatureAlgorithm) (string, error)
	SignIDToken(ctx context.Context, claims model.OIDCTokenClaims, alg model.SignatureAlgorithm) (string, error)
	SignLogoutToken(ctx context.Context, claims model.LogoutTokenClaims, alg model.SignatureAlgorithm) (string, error)
	VerifyToken(tokenStr string) (map[string]any, error)
	// Key management
	RotateKeys(ctx context.Context, domain string) error
	MarshalJWKSet(ctx context.Context, domain string, scheme string) (string, error)
}
