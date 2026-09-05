package port

import (
	"context"
	"time"

	"sprezz-identity/internal/domain/model"
)

// Crypto isolates all cryptographic token management, credential hashing, and
// signature signing assertions from the core application layer.
type Crypto interface {
	// --- Stateless Token Serialization & Signing Tracks ---
	SignAccessToken(ctx context.Context, claims model.TokenClaims, alg model.SignatureAlgorithm) (string, error)
	SignIDToken(ctx context.Context, claims model.OIDCTokenClaims, grantedScopes []string, alg model.SignatureAlgorithm) (string, error)
	SignLogoutToken(ctx context.Context, claims model.LogoutTokenClaims, alg model.SignatureAlgorithm) (string, error)

	// Hashes and signs on-demand administrative dynamic registration assertions
	SignSoftwareStatement(ctx context.Context, issuer string, audience string, claims model.SoftwareStatementClaims, issuedAt time.Time, expiresAt time.Time) (string, error)

	// --- Inbound Token Verification & Validation Layers ---
	VerifyToken(tokenStr string) (map[string]any, error)
	VerifyExternalTokenWithProvider(ctx context.Context, tokenStr string, jwksURI string, expectedIssuer string) (map[string]any, error)

	// --- Platform Key Management Registers ---
	RotateKeys(ctx context.Context, domain string) error
	MarshalJWKSet(ctx context.Context, domain string, scheme string) (string, error)
	GetMasterRegistrationPublicKey() (any, error)
	JWKSForTenant(ctx context.Context, domain string, scheme string) ([]map[string]any, error)

	// --- Argon2id Secure Password Invariant Helpers ---
	HashCredential(secret string) (string, error)
	CompareCredential(hashedSecret, plainSecret string) (bool, error)
}
