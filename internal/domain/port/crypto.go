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
	SignSoftwareStatement(ctx context.Context, issuer, audience string, claims model.SoftwareStatementClaims, issuedAt, expiresAt, notBefore time.Time) (string, error)
	// DecodeAndVerifySoftwareStatement parses and validates an incoming software statement token string
	// against the live cryptographically isolated keyset parameters of the active tenant.
	DecodeAndVerifySoftwareStatement(ctx context.Context, tenant *model.Tenant, ssa string) (*model.SoftwareStatementClaims, error)

	// --- Inbound Token Verification & Validation Layers ---
	VerifyToken(tokenStr string) (map[string]any, error)
	VerifyExternalTokenWithProvider(ctx context.Context, tokenStr string, jwksURI string, expectedIssuer string) (map[string]any, error)
	// ParseAndVerifyExternalToken abstracts unverified inspection, dynamic JWKS lookups,
	// and full cryptographic validation of an inbound third-party assertion token string.
	ParseAndVerifyExternalToken(ctx context.Context, tokenStr string, jwksURI string, expectedIssuer string) (*model.ExternalTokenClaims, error)
	// ExtractUnverifiedMetadata reads the basic tracking fields from an incoming
	// unverified third-party token string to assist with downstream provider routing.
	ExtractUnverifiedMetadata(tokenStr string) (issuer string, email string, err error)
	// ExtractUnverifiedRevocationMetadata reads the token identifier and bound client parameters
	// out of an unverified token string to validate ownership properties safely during revocation sweeps.
	ExtractUnverifiedRevocationMetadata(tokenStr string) (tokenID string, clientID string, err error)

	// --- Platform Key Management Registers ---
	RotateKeys(ctx context.Context, domain string) error
	MarshalJWKSet(ctx context.Context, domain string, scheme string) (string, error)
	GetMasterRegistrationPublicKey() (any, error)
	JWKSForTenant(ctx context.Context, domain string, scheme string) ([]map[string]any, error)
	// FindPublicKeyInJWKS matches a specific 'kid' within a tenant's JWK set
	// and reconstructs it into a compilable Go public key object.
	FindPublicKeyInJWKS(jwks []map[string]any, kid string) (any, error)

	// --- Argon2id Secure Password Invariant Helpers ---
	HashCredential(secret string) (string, error)
	CompareCredential(hashedSecret, plainSecret string) (bool, error)
}
