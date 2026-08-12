package model

type SignatureAlgorithm string

const (
	AlgEdDSA SignatureAlgorithm = "EdDSA"
	AlgES256 SignatureAlgorithm = "ES256"
	AlgRS256 SignatureAlgorithm = "RS256"
)

// SigningKey represents an infrastructure-agnostic cryptographic asset
// used by the OIDC control engine for signing and verifying tokens.
type SigningKey struct {
	// Kid is the unique Key ID used to identify this key in the JWKS block.
	Kid string

	// Algorithm specifies the signing algorithm (e.g., "RS256", "EdDSA").
	Algorithm string

	// PrivateKey holds the unencrypted, operational Go crypto private key structure.
	// This will dynamically cast to *rsa.PrivateKey or ed25519.PrivateKey at runtime.
	PrivateKey any

	// PublicJWK contains the structured, unencrypted public parameters of the key
	// formatted cleanly for public exposure via the /.well-known/jwks.json endpoint.
	PublicJWK map[string]any

	// --- Anti-Corruption Layer Artifacts ---
	// The fields below are transient fields used explicitly by outbound storage adapters
	// to transport secured envelopes across the architectural perimeter without bloating
	// the core domain business rules.

	// RawEncryptedPrivateKey stores the AES-GCM cipher payload retrieved from or sent to storage.
	RawEncryptedPrivateKey []byte

	// CryptoNonce contains the 12-byte initialization vector (IV) used to lock/unlock this specific key.
	CryptoNonce []byte
}
