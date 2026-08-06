package model

type SignatureAlgorithm string

const (
	AlgEdDSA SignatureAlgorithm = "EdDSA"
	AlgES256 SignatureAlgorithm = "ES256"
	AlgRS256 SignatureAlgorithm = "RS256"
)

type SigningKeyMetadata struct {
	KeyID     string
	Algorithm SignatureAlgorithm
}
