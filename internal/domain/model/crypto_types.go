package model

type SignatureAlgorithm string

const (
	AlgRS256 SignatureAlgorithm = "RS256"
	AlgES256 SignatureAlgorithm = "ES256"
)

type SigningKeyMetadata struct {
	KeyID     string
	Algorithm SignatureAlgorithm
}
