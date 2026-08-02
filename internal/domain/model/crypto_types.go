package model

type SignatureAlgorithm string

const (
	AlgRS256 SignatureAlgorithm = "RS256"
	AlgEdDSA SignatureAlgorithm = "EdDSA"
)

type SigningKeyMetadata struct {
	KeyID     string
	Algorithm SignatureAlgorithm
}
