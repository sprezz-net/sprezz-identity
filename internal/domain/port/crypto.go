package port

import (
	"sprezz-identity/internal/domain/model"
)

type Crypto interface {
	SignAccessToken(claims model.TokenClaims, alg model.SignatureAlgorithm) (string, error)
	SignIDToken(claims model.OIDCTokenClaims, alg model.SignatureAlgorithm) (string, error)
	VerifyToken(tokenStr string) (map[string]any, error)
	SignLogoutToken(claims model.LogoutTokenClaims, alg model.SignatureAlgorithm) (string, error)
}
