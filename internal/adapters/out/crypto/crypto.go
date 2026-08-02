package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"sprezz-identity/internal/domain/model"

	"github.com/golang-jwt/jwt/v5"
)

const httpsScheme = "https://"

type JWTSigner struct {
	mu       sync.RWMutex
	keyrings map[string]*rsa.PrivateKey
	jwks     map[string][]map[string]any
}

func NewJWTSigner() *JWTSigner {
	return &JWTSigner{
		keyrings: make(map[string]*rsa.PrivateKey),
		jwks:     make(map[string][]map[string]any),
	}
}

func (s *JWTSigner) SignAccessToken(claims model.TokenClaims, alg model.SignatureAlgorithm) (string, error) {
	if alg != model.AlgRS256 {
		return "", fmt.Errorf("unsupported signing algorithm %s", alg)
	}

	issuer := claims.Issuer
	if issuer == "" {
		issuer = httpsScheme + strings.TrimPrefix(claims.TenantID, httpsScheme)
	}
	issuer = strings.TrimSuffix(issuer, "/")
	tenantKey := strings.TrimPrefix(issuer, httpsScheme)
	kid := s.tenantKeyID(issuer)
	privateKey, err := s.getOrCreateKeyPair(tenantKey, issuer, kid)
	if err != nil {
		return "", err
	}

	audClaim := any(claims.ClientID)
	if len(claims.Audiences) > 0 {
		audClaim = claims.Audiences
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":       issuer,
		"sub":       claims.Subject,
		"aud":       audClaim,
		"jti":       claims.TokenID,
		"tid":       claims.TenantID,
		"client_id": claims.ClientID,
		"scope":     strings.Join(claims.Scopes, " "),
		"iat":       claims.IssuedAt.Unix(),
		"exp":       claims.ExpiresAt.Unix(),
		"nbf":       claims.IssuedAt.Unix(),
	})
	token.Header["kid"] = kid
	token.Header["typ"] = "JWT"

	return token.SignedString(privateKey)
}

func (s *JWTSigner) SignIDToken(claims model.OIDCTokenClaims, alg model.SignatureAlgorithm) (string, error) {
	if alg != model.AlgRS256 {
		return "", fmt.Errorf("unsupported signing algorithm %s", alg)
	}

	issuer := claims.Issuer
	if issuer == "" {
		issuer = httpsScheme + strings.TrimPrefix(claims.TenantID, httpsScheme)
	}
	issuer = strings.TrimSuffix(issuer, "/")
	tenantKey := strings.TrimPrefix(issuer, httpsScheme)
	kid := s.tenantKeyID(issuer)
	privateKey, err := s.getOrCreateKeyPair(tenantKey, issuer, kid)
	if err != nil {
		return "", err
	}

	mapClaims := jwt.MapClaims{
		"iss":       issuer,
		"sub":       claims.Subject,
		"aud":       claims.Audience,
		"jti":       claims.TokenID,
		"tid":       claims.TenantID,
		"auth_time": claims.AuthTime.Unix(),
		"nonce":     claims.Nonce,
		"iat":       claims.IssuedAt.Unix(),
		"exp":       claims.ExpiresAt.Unix(),
		"nbf":       claims.IssuedAt.Unix(),
	}
	if claims.SessionID != "" {
		mapClaims["sid"] = claims.SessionID
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)
	token.Header["kid"] = kid
	token.Header["typ"] = "JWT"

	return token.SignedString(privateKey)
}

func (s *JWTSigner) SignLogoutToken(claims model.LogoutTokenClaims, alg model.SignatureAlgorithm) (string, error) {
	if alg != model.AlgRS256 {
		return "", fmt.Errorf("unsupported signing algorithm %s", alg)
	}

	issuer := claims.Issuer
	if issuer == "" {
		issuer = httpsScheme + strings.TrimPrefix(claims.Subject, httpsScheme)
	}
	issuer = strings.TrimSuffix(issuer, "/")
	tenantKey := strings.TrimPrefix(issuer, httpsScheme)
	kid := s.tenantKeyID(issuer)
	privateKey, err := s.getOrCreateKeyPair(tenantKey, issuer, kid)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuer,
		"sub": claims.Subject,
		"aud": claims.Audience,
		"jti": claims.TokenID,
		"iat": claims.IssuedAt.Unix(),
		"events": map[string]any{
			"http://schemas.openid.net/event/back-channel-logout": map[string]any{},
		},
	})
	token.Header["kid"] = kid
	token.Header["typ"] = "JWT"

	return token.SignedString(privateKey)
}

func (s *JWTSigner) VerifyToken(tokenStr string) (map[string]any, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("missing kid in token header")
		}

		s.mu.RLock()
		defer s.mu.RUnlock()
		for _, key := range s.keyrings {
			return &key.PublicKey, nil
		}
		return nil, fmt.Errorf("key not found for kid: %s", kid)
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

func (s *JWTSigner) JWKSForTenant(domain string) ([]map[string]any, error) {
	s.mu.RLock()
	jwkSet, ok := s.jwks[domain]
	s.mu.RUnlock()
	if ok {
		return jwkSet, nil
	}

	issuer, kid := s.tenantIdentity(domain)
	_, err := s.getOrCreateKeyPair(domain, issuer, kid)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jwks[domain], nil
}

func (s *JWTSigner) MarshalJWKSet(tenant string) (string, error) {
	jwkSet, err := s.JWKSForTenant(tenant)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]any{"keys": jwkSet})
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (s *JWTSigner) tenantIdentity(tenant string) (string, string) {
	if tenant == "" {
		tenant = "default"
	}
	issuer := strings.TrimSuffix(httpsScheme+strings.TrimPrefix(tenant, httpsScheme), "/")
	kid := s.tenantKeyID(issuer)
	return issuer, kid
}

func (s *JWTSigner) tenantKeyID(tenant string) string {
	if tenant == "" {
		tenant = "default"
	}
	kidHash := sha256.Sum256([]byte(strings.TrimPrefix(tenant, httpsScheme)))
	return fmt.Sprintf("kid-%x", kidHash)
}

func (s *JWTSigner) getOrCreateKeyPair(tenant string, issuer string, kid string) (*rsa.PrivateKey, error) {
	s.mu.RLock()
	privateKey, ok := s.keyrings[issuer]
	s.mu.RUnlock()
	if ok {
		return privateKey, nil
	}

	generatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate tenant signing key: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, exists := s.keyrings[issuer]; exists {
		return existing, nil
	}

	s.keyrings[issuer] = generatedKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&generatedKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	rsaPublic, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected public key type")
	}
	modulus := base64.RawURLEncoding.EncodeToString(rsaPublic.N.Bytes())
	exponent := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
	jwk := map[string]any{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "RS256",
		"n":   modulus,
		"e":   exponent,
	}
	s.jwks[tenant] = []map[string]any{jwk}
	return generatedKey, nil
}
