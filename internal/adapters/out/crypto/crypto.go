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
	"time"

	"sprezz-identity/internal/domain/model"

	"github.com/golang-jwt/jwt/v5"
)

const httpsScheme = "https://"

type tenantKeyring struct {
	ActiveKid string
	Keys      map[string]*rsa.PrivateKey
	JWKS      []map[string]any
}

type JWTSigner struct {
	mu       sync.RWMutex
	keyrings map[string]*tenantKeyring
}

func NewJWTSigner() *JWTSigner {
	return &JWTSigner{
		keyrings: make(map[string]*tenantKeyring),
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
	tenant := strings.TrimPrefix(issuer, httpsScheme)

	keyring, err := s.getOrCreateKeyring(tenant, issuer)
	if err != nil {
		return "", err
	}

	privateKey := keyring.Keys[keyring.ActiveKid]
	audClaim := any(claims.ClientID)
	if len(claims.Audiences) > 0 {
		audClaim = claims.Audiences
	}

	mapClaims := jwt.MapClaims{
		"iss":       issuer,
		"sub":       claims.Subject,
		"aud":       audClaim,
		"jti":       claims.TokenID,
		"tid":       claims.TenantID,
		"client_id": claims.ClientID,
		"scope":     strings.Join(claims.Scopes, " "),
		"iat":       int64(claims.IssuedAt.Unix()),
		"exp":       int64(claims.ExpiresAt.Unix()),
		"nbf":       int64(claims.IssuedAt.Unix()),
	}
	if claims.DPoPHash != "" {
		mapClaims["cnf"] = map[string]any{
			"jkt": claims.DPoPHash,
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)
	token.Header["kid"] = keyring.ActiveKid
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
	tenant := strings.TrimPrefix(issuer, httpsScheme)

	keyring, err := s.getOrCreateKeyring(tenant, issuer)
	if err != nil {
		return "", err
	}

	privateKey := keyring.Keys[keyring.ActiveKid]
	mapClaims := jwt.MapClaims{
		"iss":       issuer,
		"sub":       claims.Subject,
		"aud":       claims.Audience,
		"jti":       claims.TokenID,
		"tid":       claims.TenantID,
		"auth_time": int64(claims.AuthTime.Unix()),
		"nonce":     claims.Nonce,
		"iat":       int64(claims.IssuedAt.Unix()),
		"exp":       int64(claims.ExpiresAt.Unix()),
		"nbf":       int64(claims.IssuedAt.Unix()),
	}
	if claims.SessionID != "" {
		mapClaims["sid"] = claims.SessionID
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)
	token.Header["kid"] = keyring.ActiveKid
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
	tenant := strings.TrimPrefix(issuer, httpsScheme)

	keyring, err := s.getOrCreateKeyring(tenant, issuer)
	if err != nil {
		return "", err
	}

	privateKey := keyring.Keys[keyring.ActiveKid]
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuer,
		"sub": claims.Subject,
		"aud": claims.Audience,
		"jti": claims.TokenID,
		"iat": int64(claims.IssuedAt.Unix()),
		"events": map[string]any{
			"http://schemas.openid.net/event/back-channel-logout": map[string]any{},
		},
	})
	token.Header["kid"] = keyring.ActiveKid
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
		for _, keyring := range s.keyrings {
			if key, exists := keyring.Keys[kid]; exists {
				return &key.PublicKey, nil
			}
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
	issuer, _ := s.tenantIdentity(domain)
	keyring, err := s.getOrCreateKeyring(domain, issuer)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return keyring.JWKS, nil
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

func (s *JWTSigner) RotateKeys(tenant string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	keyring, ok := s.keyrings[tenant]
	if !ok {
		return fmt.Errorf("tenant %s keyring not initialized", tenant)
	}

	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("rotate keys: generate key: %w", err)
	}

	// Generate a unique kid
	kidHash := sha256.Sum256(fmt.Appendf(nil, "%s-%d", tenant, time.Now().UnixNano()))
	newKid := fmt.Sprintf("kid-%x", kidHash)

	jwk, err := s.buildJWK(newKid, newKey)
	if err != nil {
		return fmt.Errorf("rotate keys: build jwk: %w", err)
	}

	keyring.ActiveKid = newKid
	keyring.Keys[newKid] = newKey
	keyring.JWKS = append([]map[string]any{jwk}, keyring.JWKS...)

	return nil
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

func (s *JWTSigner) buildJWK(kid string, privateKey *rsa.PrivateKey) (map[string]any, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
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
	return map[string]any{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "RS256",
		"n":   modulus,
		"e":   exponent,
	}, nil
}

func (s *JWTSigner) getOrCreateKeyring(tenant string, issuer string) (*tenantKeyring, error) {
	s.mu.RLock()
	keyring, ok := s.keyrings[tenant]
	s.mu.RUnlock()
	if ok {
		return keyring, nil
	}

	generatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate tenant signing key: %w", err)
	}

	kid := s.tenantKeyID(issuer)
	jwk, err := s.buildJWK(kid, generatedKey)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, exists := s.keyrings[tenant]; exists {
		return existing, nil
	}

	newKeyring := &tenantKeyring{
		ActiveKid: kid,
		Keys:      map[string]*rsa.PrivateKey{kid: generatedKey},
		JWKS:      []map[string]any{jwk},
	}
	s.keyrings[tenant] = newKeyring
	return newKeyring, nil
}
