package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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
	ActiveKids map[model.SignatureAlgorithm]string
	Keys       map[string]any
	JWKS       []map[string]any
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
	if alg != model.AlgRS256 && alg != model.AlgES256 {
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

	kid := keyring.ActiveKids[alg]
	privateKey := keyring.Keys[kid]

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
	if claims.ACR != "" {
		mapClaims["acr"] = claims.ACR
	}

	var method jwt.SigningMethod
	if alg == model.AlgES256 {
		method = jwt.SigningMethodES256
	} else {
		method = jwt.SigningMethodRS256
	}

	token := jwt.NewWithClaims(method, mapClaims)
	token.Header["kid"] = kid
	token.Header["typ"] = "JWT"

	return token.SignedString(privateKey)
}

func (s *JWTSigner) SignIDToken(claims model.OIDCTokenClaims, alg model.SignatureAlgorithm) (string, error) {
	if alg != model.AlgRS256 && alg != model.AlgES256 {
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

	kid := keyring.ActiveKids[alg]
	privateKey := keyring.Keys[kid]

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
	if claims.ACR != "" {
		mapClaims["acr"] = claims.ACR
	}

	var method jwt.SigningMethod
	if alg == model.AlgES256 {
		method = jwt.SigningMethodES256
	} else {
		method = jwt.SigningMethodRS256
	}

	token := jwt.NewWithClaims(method, mapClaims)
	token.Header["kid"] = kid
	token.Header["typ"] = "JWT"

	return token.SignedString(privateKey)
}

func (s *JWTSigner) SignLogoutToken(claims model.LogoutTokenClaims, alg model.SignatureAlgorithm) (string, error) {
	if alg != model.AlgRS256 && alg != model.AlgES256 {
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

	kid := keyring.ActiveKids[alg]
	privateKey := keyring.Keys[kid]

	var method jwt.SigningMethod
	if alg == model.AlgES256 {
		method = jwt.SigningMethodES256
	} else {
		method = jwt.SigningMethodRS256
	}

	token := jwt.NewWithClaims(method, jwt.MapClaims{
		"iss": issuer,
		"sub": claims.Subject,
		"aud": claims.Audience,
		"jti": claims.TokenID,
		"iat": int64(claims.IssuedAt.Unix()),
		"events": map[string]any{
			"http://schemas.openid.net/event/back-channel-logout": map[string]any{},
		},
	})
	token.Header["kid"] = kid
	token.Header["typ"] = "JWT"

	return token.SignedString(privateKey)
}

func (s *JWTSigner) lookupKeyByKid(kid string) (any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, keyring := range s.keyrings {
		if key, exists := keyring.Keys[kid]; exists {
			return key, nil
		}
	}
	return nil, fmt.Errorf("key not found for kid: %s", kid)
}

func validateSigningMethod(t *jwt.Token, key any) (any, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &k.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

func (s *JWTSigner) getPublicKeyAndValidateMethod(t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("missing kid in token header")
	}

	key, err := s.lookupKeyByKid(kid)
	if err != nil {
		return nil, err
	}

	return validateSigningMethod(t, key)
}

func (s *JWTSigner) VerifyToken(tokenStr string) (map[string]any, error) {
	token, err := jwt.Parse(tokenStr, s.getPublicKeyAndValidateMethod)
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

	newRSKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("rotate keys: generate rsa key: %w", err)
	}

	newECKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("rotate keys: generate ecdsa key: %w", err)
	}

	rsaKid := s.tenantKeyID(tenant, model.AlgRS256) + fmt.Sprintf("-%d", time.Now().UnixNano())
	ecKid := s.tenantKeyID(tenant, model.AlgES256) + fmt.Sprintf("-%d", time.Now().UnixNano())

	rsaJwk, err := s.buildRSAJWK(rsaKid, newRSKey)
	if err != nil {
		return fmt.Errorf("rotate keys: build rsa jwk: %w", err)
	}

	ecJwk := s.buildECJWK(ecKid, newECKey)

	keyring.ActiveKids[model.AlgRS256] = rsaKid
	keyring.ActiveKids[model.AlgES256] = ecKid

	keyring.Keys[rsaKid] = newRSKey
	keyring.Keys[ecKid] = newECKey

	keyring.JWKS = append([]map[string]any{rsaJwk, ecJwk}, keyring.JWKS...)

	return nil
}

func (s *JWTSigner) tenantIdentity(tenant string) (string, string) {
	if tenant == "" {
		tenant = "default"
	}
	issuer := strings.TrimSuffix(httpsScheme+strings.TrimPrefix(tenant, httpsScheme), "/")
	kid := s.tenantKeyID(issuer, model.AlgRS256)
	return issuer, kid
}

func (s *JWTSigner) tenantKeyID(tenant string, alg model.SignatureAlgorithm) string {
	if tenant == "" {
		tenant = "default"
	}
	kidHash := sha256.Sum256(fmt.Appendf(nil, "%s-%s", strings.TrimPrefix(tenant, httpsScheme), alg))
	return fmt.Sprintf("kid-%s-%x", strings.ToLower(string(alg)), kidHash[:16])
}

func (s *JWTSigner) buildRSAJWK(kid string, privateKey *rsa.PrivateKey) (map[string]any, error) {
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

func (s *JWTSigner) buildECJWK(kid string, privateKey *ecdsa.PrivateKey) map[string]any {
	x := base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes())
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"kid": kid,
		"use": "sig",
		"alg": "ES256",
		"x":   x,
		"y":   y,
	}
}

func (s *JWTSigner) getOrCreateKeyring(tenant string, issuer string) (*tenantKeyring, error) {
	s.mu.RLock()
	keyring, ok := s.keyrings[tenant]
	s.mu.RUnlock()
	if ok {
		return keyring, nil
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate tenant rsa key: %w", err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate tenant ecdsa key: %w", err)
	}

	rsaKid := s.tenantKeyID(issuer, model.AlgRS256)
	ecKid := s.tenantKeyID(issuer, model.AlgES256)

	rsaJwk, err := s.buildRSAJWK(rsaKid, rsaKey)
	if err != nil {
		return nil, err
	}

	ecJwk := s.buildECJWK(ecKid, ecKey)

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, exists := s.keyrings[tenant]; exists {
		return existing, nil
	}

	newKeyring := &tenantKeyring{
		ActiveKids: map[model.SignatureAlgorithm]string{
			model.AlgRS256: rsaKid,
			model.AlgES256: ecKid,
		},
		Keys: map[string]any{
			rsaKid: rsaKey,
			ecKid:  ecKey,
		},
		JWKS: []map[string]any{rsaJwk, ecJwk},
	}
	s.keyrings[tenant] = newKeyring
	return newKeyring, nil
}
