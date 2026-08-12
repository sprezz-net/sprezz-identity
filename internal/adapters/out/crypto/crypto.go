package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"sprezz-identity/internal/adapters/out/state"
	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/golang-jwt/jwt/v5"
)

const httpsScheme = "https://"

type tenantKeyring struct {
	ActiveKids map[model.SignatureAlgorithm]string
	Keys       map[string]any
	JWKS       []map[string]any
}

type Storage interface {
	port.CryptoStorage
	ResolveTenantByDomain(ctx context.Context, domain string) (*model.Tenant, error)
}

type JWTSigner struct {
	mu        sync.RWMutex
	keyrings  map[string]*tenantKeyring
	storage   Storage
	masterKey string
}

// Ensure JWTSigner strictly satisfies port.Crypto at compile time.
var _ port.Crypto = (*JWTSigner)(nil)

func NewJWTSigner(storage Storage, masterKey string) (*JWTSigner, error) {
	if masterKey == "" {
		return nil, errors.New("SPREZZ_MASTER_KEY must not be empty")
	}
	return &JWTSigner{
		keyrings:  make(map[string]*tenantKeyring),
		storage:   storage,
		masterKey: masterKey,
	}, nil
}

// --- Cryptographic Envelope Utilities ---

func (s *JWTSigner) encrypt(plaintext, key []byte) ([]byte, []byte, error) {
	plaintextB64 := base64.StdEncoding.EncodeToString(plaintext)
	passphrase := base64.StdEncoding.EncodeToString(key)
	encB64, err := state.EncryptAESGCM(plaintextB64, passphrase)
	if err != nil {
		return nil, nil, err
	}
	data, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return nil, nil, err
	}
	if len(data) < 12 {
		return nil, nil, fmt.Errorf("invalid ciphertext from EncryptAESGCM")
	}
	return data[12:], data[:12], nil
}

func (s *JWTSigner) decrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	combined := append(nonce, ciphertext...)
	combinedB64 := base64.StdEncoding.EncodeToString(combined)
	passphrase := base64.StdEncoding.EncodeToString(key)
	decB64, err := state.DecryptAESGCM(combinedB64, passphrase)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(decB64)
}

func (s *JWTSigner) encryptDEK(plainDEK []byte) ([]byte, []byte, error) {
	plainDEKB64 := base64.StdEncoding.EncodeToString(plainDEK)
	encB64, err := state.EncryptAESGCM(plainDEKB64, s.masterKey)
	if err != nil {
		return nil, nil, err
	}
	data, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return nil, nil, err
	}
	if len(data) < 12 {
		return nil, nil, fmt.Errorf("invalid ciphertext for DEK encryption")
	}
	return data[12:], data[:12], nil
}

func (s *JWTSigner) decryptDEK(encDEK, nonce []byte) ([]byte, error) {
	combined := append(nonce, encDEK...)
	combinedB64 := base64.StdEncoding.EncodeToString(combined)
	decB64, err := state.DecryptAESGCM(combinedB64, s.masterKey)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(decB64)
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

	s.mu.RLock()
	kid := keyring.ActiveKids[alg]
	privateKey := keyring.Keys[kid]
	s.mu.RUnlock()

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

	s.mu.RLock()
	kid := keyring.ActiveKids[alg]
	privateKey := keyring.Keys[kid]
	s.mu.RUnlock()

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

	s.mu.RLock()
	kid := keyring.ActiveKids[alg]
	privateKey := keyring.Keys[kid]
	s.mu.RUnlock()

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

	ctx := context.Background()
	tenantModel, err := s.storage.ResolveTenantByDomain(ctx, tenant)
	if err != nil {
		return fmt.Errorf("resolve tenant by domain: %w", err)
	}

	encDEK, nonceDEK, err := s.storage.GetTenantDEK(ctx, tenantModel.ID)
	if err != nil {
		return fmt.Errorf("get tenant DEK: %w", err)
	}
	rawDEK, err := s.decryptDEK(encDEK, nonceDEK)
	if err != nil {
		return fmt.Errorf("decrypt tenant DEK: %w", err)
	}

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

	pkcs8Rsa, err := x509.MarshalPKCS8PrivateKey(newRSKey)
	if err != nil {
		return fmt.Errorf("rotate keys: marshal rsa private key: %w", err)
	}
	pkcs8Ec, err := x509.MarshalPKCS8PrivateKey(newECKey)
	if err != nil {
		return fmt.Errorf("rotate keys: marshal ecdsa private key: %w", err)
	}

	encRsa, nonceRsa, err := s.encrypt(pkcs8Rsa, rawDEK)
	if err != nil {
		return fmt.Errorf("rotate keys: encrypt rsa private key: %w", err)
	}
	encEc, nonceEc, err := s.encrypt(pkcs8Ec, rawDEK)
	if err != nil {
		return fmt.Errorf("rotate keys: encrypt ecdsa private key: %w", err)
	}

	// Demote active signing keys to verification-only
	if err := s.storage.RotateSigningKeys(ctx, tenantModel.ID); err != nil {
		return fmt.Errorf("rotate keys: demote active keys: %w", err)
	}

	// Insert new keys as active signing keys
	_, err = s.storage.InsertSigningKey(ctx, tenantModel.ID, model.SigningKey{
		Kid:       rsaKid,
		Algorithm: string(model.AlgRS256),
		PublicJWK: rsaJwk,
	}, encRsa, nonceRsa)
	if err != nil {
		return fmt.Errorf("rotate keys: insert new rsa signing key: %w", err)
	}

	_, err = s.storage.InsertSigningKey(ctx, tenantModel.ID, model.SigningKey{
		Kid:       ecKid,
		Algorithm: string(model.AlgES256),
		PublicJWK: ecJwk,
	}, encEc, nonceEc)
	if err != nil {
		return fmt.Errorf("rotate keys: insert new ecdsa signing key: %w", err)
	}

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

	ctx := context.Background()
	tenantModel, err := s.storage.ResolveTenantByDomain(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant by domain: %w", err)
	}

	rawDEK, err := s.resolveOrCreateDEK(ctx, tenantModel)
	if err != nil {
		return nil, err
	}

	activeKeys, err := s.storage.GetActiveSigningKeys(ctx, tenantModel.ID)
	if err != nil {
		return nil, fmt.Errorf("get active signing keys: %w", err)
	}

	if len(activeKeys) == 0 {
		return s.bootstrapKeyring(ctx, tenant, issuer, tenantModel, rawDEK)
	}

	return s.loadKeyringFromDB(ctx, tenant, tenantModel, rawDEK, activeKeys)
}

func (s *JWTSigner) resolveOrCreateDEK(ctx context.Context, tenantModel *model.Tenant) ([]byte, error) {
	encDEK, nonceDEK, err := s.storage.GetTenantDEK(ctx, tenantModel.ID)
	if err == nil && len(encDEK) > 0 {
		rawDEK, err := s.decryptDEK(encDEK, nonceDEK)
		if err != nil {
			return nil, fmt.Errorf("decrypt tenant DEK: %w", err)
		}
		return rawDEK, nil
	}

	rawDEK := make([]byte, 32)
	if _, err := rand.Read(rawDEK); err != nil {
		return nil, fmt.Errorf("generate random DEK: %w", err)
	}
	encryptedDEK, nonce, err := s.encryptDEK(rawDEK)
	if err != nil {
		return nil, fmt.Errorf("encrypt tenant DEK: %w", err)
	}
	if err := s.storage.InsertTenantDEK(ctx, tenantModel.ID, encryptedDEK, nonce); err != nil {
		return nil, fmt.Errorf("insert tenant DEK: %w", err)
	}
	return rawDEK, nil
}

func (s *JWTSigner) bootstrapKeyring(ctx context.Context, tenant, issuer string, tenantModel *model.Tenant, rawDEK []byte) (*tenantKeyring, error) {
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

	pkcs8Rsa, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		return nil, err
	}
	pkcs8Ec, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		return nil, err
	}

	encRsa, nonceRsa, err := s.encrypt(pkcs8Rsa, rawDEK)
	if err != nil {
		return nil, err
	}
	encEc, nonceEc, err := s.encrypt(pkcs8Ec, rawDEK)
	if err != nil {
		return nil, err
	}

	_, err = s.storage.InsertSigningKey(ctx, tenantModel.ID, model.SigningKey{
		Kid:       rsaKid,
		Algorithm: string(model.AlgRS256),
		PublicJWK: rsaJwk,
	}, encRsa, nonceRsa)
	if err != nil {
		return nil, err
	}

	_, err = s.storage.InsertSigningKey(ctx, tenantModel.ID, model.SigningKey{
		Kid:       ecKid,
		Algorithm: string(model.AlgES256),
		PublicJWK: ecJwk,
	}, encEc, nonceEc)
	if err != nil {
		return nil, err
	}

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

func (s *JWTSigner) loadKeyringFromDB(ctx context.Context, tenant string, tenantModel *model.Tenant, rawDEK []byte, activeKeys []model.SigningKey) (*tenantKeyring, error) {
	keysMap := make(map[string]any)
	activeKids := make(map[model.SignatureAlgorithm]string)
	var jwks []map[string]any

	for _, k := range activeKeys {
		decryptedPriv, err := s.decrypt(k.RawEncryptedPrivateKey, rawDEK, k.CryptoNonce)
		if err != nil {
			return nil, fmt.Errorf("decrypt private key %s: %w", k.Kid, err)
		}

		parsedKey, err := x509.ParsePKCS8PrivateKey(decryptedPriv)
		if err != nil {
			return nil, fmt.Errorf("parse decrypted private key: %w", err)
		}

		keysMap[k.Kid] = parsedKey
		alg := model.SignatureAlgorithm(k.Algorithm)
		activeKids[alg] = k.Kid
		jwks = append(jwks, k.PublicJWK)
	}

	verKeys, err := s.storage.GetActiveVerificationKeys(ctx, tenantModel.ID)
	if err == nil {
		jwks = mergeVerificationKeys(jwks, verKeys)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, exists := s.keyrings[tenant]; exists {
		return existing, nil
	}

	newKeyring := &tenantKeyring{
		ActiveKids: activeKids,
		Keys:       keysMap,
		JWKS:       jwks,
	}
	s.keyrings[tenant] = newKeyring
	return newKeyring, nil
}

func mergeVerificationKeys(jwks []map[string]any, verKeys []model.SigningKey) []map[string]any {
	for _, k := range verKeys {
		alreadyIn := false
		for _, j := range jwks {
			if j["kid"] == k.Kid {
				alreadyIn = true
				break
			}
		}
		if !alreadyIn {
			jwks = append(jwks, k.PublicJWK)
		}
	}
	return jwks
}
