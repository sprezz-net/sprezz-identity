package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
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
	"io"
	"strings"
	"sync"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
)

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
	clock     port.Clock
	masterKey []byte
}

// Ensure JWTSigner strictly satisfies port.Crypto at compile time.
var _ port.Crypto = (*JWTSigner)(nil)

func NewJWTSigner(storage Storage, cl port.Clock, masterKey string) (*JWTSigner, error) {
	if masterKey == "" {
		return nil, errors.New("SPREZZ_MASTER_KEY must not be empty")
	}

	// Enforce key requirements: AES-GCM requires exactly 16, 24, or 32 bytes keys
	keyBytes := []byte(masterKey)
	if len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
		return nil, fmt.Errorf("SPREZZ_MASTER_KEY must be exactly 16, 24, or 32 bytes for AES-GCM (current size: %d)", len(keyBytes))
	}

	return &JWTSigner{
		keyrings:  make(map[string]*tenantKeyring),
		storage:   storage,
		clock:     cl,
		masterKey: keyBytes,
	}, nil
}

// --- Cryptographic Envelope Utilities ---

func (s *JWTSigner) encrypt(plaintext, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher block: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize gcm: %w", err)
	}

	// Generate a high-entropy cryptographically secure random 12-byte nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate random nonce: %w", err)
	}

	// Seal appends the ciphertext directly to the nonce slice space
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, nil
}

func (s *JWTSigner) decrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher block: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize gcm: %w", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm decryption failed: %w", err)
	}

	return plaintext, nil
}

func (s *JWTSigner) encryptDEK(plainDEK []byte) ([]byte, []byte, error) {
	// Reuses the optimized raw byte encryption utility using your configured masterKey string bytes
	ciphertext, nonce, err := s.encrypt(plainDEK, s.masterKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt dek wrapper: %w", err)
	}

	return ciphertext, nonce, nil
}

func (s *JWTSigner) decryptDEK(encDEK, nonce []byte) ([]byte, error) {
	// Reuses our optimized raw decryption logic using the configured masterKey
	plainDEK, err := s.decrypt(encDEK, s.masterKey, nonce)
	if err != nil {
		return nil, fmt.Errorf("decrypt dek wrapper failed: %w", err)
	}

	return plainDEK, nil
}

func (s *JWTSigner) SignAccessToken(ctx context.Context, claims model.TokenClaims, alg model.SignatureAlgorithm) (string, error) {
	if alg != model.AlgRS256 && alg != model.AlgES256 {
		return "", fmt.Errorf("unsupported signing algorithm %s", alg)
	}

	issuer := claims.Issuer
	if issuer == "" {
		return "", errors.New("cannot sign access token: issuer claim is mandatory and cannot be empty")
	}
	issuer = strings.TrimSuffix(issuer, "/")
	tenant := strings.TrimPrefix(issuer, model.SchemeHttps+"://")
	tenant = strings.TrimPrefix(tenant, model.SchemeHttp+"://")

	keyring, err := s.getOrCreateKeyring(ctx, tenant, issuer)
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

func (s *JWTSigner) SignIDToken(ctx context.Context, claims model.OIDCTokenClaims, alg model.SignatureAlgorithm) (string, error) {
	if alg != model.AlgRS256 && alg != model.AlgES256 {
		return "", fmt.Errorf("unsupported signing algorithm %s", alg)
	}

	issuer := claims.Issuer
	if issuer == "" {
		return "", errors.New("cannot sign access token: issuer claim is mandatory and cannot be empty")
	}
	issuer = strings.TrimSuffix(issuer, "/")
	tenant := strings.TrimPrefix(issuer, model.SchemeHttps+"://")
	tenant = strings.TrimPrefix(tenant, model.SchemeHttp+"://")

	keyring, err := s.getOrCreateKeyring(ctx, tenant, issuer)
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

func (s *JWTSigner) SignLogoutToken(ctx context.Context, claims model.LogoutTokenClaims, alg model.SignatureAlgorithm) (string, error) {
	if alg != model.AlgRS256 && alg != model.AlgES256 {
		return "", fmt.Errorf("unsupported signing algorithm %s", alg)
	}

	issuer := claims.Issuer
	if issuer == "" {
		return "", errors.New("cannot sign access token: issuer claim is mandatory and cannot be empty")
	}
	issuer = strings.TrimSuffix(issuer, "/")
	tenant := strings.TrimPrefix(issuer, model.SchemeHttps+"://")
	tenant = strings.TrimPrefix(tenant, model.SchemeHttp+"://")

	keyring, err := s.getOrCreateKeyring(ctx, tenant, issuer)
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

func (s *JWTSigner) JWKSForTenant(ctx context.Context, domain string, scheme string) ([]map[string]any, error) {
	issuer, _, err := s.tenantIdentity(domain, scheme)
	if err != nil {
		return nil, err
	}
	keyring, err := s.getOrCreateKeyring(ctx, domain, issuer)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return keyring.JWKS, nil
}

func (s *JWTSigner) MarshalJWKSet(ctx context.Context, domain string, scheme string) (string, error) {
	jwkSet, err := s.JWKSForTenant(ctx, domain, scheme)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]any{"keys": jwkSet})
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (s *JWTSigner) RotateKeys(ctx context.Context, domain string) error {
	// 1. FAST READ LOCK: Check memory cache up front without holding up other threads
	s.mu.RLock()
	keyring, exists := s.keyrings[domain]
	s.mu.RUnlock()
	if !exists {
		return fmt.Errorf("tenant %s keyring not initialized", domain)
	}

	// 2. UNLOCKED I/O LOOP: Run all slow database and CPU-heavy cryptography work completely unlocked
	tenantModel, err := s.storage.ResolveTenantByDomain(ctx, domain)
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

	newRSKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("rotate keys: generate rsa key: %w", err)
	}

	newECKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("rotate keys: generate ecdsa key: %w", err)
	}

	// Calculate unique rotatable Key IDs utilizing your custom clock port
	nanoSuffix := fmt.Sprintf("-%d", s.clock.Now().UnixNano())

	rsaBase, err := s.tenantKeyID(domain, model.AlgRS256)
	if err != nil {
		return fmt.Errorf("failed to compute rsa key identifier: %w", err)
	}
	rsaKid := rsaBase + nanoSuffix

	ecBase, err := s.tenantKeyID(domain, model.AlgES256)
	if err != nil {
		return fmt.Errorf("failed to compute ec key identifier: %w", err)
	}
	ecKid := ecBase + nanoSuffix

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

	// Execute database transaction writes completely unlocked
	if err := s.storage.RotateSigningKeys(ctx, tenantModel.ID); err != nil {
		return fmt.Errorf("rotate keys: demote active keys: %w", err)
	}

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

	// 3. FAST WRITE LOCK: Secure a lock *only* at the end for an instant in-memory cache map update
	s.mu.Lock()
	keyring.ActiveKids[model.AlgRS256] = rsaKid
	keyring.ActiveKids[model.AlgES256] = ecKid

	keyring.Keys[rsaKid] = newRSKey
	keyring.Keys[ecKid] = newECKey

	keyring.JWKS = append([]map[string]any{rsaJwk, ecJwk}, keyring.JWKS...)
	s.mu.Unlock()

	return nil
}

func (s *JWTSigner) tenantIdentity(domain string, scheme string) (string, string, error) {
	if domain == "" {
		return "", "", errors.New("domain cannot be empty")
	}
	issuer := strings.TrimSuffix(domain, "/")
	issuer = strings.TrimPrefix(issuer, model.SchemeHttps+"://")
	issuer = strings.TrimPrefix(issuer, model.SchemeHttp+"://")
	issuer = scheme + "://" + issuer
	kid, err := s.tenantKeyID(issuer, model.AlgRS256)
	if err != nil {
		return "", "", err
	}
	return issuer, kid, nil
}

func (s *JWTSigner) tenantKeyID(domain string, alg model.SignatureAlgorithm) (string, error) {
	if domain == "" {
		return "", errors.New("domain cannot be empty")
	}
	domain = strings.TrimPrefix(domain, model.SchemeHttps+"://")
	domain = strings.TrimPrefix(domain, model.SchemeHttp+"://")
	kidHash := sha256.Sum256(fmt.Appendf(nil, "%s-%s", domain, alg))
	return fmt.Sprintf("kid-%s-%x", strings.ToLower(string(alg)), kidHash[:16]), nil
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

func (s *JWTSigner) getOrCreateKeyring(ctx context.Context, tenant string, issuer string) (*tenantKeyring, error) {
	s.mu.RLock()
	keyring, ok := s.keyrings[tenant]
	s.mu.RUnlock()
	if ok {
		return keyring, nil
	}

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
	// 1. FAST MEMORY CHECK: Check if another thread already bootstrapped this tenant
	s.mu.RLock()
	existing, exists := s.keyrings[tenant]
	s.mu.RUnlock()
	if exists {
		return existing, nil
	}

	// 2. UNLOCKED CRYPTO OPERATIONS: Generate keys without blocking other application threads
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate tenant rsa key: %w", err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate tenant ecdsa key: %w", err)
	}

	nanoSuffix := fmt.Sprintf("-%d", s.clock.Now().UnixNano())

	rsaBase, err := s.tenantKeyID(issuer, model.AlgRS256)
	if err != nil {
		return nil, fmt.Errorf("failed to compute rsa key identifier: %w", err)
	}
	rsaKid := rsaBase + nanoSuffix

	ecBase, err := s.tenantKeyID(issuer, model.AlgES256)
	if err != nil {
		return nil, fmt.Errorf("failed to compute ec key identifier: %w", err)
	}
	ecKid := ecBase + nanoSuffix

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

	// 3. PERSIST UNLOCKED: Write to DB without holding a global mutex
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

	// 4. CHRONOLOGICAL LOCKING: Lock quickly at the end to save to cache map
	s.mu.Lock()
	// Double check memory safety after acquiring write lock
	if existing, exists := s.keyrings[tenant]; exists {
		s.mu.Unlock()
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
	s.mu.Unlock() // Explicit release immediately

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

// HashCredential wraps the secure cryptographic hashing algorithm
func (s *JWTSigner) HashCredential(secret string) (string, error) {
	// Reuses identical default Argon2id parameters (1 iteration, 64MB memory, 4 threads)
	hash, err := argon2id.CreateHash(secret, argon2id.DefaultParams)
	if err != nil {
		return "", err
	}
	return hash, nil
}

// CompareCredential validates incoming client request string metrics
func (s *JWTSigner) CompareCredential(hashedSecret, plainSecret string) (bool, error) {
	match, err := argon2id.ComparePasswordAndHash(plainSecret, hashedSecret)
	if err != nil {
		return false, err
	}
	return match, nil
}
