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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

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
	mu          sync.RWMutex
	keyrings    map[string]*tenantKeyring
	storage     Storage
	clock       port.Clock
	httpClient  *http.Client
	masterKey   []byte
	adminDomain string
	appEnv      string
}

// Ensure JWTSigner strictly satisfies port.Crypto at compile time.
var _ port.Crypto = (*JWTSigner)(nil)

func NewJWTSigner(storage Storage, cl port.Clock, httpClient *http.Client, masterKey string, adminDomain string, appEnv string) (*JWTSigner, error) {
	if masterKey == "" {
		return nil, errors.New("SPREZZ_MASTER_KEY must not be empty")
	}
	if adminDomain == "" {
		return nil, errors.New("crypto_init: admin_tenant_domain must be explicitly provided")
	}

	keyBytes := []byte(masterKey)
	keyLen := len(keyBytes)

	// 1. If the raw string is already directly 16, 24, or 32 binary bytes, use it immediately
	if keyLen == 16 || keyLen == 24 || keyLen == 32 {
		return &JWTSigner{
			keyrings:  make(map[string]*tenantKeyring),
			storage:   storage,
			clock:     cl,
			masterKey: keyBytes,
		}, nil
	}

	// 2. If it is 64 characters long, it's likely an openssl rand -hex 32 string! Try Hex Decoding.
	if decodedBytes, err := hex.DecodeString(masterKey); err == nil {
		decodedLen := len(decodedBytes)
		if decodedLen == 16 || decodedLen == 24 || decodedLen == 32 {
			return &JWTSigner{
				keyrings:  make(map[string]*tenantKeyring),
				storage:   storage,
				clock:     cl,
				masterKey: decodedBytes, // Correctly resolved to 32 pure binary bytes
			}, nil
		}
	}

	// 3. Fallback: Treat as Base64 encoded transport layout string
	decodedBytes, err := base64.StdEncoding.DecodeString(masterKey)
	if err != nil {
		var fallbackErr error
		decodedBytes, fallbackErr = base64.RawStdEncoding.DecodeString(masterKey)
		if fallbackErr != nil {
			return nil, fmt.Errorf("SPREZZ_MASTER_KEY string configuration layout is invalid (size: %d) and cannot be decoded via Hex or Base64 formats", keyLen)
		}
	}

	// 4. Enforce strict constraint checking on Base64 payload output data
	decodedLen := len(decodedBytes)
	if decodedLen != 16 && decodedLen != 24 && decodedLen != 32 {
		return nil, fmt.Errorf("decoded SPREZZ_MASTER_KEY must be exactly 16, 24, or 32 binary bytes for AES-GCM (current decoded size: %d)", decodedLen)
	}

	return &JWTSigner{
		keyrings:    make(map[string]*tenantKeyring),
		storage:     storage,
		clock:       cl,
		httpClient:  httpClient,
		masterKey:   decodedBytes,
		adminDomain: adminDomain,
		appEnv:      appEnv,
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

// Internal mapper
func (s *JWTSigner) mapAlgorithm(alg model.SignatureAlgorithm) jwt.SigningMethod {
	if alg == model.AlgES256 {
		return jwt.SigningMethodES256
	}
	return jwt.SigningMethodRS256
}

// SignAccessToken maps the pure model.TokenClaims struct directly to the jwt signing chain.
func (s *JWTSigner) SignAccessToken(ctx context.Context, claims model.TokenClaims, alg model.SignatureAlgorithm) (string, error) {
	if alg != model.AlgRS256 && alg != model.AlgES256 {
		return "", fmt.Errorf("unsupported signing algorithm %s", alg)
	}

	issuer := strings.TrimSuffix(claims.Issuer, "/")
	if issuer == "" {
		return "", errors.New("cannot sign access token: issuer claim is mandatory and cannot be empty")
	}
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

	// The library natively marshals your structured type fields using Go's JSON metadata tags
	// Natively leverages your existing internal s.mapAlgorithm(alg) helper method safely
	token := jwt.NewWithClaims(s.mapAlgorithm(alg), claims)
	token.Header["kid"] = kid
	token.Header["typ"] = "at+jwt" // RFC 9068 spec-compliant explicit access token indicator profile

	return token.SignedString(privateKey)
}

// SignIDToken signs OIDC identity statements while enforcing scope-dependent user privacy gates.
func (s *JWTSigner) SignIDToken(ctx context.Context, claims model.OIDCTokenClaims, grantedScopes []string, alg model.SignatureAlgorithm) (string, error) {
	if alg != model.AlgRS256 && alg != model.AlgES256 {
		return "", fmt.Errorf("unsupported signing algorithm %s", alg)
	}

	issuer := claims.Issuer
	if issuer == "" {
		return "", errors.New("cannot sign id token: issuer claim is mandatory and cannot be empty")
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

	// Execute user data minimization scope filtering natively inside the infrastructure layer
	filteredClaims := claims.FilterByScope(grantedScopes)

	// Passes the structured domain object directly into the library claims pipeline
	token := jwt.NewWithClaims(s.mapAlgorithm(alg), filteredClaims)
	token.Header["kid"] = kid
	token.Header["typ"] = "JWT"

	return token.SignedString(privateKey)
}

// SignLogoutToken signs back-channel session revocation tokens according to OIDC Back-Channel Logout profiles.
func (s *JWTSigner) SignLogoutToken(ctx context.Context, claims model.LogoutTokenClaims, alg model.SignatureAlgorithm) (string, error) {
	if alg != model.AlgRS256 && alg != model.AlgES256 {
		return "", fmt.Errorf("unsupported signing algorithm %s", alg)
	}

	issuer := claims.Issuer
	if issuer == "" {
		return "", errors.New("cannot sign logout token: issuer claim is mandatory and cannot be empty")
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

	// Assemble back-channel logout payload requirements using primitive mappings natively
	logoutMapClaims := jwt.MapClaims{
		"iss":    issuer,
		"sub":    claims.Subject,
		"aud":    claims.Audience,
		"jti":    claims.TokenID,
		"iat":    claims.IssuedAt,
		"events": claims.Events,
	}

	// Conditionally append session identifier if active SSO tracing is tracked
	if claims.SessionID != "" {
		logoutMapClaims["sid"] = claims.SessionID
	}

	token := jwt.NewWithClaims(s.mapAlgorithm(alg), logoutMapClaims)
	token.Header["kid"] = kid
	token.Header["typ"] = "logout+jwt" // Explicit spec-compliant profile wrapper identifier

	return token.SignedString(privateKey)
}

// VerifyToken decodes signatures and transforms third-party maps into clean Go primitives
// to satisfy your decoupled pure domain port definitions seamlessly.
func (s *JWTSigner) VerifyToken(tokenStr string) (map[string]any, error) {
	var mapClaims jwt.MapClaims
	token, err := jwt.ParseWithClaims(tokenStr, &mapClaims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("missing kid in token header")
		}

		s.mu.RLock()
		defer s.mu.RUnlock()
		for _, keyring := range s.keyrings {
			if key, exists := keyring.Keys[kid]; exists {
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
				}
			}
		}
		return nil, fmt.Errorf("key not found for kid: %s", kid)
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("crypto: validation failure: %w", err)
	}

	// Implicitly maps jwt.MapClaims straight into map[string]any natively with zero overhead
	return mapClaims, nil
}

// VerifyExternalTokenWithProvider implements federated token validation.
// It resolves public keys via a safe, size-limited JWKS network cache, verifies the asymmetric
// signature, and returns pure primitive maps to decouple the core service domains.
func (s *JWTSigner) VerifyExternalTokenWithProvider(
	ctx context.Context,
	tokenStr string,
	jwksURI string,
	expectedIssuer string,
) (map[string]any, error) {
	// 1. Guard input boundaries against massive buffer payload optimization exploits
	if len(tokenStr) > 8192 {
		return nil, errors.New("crypto: incoming assertion token length exceeds safe execution threshold")
	}

	hasHTTPS := strings.HasPrefix(jwksURI, model.SchemeHttps+"://")
	hasHTTP := strings.HasPrefix(jwksURI, model.SchemeHttp+"://")

	// Structural Guard: Ensure the incoming URL string contains a readable HTTP schema prefix
	if !hasHTTPS && !hasHTTP {
		return nil, errors.New("crypto: dynamic verification endpoints missing valid scheme descriptors")
	}

	// Dynamic Environment Rule: Reject plain-text unencrypted http lines instantly in production/staging environments
	if s.appEnv != "local" && !hasHTTPS {
		return nil, errors.New("crypto: secure boundary restriction rejected target scheme; non-local provider endpoints must utilize https://")
	}

	// 2. Resolve public keys from the target endpoint via secure network pooling
	keys, err := s.resolveRemoteJWKSWithCache(ctx, jwksURI)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed resolving trusted token keys: %w", err)
	}

	// 3. Configure the parser engine using a secure key extraction routine
	var mapClaims jwt.MapClaims
	token, err := jwt.ParseWithClaims(tokenStr, &mapClaims, func(t *jwt.Token) (any, error) {
		kidClaim, _ := t.Header["kid"].(string)
		if kidClaim == "" {
			return nil, errors.New("crypto: token signature verification rejected due to missing 'kid' property")
		}

		// Find the public key matching the token's key identifier
		var targetKey *JWKSEntry
		for _, k := range keys {
			if k.Kid == kidClaim {
				targetKey = &k
				break
			}
		}
		if targetKey == nil {
			return nil, fmt.Errorf("crypto: active trust anchor catalog does not contain key %s", kidClaim)
		}

		// Build public validation matrices based on the target key type
		switch targetKey.Kty {
		case "RSA":
			if !strings.HasPrefix(t.Method.Alg(), "RS") {
				return nil, fmt.Errorf("crypto: signing algorithm family mismatch %s", t.Method.Alg())
			}

			rawN, err := base64.RawURLEncoding.DecodeString(targetKey.N)
			if err != nil {
				return nil, errors.New("crypto: corrupted key public modulus matrix layout")
			}
			rawE, err := base64.RawURLEncoding.DecodeString(targetKey.E)
			if err != nil {
				return nil, errors.New("crypto: corrupted key public exponent entry")
			}

			var bigE int
			for _, b := range rawE {
				bigE = (bigE << 8) | int(b)
			}

			return &rsa.PublicKey{
				N: new(big.Int).SetBytes(rawN),
				E: bigE,
			}, nil

		case "EC":
			if !strings.HasPrefix(t.Method.Alg(), "ES") {
				return nil, fmt.Errorf("crypto: signing algorithm family mismatch %s", t.Method.Alg())
			}

			rawX, err := base64.RawURLEncoding.DecodeString(targetKey.X)
			if err != nil {
				return nil, errors.New("crypto: corrupted elliptic curve public x coordinate")
			}
			rawY, err := base64.RawURLEncoding.DecodeString(targetKey.Y)
			if err != nil {
				return nil, errors.New("crypto: corrupted elliptic curve public y coordinate")
			}

			var curve elliptic.Curve
			switch targetKey.Crv {
			case "P-256":
				curve = elliptic.P256()
			default:
				return nil, fmt.Errorf("crypto: unsupported elliptic curve profile %s", targetKey.Crv)
			}

			publicKeyBytes := make([]byte, 1+32+32)
			publicKeyBytes[0] = 0x04
			copy(publicKeyBytes[1+32-len(rawX):1+32], rawX)
			copy(publicKeyBytes[1+32+32-len(rawY):1+32+32], rawY)

			pubKey, err := ecdsa.ParseUncompressedPublicKey(curve, publicKeyBytes)
			if err != nil {
				return nil, fmt.Errorf("crypto: invalid elliptic curve public key coordinates: %w", err)
			}
			return pubKey, nil

		default:
			return nil, fmt.Errorf("crypto: unsupported key architecture family format %s", targetKey.Kty)
		}
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("crypto: asymmetric verification failed: %w", err)
	}

	tokenIssuer, _ := mapClaims["iss"].(string)
	if tokenIssuer != expectedIssuer {
		return nil, errors.New("crypto: foreign token contains mismatched issuer parameters")
	}

	return mapClaims, nil
}

// SignSoftwareStatement cryptographically signs a structured platform statement envelope
// using the active ES256 key of the specified master administrative tenant domain [1.14].
func (s *JWTSigner) SignSoftwareStatement(
	ctx context.Context,
	issuer string,
	audience string,
	claims model.SoftwareStatementClaims,
	issuedAt time.Time,
	expiresAt time.Time,
) (string, error) {

	// 1. Resolve the admin tenant metadata model straight from storage using the configured domain
	tenantModel, err := s.storage.ResolveTenantByDomain(ctx, issuer)
	if err != nil {
		return "", fmt.Errorf("crypto: sign software statement failed: %w", err)
	}

	// 2. Fetch or bootstrap the administrative tenant's keyring matrix
	baseURI := tenantModel.GetBaseURI()
	keyring, err := s.getOrCreateKeyring(ctx, issuer, baseURI)
	if err != nil {
		return "", err
	}

	s.mu.RLock()
	// Dynamic Registration Software Statements must always be signed using the ES256 algorithm
	kid := keyring.ActiveKids[model.AlgES256]
	privateKey := keyring.Keys[kid]
	s.mu.RUnlock()

	// 3. Hydrate standard OIDC temporal metadata parameters natively into the domain claims frame
	claims.Issuer = issuer
	claims.Audience = []string{audience}
	claims.IssuedAt = jwt.NewNumericDate(issuedAt)
	claims.ExpiresAt = jwt.NewNumericDate(expiresAt)

	// 4. Flatten the structural domain object into library-compliant map layers natively
	mapClaims := claims.ToMapClaims()

	// 5. Build and sign the finalized cryptographic token envelope
	token := jwt.NewWithClaims(s.mapAlgorithm(model.AlgES256), mapClaims)
	token.Header["kid"] = kid
	token.Header["typ"] = "JWT"

	return token.SignedString(privateKey)
}

// --- Supporting JWKS Structures & Network Ingestion Filters ---

type JWKSEntry struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	Crv string `json:"crv,omitempty"`
}

type JWKSCluster struct {
	Keys []JWKSEntry `json:"keys"`
}

// resolveRemoteJWKSWithCache fetches remote public keys while enforcing a strict 1MB response limit
// and routes requests through the secure, SSRF-defended HTTP client pool [5.3].
func (s *JWTSigner) resolveRemoteJWKSWithCache(ctx context.Context, jwksURI string) ([]JWKSEntry, error) {
	// 1. Build the network query execution pass within the current request thread context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}

	// 2. DEFENSIVE GUARD: Execute the request using the injected, secure HTTP client engine.
	// This engine runs safe DialContext checks to completely block DNS rebinding and loopback hops.
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crypto: secure back-channel connection tracking failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crypto: remote key directory returned an invalid status code: %d", resp.StatusCode)
	}

	// 3. Section 5.3 Compliance: Limit stream reader to exactly 1 Megabyte to prevent memory exhaustion [5.3]
	safeLimitReader := io.LimitReader(resp.Body, 1024*1024)
	payloadBytes, err := io.ReadAll(safeLimitReader)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed reading safe remote byte stream payload: %w", err)
	}

	var cluster JWKSCluster
	if err := json.Unmarshal(payloadBytes, &cluster); err != nil {
		return nil, fmt.Errorf("crypto: failed parsing verified public targets structures: %w", err)
	}

	return cluster.Keys, nil
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
	// 1. Read Lock: Fast check if this node already has the keys warm in memory
	s.mu.RLock()
	keyring, ok := s.keyrings[tenant]
	s.mu.RUnlock()
	if ok {
		return keyring, nil
	}

	// 2. Unlocked I/O: Resolve tenant details from the shared relational cluster store
	tenantModel, err := s.storage.ResolveTenantByDomain(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("crypto: resolve tenant domain failed: %w", err)
	}

	// Resolve or seed the shared data encryption key (DEK) inside the DB cluster
	rawDEK, err := s.resolveOrCreateDEK(ctx, tenantModel)
	if err != nil {
		return nil, err
	}

	// 3. Cluster Sync Check: Query the shared DB to see if another cluster node already made keys
	activeKeys, err := s.storage.GetActiveSigningKeys(ctx, tenantModel.ID)
	if err != nil {
		return nil, fmt.Errorf("crypto: active signing keys fetch failed: %w", err)
	}

	// CLUSTER GUARD: If keys exist in DB, load them natively instead of generating new ones on the fly!
	if len(activeKeys) > 0 {
		return s.loadKeyringFromDB(ctx, tenant, tenantModel, rawDEK, activeKeys)
	}

	// 4. Fallback Bootstrap: Only execute generation if the DB cluster is completely fresh (Zero keys exist)
	return s.bootstrapKeyring(ctx, tenant, issuer, tenantModel, rawDEK)
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

// GetMasterRegistrationPublicKey dynamically resolves the active verification public key
// straight out of your bootstrapped admin tenant's in-memory/database keyring graph.
func (s *JWTSigner) GetMasterRegistrationPublicKey() (any, error) {
	ctx := context.Background()

	// 1. Resolve the admin tenant metadata model straight from storage using the configured domain
	adminTenant, err := s.storage.ResolveTenantByDomain(ctx, s.adminDomain)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to resolve admin tenant metadata by domain '%s': %w", s.adminDomain, err)
	}

	// 2. Cleanly construct the admin tenant's canonical issuer identity URI
	adminIssuer := adminTenant.GetBaseURI()

	// 3. Fetch or bootstrap the admin tenant's keyring (auto-decrypting it via the masterKey KEK pattern)
	keyring, err := s.getOrCreateKeyring(context.Background(), s.adminDomain, adminIssuer)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to resolve admin tenant master keyring: %w", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// 4. Extract the active asymmetric ECDSA (ES256) Key ID from the admin tenant's keyring matrix
	activeKid, exists := keyring.ActiveKids[model.AlgES256]
	if !exists {
		return nil, fmt.Errorf("crypto: admin tenant lacks an active ES256 master capability key")
	}

	privateKey, exists := keyring.Keys[activeKid]
	if !exists {
		return nil, fmt.Errorf("crypto: admin private key instance missing from operational memory context caches")
	}

	// 5. Extract and assert type conformity onto the asymmetric public key component
	ecdsaPrivKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("crypto: master admin key type mismatch - expected asymmetric *ecdsa.PrivateKey")
	}

	// 6. Natively expose the public component structure for the golang-jwt validator engine
	return &ecdsaPrivKey.PublicKey, nil
}
