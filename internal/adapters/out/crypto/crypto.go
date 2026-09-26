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
	"github.com/google/uuid"
)

type tenantKeyring struct {
	ActiveKids map[model.SignatureAlgorithm]string
	Keys       map[string]any
	JWKS       []map[string]any
}

type Storage interface {
	port.CryptoStorage

	GetActiveSigningKeys(ctx context.Context, tenantUUID uuid.UUID) ([]model.SigningKey, error)
	GetActiveVerificationKeys(ctx context.Context, tenantUUID uuid.UUID) ([]model.SigningKey, error)
	GetTenantDEK(ctx context.Context, tenantUUID uuid.UUID) (encryptedDEK []byte, nonce []byte, err error)
	InsertSigningKey(ctx context.Context, tenantUUID uuid.UUID, key model.SigningKey, encryptedPrivateKey []byte, nonce []byte) (string, error)
	InsertTenantDEK(ctx context.Context, tenantUUID uuid.UUID, encryptedDEK []byte, nonce []byte) error
	ResolveTenantByDomain(ctx context.Context, domain string) (*model.Tenant, error)
	RotateSigningKeys(ctx context.Context, tenantUUID uuid.UUID) error
}

type JWTSigner struct {
	mu             sync.RWMutex
	keyrings       map[string]*tenantKeyring
	flatPublicKeys map[string]any // OPTIMIZED: High-performance O(1) global verification lookup table
	storage        Storage
	clock          port.Clock
	httpClient     *http.Client
	masterKey      []byte
	adminDomain    string
	appEnv         string
}

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

	var decodedBytes []byte

	// 1. If the raw string is already directly 16, 24, or 32 binary bytes, use it immediately
	if keyLen == 16 || keyLen == 24 || keyLen == 32 {
		decodedBytes = keyBytes
	} else if len(masterKey) == 64 {
		// 2. If it is 64 characters long, it's likely an openssl rand -hex 32 string! Try Hex Decoding.
		if db, err := hex.DecodeString(masterKey); err == nil {
			decodedLen := len(db)
			if decodedLen == 16 || decodedLen == 24 || decodedLen == 32 {
				decodedBytes = db
			}
		}
	}

	if decodedBytes == nil {
		// 3. Fallback: Treat as Base64 encoded transport layout string
		db, err := base64.StdEncoding.DecodeString(masterKey)
		if err != nil {
			db, _ = base64.RawStdEncoding.DecodeString(masterKey)
		}
		decodedBytes = db
	}

	// 4. Enforce strict constraint checking on Base64 payload output data
	if len(decodedBytes) != 16 && len(decodedBytes) != 24 && len(decodedBytes) != 32 {
		return nil, fmt.Errorf("decoded SPREZZ_MASTER_KEY size is invalid: %d", len(decodedBytes))
	}

	return &JWTSigner{
		keyrings:       make(map[string]*tenantKeyring),
		flatPublicKeys: make(map[string]any),
		storage:        storage,
		clock:          cl,
		httpClient:     httpClient,
		masterKey:      decodedBytes,
		adminDomain:    adminDomain,
		appEnv:         appEnv,
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
	return aesgcm.Seal(nil, nonce, plaintext, nil), nonce, nil
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

	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

func (s *JWTSigner) encryptDEK(plainDEK []byte) ([]byte, []byte, error) {
	// Reuses the optimized raw byte encryption utility using your configured masterKey string bytes
	return s.encrypt(plainDEK, s.masterKey)
}

func (s *JWTSigner) decryptDEK(encDEK, nonce []byte) ([]byte, error) {
	// Reuses our optimized raw decryption logic using the configured masterKey
	return s.decrypt(encDEK, s.masterKey, nonce)
}

// Internal mapper
func (s *JWTSigner) mapAlgorithm(alg model.SignatureAlgorithm) jwt.SigningMethod {
	if alg == model.AlgES256 {
		return jwt.SigningMethodES256
	}
	return jwt.SigningMethodRS256
}

// ============================================================================
// SIGNING HOT-PATHS
// ============================================================================

// SignAccessToken maps the pure model.TokenClaims struct directly to the jwt signing chain.
func (s *JWTSigner) SignAccessToken(ctx context.Context, claims model.TokenClaims, alg model.SignatureAlgorithm) (string, error) {
	if alg != model.AlgRS256 && alg != model.AlgES256 {
		return "", fmt.Errorf("unsupported signing algorithm %s", alg)
	}

	issuer := strings.TrimSuffix(claims.Issuer, "/")
	if issuer == "" {
		return "", errors.New("cannot sign access token: issuer claim is mandatory")
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
	token := jwt.NewWithClaims(s.mapAlgorithm(alg), &accessTokenClaimsWrapper{TokenClaims: claims})
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
		return "", errors.New("cannot sign id token: issuer claim is mandatory")
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
	token := jwt.NewWithClaims(s.mapAlgorithm(alg), &oidcTokenClaimsWrapper{OIDCTokenClaims: filteredClaims})
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
		return "", errors.New("cannot sign logout token: issuer claim is mandatory")
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

// ============================================================================
// VERIFICATION HOT-PATHS (FULLY OPTIMIZED)
// ============================================================================

// VerifyToken decodes signatures and transforms third-party maps into clean Go primitives
// to satisfy your decoupled pure domain port definitions seamlessly.
func (s *JWTSigner) VerifyToken(tokenStr string) (map[string]any, error) {
	// 1. Unverified parse to safely extract issuer for keyring warm-up
	var unverifiedClaims jwt.MapClaims
	parser := jwt.NewParser()
	_, _, err := parser.ParseUnverified(tokenStr, &unverifiedClaims)
	if err == nil {
		if iss, ok := unverifiedClaims["iss"].(string); ok && iss != "" {
			iss = strings.TrimSuffix(iss, "/")
			tenantDomain := strings.TrimPrefix(iss, model.SchemeHttps+"://")
			tenantDomain = strings.TrimPrefix(tenantDomain, model.SchemeHttp+"://")

			// Keep keyring warm
			_, _ = s.getOrCreateKeyring(context.Background(), tenantDomain, iss)
		}
	}

	var mapClaims jwt.MapClaims
	token, err := jwt.ParseWithClaims(tokenStr, &mapClaims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("missing kid in token header")
		}

		// Highly optimized O(1) concurrent read-lock check using flat global map!
		s.mu.RLock()
		cachedKey, exists := s.flatPublicKeys[kid]
		s.mu.RUnlock()

		if !exists {
			return nil, fmt.Errorf("key not found for kid: %s", kid)
		}

		// Perform signature family validation checks straight across the unboxed type fields
		switch k := cachedKey.(type) {
		case *rsa.PublicKey:
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return k, nil
		case *ecdsa.PublicKey:
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported key type family format mapped inside cache")
		}
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
func (s *JWTSigner) VerifyExternalTokenWithProvider(ctx context.Context, tokenStr string, jwksURI string, expectedIssuer string) (map[string]any, error) {
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
		return nil, errors.New("crypto: secure boundary restriction rejected target scheme")
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
			return nil, errors.New("crypto: token signature verification rejected due to missing 'kid'")
		}

		// Find the public key matching the token's key identifier
		var targetKey *JWKSEntry
		for i := range keys {
			if keys[i].Kid == kidClaim {
				targetKey = &keys[i]
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

			rawN, errN := base64.RawURLEncoding.DecodeString(targetKey.N)
			rawE, errE := base64.RawURLEncoding.DecodeString(targetKey.E)
			if errN != nil || errE != nil {
				return nil, errors.New("crypto: corrupted key public coordinates")
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

			rawX, errX := base64.RawURLEncoding.DecodeString(targetKey.X)
			rawY, errY := base64.RawURLEncoding.DecodeString(targetKey.Y)
			if errX != nil || errY != nil {
				return nil, errors.New("crypto: corrupted elliptic curve public key coordinates")
			}

			var curve elliptic.Curve
			if targetKey.Crv == "P-256" {
				curve = elliptic.P256()
			} else {
				return nil, fmt.Errorf("crypto: unsupported elliptic curve profile %s", targetKey.Crv)
			}

			publicKeyBytes := make([]byte, 1+32+32)
			publicKeyBytes[0] = 0x04
			copy(publicKeyBytes[1+32-len(rawX):1+32], rawX)
			copy(publicKeyBytes[1+32+32-len(rawY):1+32+32], rawY)

			return ecdsa.ParseUncompressedPublicKey(curve, publicKeyBytes)

		default:
			return nil, fmt.Errorf("crypto: unsupported key family format %s", targetKey.Kty)
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

// ParseAndVerifyExternalToken processes inbound assertions by combining unverified metadata extraction with signature validation.
func (s *JWTSigner) ParseAndVerifyExternalToken(ctx context.Context, tokenStr string, jwksURI string, expectedIssuer string) (*model.ExternalTokenClaims, error) {
	// Call your pre-existing optimized validation path natively
	mapClaims, err := s.VerifyExternalTokenWithProvider(ctx, tokenStr, jwksURI, expectedIssuer)
	if err != nil {
		return nil, err
	}

	// Safely map third-party payload maps onto pure un-annotated domain tracking structures
	sub, _ := mapClaims["sub"].(string)
	email, _ := mapClaims["email"].(string)
	emailVerified, _ := mapClaims["email_verified"].(bool)
	acr, _ := mapClaims["acr"].(string)

	var amr []string
	if amrRaw, exists := mapClaims["amr"]; exists {
		if amrSlice, ok := amrRaw.([]any); ok {
			for i := range amrSlice {
				if str, ok := amrSlice[i].(string); ok {
					amr = append(amr, str)
				}
			}
		}
	}

	return &model.ExternalTokenClaims{
		Issuer:        expectedIssuer,
		Subject:       sub,
		Email:         email,
		EmailVerified: emailVerified,
		ACR:           acr,
		AMR:           amr,
	}, nil
}

// ExtractUnverifiedMetadata inspects an inbound token string to extract its issuer and email claims safely.
func (s *JWTSigner) ExtractUnverifiedMetadata(tokenStr string) (string, string, error) {
	parser := jwt.NewParser()
	unverifiedToken, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return "", "", fmt.Errorf("crypto: structural unverified decoding failed: %w", err)
	}

	unverifiedClaims, ok := unverifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", errors.New("crypto: corrupt unverified token claims container layout")
	}

	issuer, _ := unverifiedClaims["iss"].(string)
	email, _ := unverifiedClaims["email"].(string)

	return issuer, email, nil
}

// ExtractUnverifiedRevocationMetadata inspects an inbound unverified token string to extract its unique JTI and client identity bindings.
func (s *JWTSigner) ExtractUnverifiedRevocationMetadata(tokenStr string) (string, string, error) {
	parser := jwt.NewParser()
	unverifiedToken, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return "", "", fmt.Errorf("crypto: structural unverified decoding failed: %w", err)
	}

	unverifiedClaims, ok := unverifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", errors.New("crypto: corrupt unverified token claims container layout")
	}

	tokenID, _ := unverifiedClaims["jti"].(string)

	// Read standard OAuth2 client mapping handles natively
	clientID, _ := unverifiedClaims["client_id"].(string)
	if clientID == "" {
		clientID, _ = unverifiedClaims["azp"].(string)
	}

	return tokenID, clientID, nil
}

// ============================================================================
// SYSTEM KEYRINGS & RECOVERY HANDLERS
// ============================================================================

func (s *JWTSigner) SignSoftwareStatement(ctx context.Context, issuer, audience string, claims model.SoftwareStatementClaims, issuedAt, expiresAt, notBefore time.Time) (string, error) {
	// 1. Resolve the tenant metadata model straight from storage using the configured domain
	tenantModel, err := s.storage.ResolveTenantByDomain(ctx, issuer)
	if err != nil {
		return "", fmt.Errorf("crypto: sign software statement failed: %w", err)
	}

	// 2. Fetch or bootstrap the tenant's keyring matrix
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
	claimsMap := jwt.MapClaims{
		"iss":              issuer,
		"aud":              []string{audience},
		"iat":              jwt.NewNumericDate(issuedAt),
		"exp":              jwt.NewNumericDate(expiresAt),
		"software_id":      claims.SoftwareID,
		"software_version": claims.SoftwareVersion,
		"jti":              uuid.New().String(),
	}

	// Conditionally inject optional claims to prevent "null" or empty string mutations
	if !notBefore.IsZero() {
		claimsMap["nbf"] = jwt.NewNumericDate(notBefore)
	}
	if claims.ClientName != "" {
		claimsMap["client_name"] = claims.ClientName
	}
	if claims.Subject != "" {
		claimsMap["sub"] = claims.Subject
	}
	if len(claims.RedirectURIs) > 0 {
		claimsMap["redirect_uris"] = claims.RedirectURIs
	}
	if len(claims.PostLogoutRedirectURIs) > 0 {
		claimsMap["post_logout_redirect_uris"] = claims.PostLogoutRedirectURIs
	}
	if len(claims.Scopes) > 0 {
		claimsMap["scopes"] = claims.Scopes
	}

	// 4. Build and sign the finalized cryptographic token envelope
	token := jwt.NewWithClaims(s.mapAlgorithm(model.AlgES256), claimsMap)
	token.Header["kid"] = kid
	token.Header["typ"] = "JWT"

	return token.SignedString(privateKey)
}

// DecodeAndVerifySoftwareStatement processes incoming dynamic tokens using a unified, multi-tenant JWKS pipeline.
// Fully satisfies structural jwt.Claims interface requirements using our adapter wrapper isolation boundaries.
func (s *JWTSigner) DecodeAndVerifySoftwareStatement(ctx context.Context, currentTenant *model.Tenant, ssa string) (*model.SoftwareStatementClaims, error) {
	if ssa == "" {
		return nil, errors.New("software_statement: raw token string parameter is missing")
	}

	// 1. Unpack token unverified first to read the header 'kid' and the claims container
	parser := jwt.NewParser()
	var wrapper softwareStatementClaimsWrapper
	unverifiedToken, _, err := parser.ParseUnverified(ssa, &wrapper)
	if err != nil {
		return nil, fmt.Errorf("software_statement: structural token decoding failed: %w", err)
	}

	tokenKID, _ := unverifiedToken.Header["kid"].(string)
	if tokenKID == "" {
		return nil, errors.New("software_statement: missing mandatory 'kid' header parameter")
	}

	audiences, err := wrapper.GetAudience()
	if err != nil || len(audiences) == 0 {
		return nil, errors.New("software_statement: missing mandatory 'aud' claim parameter")
	}

	// 2. STRICT AUDIENCE ISOLATION CHECK
	currentTenantBaseURI := currentTenant.GetBaseURI()
	hasValidAudience := false
	for _, audStr := range audiences {
		if audStr == currentTenantBaseURI {
			hasValidAudience = true
			break
		}
	}

	if !hasValidAudience {
		return nil, fmt.Errorf("software statement is not targeted for this tenant context (mismatched audience)")
	}

	// 3. CRYPTOGRAPHIC KEY RESOLUTION
	jwkSet, err := s.JWKSForTenant(ctx, currentTenant.Domain, currentTenant.Scheme)
	if err != nil {
		return nil, fmt.Errorf("software_statement: failed resolving tenant keyset footprint: %w", err)
	}

	targetPublicKey, err := s.FindPublicKeyInJWKS(jwkSet, tokenKID)
	if err != nil {
		return nil, fmt.Errorf("software_statement: unable to locate key ID '%s' inside tenant JWKS: %w", tokenKID, err)
	}

	// 4. SECURE SIGNATURE VERIFICATION PASS
	var verifiedWrapper softwareStatementClaimsWrapper
	_, err = jwt.ParseWithClaims(ssa, &verifiedWrapper, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected dynamic registration signature method: %v", t.Header["alg"])
			}
		}
		return targetPublicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("software statement validation failed: %w", err)
	}

	// Return the pure un-annotated domain model struct stripped of all library bindings
	return &verifiedWrapper.SoftwareStatementClaims, nil
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

func (s *JWTSigner) JWKSForTenant(ctx context.Context, domain, scheme string) ([]map[string]any, error) {
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

// FindPublicKeyInJWKS matches a specific key ID inside a raw JWK set slice mapping
// and transforms its string coordinates back into a native compilable public key instance.
func (s *JWTSigner) FindPublicKeyInJWKS(jwks []map[string]any, kid string) (any, error) {
	var targetJWK map[string]any
	for i := range jwks {
		if kidVal, ok := jwks[i]["kid"].(string); ok && kidVal == kid {
			targetJWK = jwks[i]
			break
		}
	}

	if targetJWK == nil {
		return nil, fmt.Errorf("crypto: key ID '%s' not found inside the provided JWK set context", kid)
	}

	kty, _ := targetJWK["kty"].(string)
	switch kty {
	case "RSA":
		modulusStr, _ := targetJWK["n"].(string)
		exponentStr, _ := targetJWK["e"].(string)

		rawN, errN := base64.RawURLEncoding.DecodeString(modulusStr)
		rawE, errE := base64.RawURLEncoding.DecodeString(exponentStr)
		if errN != nil || errE != nil {
			return nil, fmt.Errorf("crypto: corrupted RSA public key parameters inside target JWK")
		}

		var bigE int
		for _, b := range rawE {
			bigE = (bigE << 8) | int(b)
		}

		return &rsa.PublicKey{
			// Reconstructs the mathematical modulus value safely
			N: new(big.Int).SetBytes(rawN),
			E: bigE,
		}, nil

	case "EC":
		xStr, _ := targetJWK["x"].(string)
		yStr, _ := targetJWK["y"].(string)
		crv, _ := targetJWK["crv"].(string)

		rawX, errX := base64.RawURLEncoding.DecodeString(xStr)
		rawY, errY := base64.RawURLEncoding.DecodeString(yStr)
		if errX != nil || errY != nil {
			return nil, fmt.Errorf("crypto: corrupted elliptic curve public key coordinates inside target JWK")
		}

		var curve elliptic.Curve
		if crv == "P-256" {
			curve = elliptic.P256()
		} else {
			return nil, fmt.Errorf("crypto: unsupported elliptic curve profile family '%s'", crv)
		}

		publicKeyBytes := make([]byte, 1+32+32)
		publicKeyBytes[0] = 0x04 // Uncompressed key format indicator byte
		copy(publicKeyBytes[1+32-len(rawX):1+32], rawX)
		copy(publicKeyBytes[1+32+32-len(rawY):1+32+32], rawY)

		return ecdsa.ParseUncompressedPublicKey(curve, publicKeyBytes)

	default:
		return nil, fmt.Errorf("crypto: unsupported cryptographic key family format '%s'", kty)
	}
}

func (s *JWTSigner) MarshalJWKSet(ctx context.Context, domain, scheme string) (string, error) {
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

	pkcs8Rsa, _ := x509.MarshalPKCS8PrivateKey(newRSKey)
	pkcs8Ec, _ := x509.MarshalPKCS8PrivateKey(newECKey)

	encRsa, nonceRsa, _ := s.encrypt(pkcs8Rsa, rawDEK)
	encEc, nonceEc, _ := s.encrypt(pkcs8Ec, rawDEK)

	// Execute database transaction writes completely unlocked
	if err := s.storage.RotateSigningKeys(ctx, tenantModel.ID); err != nil {
		return fmt.Errorf("rotate keys: demote active keys: %w", err)
	}

	_, _ = s.storage.InsertSigningKey(ctx, tenantModel.ID, model.SigningKey{Kid: rsaKid, Algorithm: string(model.AlgRS256), PublicJWK: rsaJwk}, encRsa, nonceRsa)
	_, _ = s.storage.InsertSigningKey(ctx, tenantModel.ID, model.SigningKey{Kid: ecKid, Algorithm: string(model.AlgES256), PublicJWK: ecJwk}, encEc, nonceEc)

	// 3. FAST WRITE LOCK: Secure a lock *only* at the end for an instant in-memory cache map update
	s.mu.Lock()
	keyring.ActiveKids[model.AlgRS256] = rsaKid
	keyring.ActiveKids[model.AlgES256] = ecKid

	keyring.Keys[rsaKid] = newRSKey
	keyring.Keys[ecKid] = newECKey

	keyring.JWKS = append([]map[string]any{rsaJwk, ecJwk}, keyring.JWKS...)

	// Inject newly minted verification keys straight into the global high-performance look-up cache map
	s.flatPublicKeys[rsaKid] = &newRSKey.PublicKey
	s.flatPublicKeys[ecKid] = &newECKey.PublicKey
	s.mu.Unlock()

	return nil
}

func (s *JWTSigner) tenantIdentity(domain, scheme string) (string, string, error) {
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
		return s.decryptDEK(encDEK, nonceDEK)
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

	pkcs8Rsa, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	pkcs8Ec, _ := x509.MarshalPKCS8PrivateKey(ecKey)

	encRsa, nonceRsa, _ := s.encrypt(pkcs8Rsa, rawDEK)
	encEc, nonceEc, _ := s.encrypt(pkcs8Ec, rawDEK)

	_, err = s.storage.InsertSigningKey(ctx, tenantModel.ID, model.SigningKey{Kid: rsaKid, Algorithm: string(model.AlgRS256), PublicJWK: rsaJwk}, encRsa, nonceRsa)
	if err != nil {
		return nil, err
	}
	_, err = s.storage.InsertSigningKey(ctx, tenantModel.ID, model.SigningKey{Kid: ecKid, Algorithm: string(model.AlgES256), PublicJWK: ecJwk}, encEc, nonceEc)
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
		ActiveKids: map[model.SignatureAlgorithm]string{model.AlgRS256: rsaKid, model.AlgES256: ecKid},
		Keys:       map[string]any{rsaKid: rsaKey, ecKid: ecKey},
		JWKS:       []map[string]any{rsaJwk, ecJwk},
	}
	s.keyrings[tenant] = newKeyring

	// Index verification vectors into the high-performance flat cache instantly
	s.flatPublicKeys[rsaKid] = &rsaKey.PublicKey
	s.flatPublicKeys[ecKid] = &ecKey.PublicKey

	s.mu.Unlock() // Explicit release immediately
	return newKeyring, nil
}

func (s *JWTSigner) loadKeyringFromDB(ctx context.Context, tenant string, tenantModel *model.Tenant, rawDEK []byte, activeKeys []model.SigningKey) (*tenantKeyring, error) {
	keysMap := make(map[string]any)
	activeKids := make(map[model.SignatureAlgorithm]string)
	var jwks []map[string]any

	for i := range activeKeys {
		k := activeKeys[i]
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
	if existing, exists := s.keyrings[tenant]; exists {
		s.mu.Unlock()
		return existing, nil
	}

	newKeyring := &tenantKeyring{
		ActiveKids: activeKids,
		Keys:       keysMap,
		JWKS:       jwks,
	}
	s.keyrings[tenant] = newKeyring

	// Unpack all decrypted target database private keys to populate public key references
	for kid, privKey := range keysMap {
		switch pk := privKey.(type) {
		case *rsa.PrivateKey:
			s.flatPublicKeys[kid] = &pk.PublicKey
		case *ecdsa.PrivateKey:
			s.flatPublicKeys[kid] = &pk.PublicKey
		}
	}

	// Unpack historic verification key fragments to populate public cache references
	for i := range verKeys {
		vk := verKeys[i]
		if _, exists := s.flatPublicKeys[vk.Kid]; !exists {
			if parsedPubKey, err := s.FindPublicKeyInJWKS(jwks, vk.Kid); err == nil {
				s.flatPublicKeys[vk.Kid] = parsedPubKey
			}
		}
	}

	s.mu.Unlock() // Explicitly release write lock
	return newKeyring, nil
}

// mergeVerificationKeys appends historical verification keys to the JWKS array
// while strictly filtering out duplicate Key IDs (kids) to prevent payload corruption.
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
// Overrode library defaults to strictly enforce §3.3 spec compliance (t=3, m=65536, p=2)
func (s *JWTSigner) HashCredential(secret string) (string, error) {
	customParams := &argon2id.Params{
		Memory:      65536, // 64MB memory profile requirement
		Iterations:  3,     // t=3 iterations execution threshold
		Parallelism: 2,     // p=2 concurrent execution threads
		SaltLength:  16,    // 16-byte cryptographically secure entropy salt
		KeyLength:   32,    // 32-byte final output hash length
	}

	hash, err := argon2id.CreateHash(secret, customParams)
	if err != nil {
		return "", fmt.Errorf("crypto: argon2id computation failed: %w", err)
	}
	return hash, nil
}

// CompareCredential validates incoming client request string metrics
func (s *JWTSigner) CompareCredential(hashedSecret, plainSecret string) (bool, error) {
	return argon2id.ComparePasswordAndHash(plainSecret, hashedSecret)
}
