package crypto

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestJWTSigner_SignAccessToken_Success(t *testing.T) {
	signer := newTestSigner(t)
	ctx := context.Background()

	claims := model.TokenClaims{
		TokenID:   "token-123",
		Issuer:    "https://auth.example.com",
		TenantID:  "https://auth.example.com",
		Subject:   "user-sub",
		ClientID:  "client-id",
		Scopes:    []string{"openid", "profile"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}

	tokenStr, err := signer.SignAccessToken(ctx, claims, model.AlgRS256)
	if err != nil {
		t.Fatalf("unexpected error signing access token: %v", err)
	}

	if tokenStr == "" {
		t.Fatal("expected non-empty signed token string")
	}

	// Verify JWT parsing using the generated public key in JWKS
	jwkSet, err := signer.JWKSForTenant(ctx, "auth.example.com", "https")
	if err != nil {
		t.Fatalf("failed to retrieve JWKS: %v", err)
	}
	if len(jwkSet) == 0 {
		t.Fatal("expected JWKS to contain at least one key")
	}

	// Parse unverified to extract kid
	parser := jwt.NewParser()
	unverifiedToken, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("failed to parse token unverified: %v", err)
	}
	kid, ok := unverifiedToken.Header["kid"].(string)
	if !ok || kid == "" {
		t.Fatal("token missing kid header")
	}

	// Verify key matching
	matched := false
	for _, key := range jwkSet {
		if key["kid"] == kid {
			matched = true
			break
		}
	}
	if !matched {
		t.Errorf("token kid %q not found in JWKS", kid)
	}

	// Verify the parsed claims contain 'tid'
	claimsVerified, err := signer.VerifyToken(tokenStr)
	if err != nil {
		t.Fatalf("failed to verify RS256 token: %v", err)
	}
	if claimsVerified["tid"] != "https://auth.example.com" {
		t.Errorf("expected tid 'https://auth.example.com', got %v", claimsVerified["tid"])
	}
}

func TestJWTSigner_SignAccessToken_ES256_Success(t *testing.T) {
	signer := newTestSigner(t)
	ctx := context.Background()

	claims := model.TokenClaims{
		TokenID:   "token-es256-123",
		Issuer:    "https://auth.example.com",
		TenantID:  "https://auth.example.com",
		Subject:   "user-sub",
		ClientID:  "client-id",
		Scopes:    []string{"openid", "profile"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}

	tokenStr, err := signer.SignAccessToken(ctx, claims, model.AlgES256)
	if err != nil {
		t.Fatalf("unexpected error signing access token ES256: %v", err)
	}

	if tokenStr == "" {
		t.Fatal("expected non-empty signed token string")
	}

	claimsVerified, err := signer.VerifyToken(tokenStr)
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}

	if claimsVerified["sub"] != "user-sub" {
		t.Errorf("expected sub 'user-sub', got %v", claimsVerified["sub"])
	}

	if claimsVerified["tid"] != "https://auth.example.com" {
		t.Errorf("expected tid 'https://auth.example.com', got %v", claimsVerified["tid"])
	}
}

func TestJWTSigner_SignAccessToken_UnsupportedAlg(t *testing.T) {
	signer := newTestSigner(t)
	ctx := context.Background()

	claims := model.TokenClaims{}

	_, err := signer.SignAccessToken(ctx, claims, "HS256")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm, got nil")
	}
}

func TestJWTSigner_SignIDToken_Success(t *testing.T) {
	signer := newTestSigner(t)
	ctx := context.Background()

	claims := model.OIDCTokenClaims{
		TokenID:   "id-token-123",
		Issuer:    "https://auth.example.com",
		Subject:   "user-sub",
		Audience:  "client-id",
		TenantID:  "https://auth.example.com",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		AuthTime:  time.Now().UTC(),
		Nonce:     "nonce-value",
	}

	tokenStr, err := signer.SignIDToken(ctx, claims, model.AlgRS256)
	if err != nil {
		t.Fatalf("unexpected error signing ID token: %v", err)
	}

	if tokenStr == "" {
		t.Fatal("expected non-empty signed token string")
	}

	claimsVerified, err := signer.VerifyToken(tokenStr)
	if err != nil {
		t.Fatalf("failed to verify RS256 ID token: %v", err)
	}
	if claimsVerified["tid"] != "https://auth.example.com" {
		t.Errorf("expected tid 'https://auth.example.com', got %v", claimsVerified["tid"])
	}
}

func TestJWTSigner_SignIDToken_ES256_Success(t *testing.T) {
	signer := newTestSigner(t)
	ctx := context.Background()

	claims := model.OIDCTokenClaims{
		TokenID:   "id-token-es256",
		Issuer:    "https://auth.example.com",
		Subject:   "user-sub-es",
		Audience:  "client-id",
		TenantID:  "https://auth.example.com",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		AuthTime:  time.Now().UTC(),
		Nonce:     "nonce-value",
	}

	tokenStr, err := signer.SignIDToken(ctx, claims, model.AlgES256)
	if err != nil {
		t.Fatalf("unexpected error signing ID token ES256: %v", err)
	}

	claimsVerified, err := signer.VerifyToken(tokenStr)
	if err != nil {
		t.Fatalf("failed to verify ES256 ID Token: %v", err)
	}

	if claimsVerified["sub"] != "user-sub-es" {
		t.Errorf("expected sub 'user-sub-es', got %v", claimsVerified["sub"])
	}

	if claimsVerified["tid"] != "https://auth.example.com" {
		t.Errorf("expected tid 'https://auth.example.com', got %v", claimsVerified["tid"])
	}
}

func TestJWTSigner_SignIDToken_UnsupportedAlg(t *testing.T) {
	signer := newTestSigner(t)
	ctx := context.Background()

	claims := model.OIDCTokenClaims{}

	_, err := signer.SignIDToken(ctx, claims, "HS256")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm, got nil")
	}
}

func TestJWTSigner_MarshalJWKSet(t *testing.T) {
	signer := newTestSigner(t)
	ctx := context.Background()

	domain := "test-tenant.com"
	scheme := "https"
	jsonStr, err := signer.MarshalJWKSet(ctx, domain, scheme)
	if err != nil {
		t.Fatalf("unexpected error marshaling JWK set: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &payload); err != nil {
		t.Fatalf("failed to unmarshal JSON JWKS payload: %v", err)
	}

	keys, ok := payload["keys"].([]any)
	if !ok || len(keys) != 2 {
		t.Fatalf("expected 2 keys in JWKS (RSA + ECDSA), got %v", len(keys))
	}

	keyObj1, ok1 := keys[0].(map[string]any)
	keyObj2, ok2 := keys[1].(map[string]any)
	if !ok1 || !ok2 {
		t.Fatalf("JWK is not a JSON object")
	}

	kty1 := keyObj1["kty"]
	kty2 := keyObj2["kty"]
	if (kty1 == "RSA" && kty2 == "EC") || (kty1 == "EC" && kty2 == "RSA") {
		// Valid combination of generated keys
	} else {
		t.Errorf("unexpected key combination: %v, %v", kty1, kty2)
	}
}

func TestJWTSigner_SignLogoutToken_Success(t *testing.T) {
	signer := newTestSigner(t)
	ctx := context.Background()

	claims := model.LogoutTokenClaims{
		TokenID:  "logout-token-123",
		Issuer:   "https://auth.example.com",
		Subject:  "user-sub",
		Audience: "client-id",
		IssuedAt: time.Now().UTC(),
	}

	tokenStr, err := signer.SignLogoutToken(ctx, claims, model.AlgRS256)
	if err != nil {
		t.Fatalf("unexpected error signing logout token: %v", err)
	}

	if tokenStr == "" {
		t.Fatal("expected non-empty signed logout token string")
	}
}

func TestJWTSigner_SignLogoutToken_ES256_Success(t *testing.T) {
	signer := newTestSigner(t)
	ctx := context.Background()

	claims := model.LogoutTokenClaims{
		TokenID:  "logout-token-es",
		Issuer:   "https://auth.example.com",
		Subject:  "user-sub-es",
		Audience: "client-id",
		IssuedAt: time.Now().UTC(),
	}

	tokenStr, err := signer.SignLogoutToken(ctx, claims, model.AlgES256)
	if err != nil {
		t.Fatalf("unexpected error signing logout token ES256: %v", err)
	}

	claimsVerified, err := signer.VerifyToken(tokenStr)
	if err != nil {
		t.Fatalf("failed to verify ES256 logout token: %v", err)
	}

	if claimsVerified["sub"] != "user-sub-es" {
		t.Errorf("expected sub 'user-sub-es', got %v", claimsVerified["sub"])
	}
}

func TestJWTSigner_SignLogoutToken_UnsupportedAlg(t *testing.T) {
	signer := newTestSigner(t)
	ctx := context.Background()

	claims := model.LogoutTokenClaims{}

	_, err := signer.SignLogoutToken(ctx, claims, "HS256")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm, got nil")
	}
}

func TestJWTSigner_VerifyToken_Success(t *testing.T) {
	signer := newTestSigner(t)
	ctx := context.Background()

	claims := model.TokenClaims{
		TokenID:   "token-123",
		Issuer:    "https://auth.example.com",
		TenantID:  "https://auth.example.com",
		Subject:   "user-sub",
		ClientID:  "client-id",
		Scopes:    []string{"openid"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}

	tokenStr, err := signer.SignAccessToken(ctx, claims, model.AlgRS256)
	if err != nil {
		t.Fatalf("failed to sign access token: %v", err)
	}

	verifiedClaims, err := signer.VerifyToken(tokenStr)
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}

	if verifiedClaims["sub"] != "user-sub" {
		t.Errorf("expected sub 'user-sub', got %v", verifiedClaims["sub"])
	}
}

func TestJWTSigner_VerifyToken_Failures(t *testing.T) {
	signer := newTestSigner(t)
	ctx := context.Background()

	// 1. Mismatched method: HMAC token
	tokenHMAC := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "test"})
	tokenStrHMAC, _ := tokenHMAC.SignedString([]byte("secret"))
	_, err := signer.VerifyToken(tokenStrHMAC)
	if err == nil {
		t.Error("expected error for HMAC signing method, got nil")
	}

	// 2. Missing kid header
	// Sign using key directly to bypass kid injection
	keyring, err := signer.getOrCreateKeyring(ctx, "auth.example.com", "https://auth.example.com")
	if err != nil {
		t.Fatalf("failed to get keyring: %v", err)
	}
	privateKey := keyring.Keys[keyring.ActiveKids[model.AlgRS256]]
	tokenNoKid := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "user-sub"})
	tokenStrNoKid, _ := tokenNoKid.SignedString(privateKey)
	_, err = signer.VerifyToken(tokenStrNoKid)
	if err == nil || !strings.Contains(err.Error(), "missing kid") {
		t.Errorf("expected missing kid error, got: %v", err)
	}

	// 3. Expired token
	claimsExpired := model.TokenClaims{
		TokenID:   "token-expired",
		Issuer:    "https://auth.example.com",
		TenantID:  "https://auth.example.com",
		Subject:   "user-sub",
		ClientID:  "client-id",
		IssuedAt:  time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
	}
	tokenStrExpired, err := signer.SignAccessToken(ctx, claimsExpired, model.AlgRS256)
	if err != nil {
		t.Fatalf("failed to sign expired token: %v", err)
	}
	_, err = signer.VerifyToken(tokenStrExpired)
	if err == nil || !strings.Contains(err.Error(), "token is expired") {
		t.Errorf("expected token is expired error, got: %v", err)
	}

	// 4. Unknown key / Key not found for kid
	signerEmpty := newTestSigner(t)
	tokenWithKid := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "user-sub"})
	tokenWithKid.Header["kid"] = "unknown-kid"
	tokenStrWithKid, _ := tokenWithKid.SignedString(privateKey)
	_, err = signerEmpty.VerifyToken(tokenStrWithKid)
	if err == nil || !strings.Contains(err.Error(), "key not found") {
		t.Errorf("expected key not found error, got: %v", err)
	}
}

func TestJWTSigner_IssuerEmpty(t *testing.T) {
	signer := newTestSigner(t)
	ctx := context.Background()

	// 1. Assert failure for SignAccessToken when Issuer is missing
	claimsAccess := model.TokenClaims{
		TokenID:   "token-fallback",
		TenantID:  "https://auth.example.com",
		Subject:   "user-sub",
		ClientID:  "client-id",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	_, err := signer.SignAccessToken(ctx, claimsAccess, model.AlgRS256)
	if err == nil {
		t.Fatal("expected error when signing access token with an empty issuer, got nil")
	}

	// 2. Assert failure for SignIDToken when Issuer is missing
	claimsID := model.OIDCTokenClaims{
		TokenID:   "id-fallback",
		TenantID:  "https://auth.example.com",
		Subject:   "user-sub",
		Audience:  "client-id",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		AuthTime:  time.Now().UTC(),
	}
	_, err = signer.SignIDToken(ctx, claimsID, model.AlgRS256)
	if err == nil {
		t.Fatal("expected error when signing ID token with an empty issuer, got nil")
	}

	// 3. Assert failure for SignLogoutToken when Issuer is missing
	claimsLogout := model.LogoutTokenClaims{
		TokenID:  "logout-fallback",
		Subject:  "https://auth.example.com",
		Audience: "client-id",
		IssuedAt: time.Now().UTC(),
	}
	_, err = signer.SignLogoutToken(ctx, claimsLogout, model.AlgRS256)
	if err == nil {
		t.Fatal("expected error when signing logout token with an empty issuer, got nil")
	}
}

func getKidByKty(jwks []map[string]any, kty string) string {
	for _, k := range jwks {
		if k["kty"] == kty {
			return k["kid"].(string)
		}
	}
	return ""
}

func TestJWTSigner_RotateKeys(t *testing.T) {
	ctx := context.Background()
	storageRepo := newMockStorage()
	domain := "test-tenant.com"
	scheme := "https"

	// A. Initial setup phase with the baseline clock timestamp value
	currentTime := time.Now().UTC()
	initialClock := portmock.NewMockClock(currentTime)

	signer1, _ := NewJWTSigner(storageRepo, initialClock, "01234567890123456789012345678901")

	// Initialize the original keyset state inside memory map cache
	jwks, err := signer1.JWKSForTenant(ctx, domain, scheme)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(jwks) != 2 {
		t.Fatalf("expected 2 keys in JWKS, got %d", len(jwks))
	}

	initialRSKid := getKidByKty(jwks, "RSA")

	// B. Advanced rotation phase using a new clock instance set 5 minutes ahead
	// This guarantees that s.clock.Now().UnixNano() calculates a distinct suffix!
	advancedTime := currentTime.Add(5 * time.Minute)
	rotatedClock := portmock.NewMockClock(advancedTime)

	// Build a fresh signer container sharing the exact same storage memory context
	signer2, _ := NewJWTSigner(storageRepo, rotatedClock, "01234567890123456789012345678901")

	// Prime the signer2 memory map cache with the initial keyring footprint
	_, _ = signer2.JWKSForTenant(ctx, domain, scheme)

	// Execute key rotation under the advanced timeline state configuration
	if err := signer2.RotateKeys(ctx, domain); err != nil {
		t.Fatalf("unexpected key rotation error: %v", err)
	}

	// Verify JWKS transitions cleanly
	jwksRotated, err := signer2.JWKSForTenant(ctx, domain, scheme)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(jwksRotated) != 4 {
		t.Fatalf("expected 4 keys in JWKS after rotation, got %d", len(jwksRotated))
	}

	activeRSKid := getKidByKty(jwksRotated, "RSA")
	if activeRSKid == initialRSKid {
		t.Fatal("expected Active RS256 Kid to change after key rotation")
	}
}

func TestJWTSigner_RotateKeys_NoDowntime(t *testing.T) {
	ctx := context.Background()
	storageRepo := newMockStorage()
	domain := "test-tenant.com"
	issuer := "https://" + domain

	// 1. PHASE 1: Sign token with the initial keyset baseline
	currentTime := time.Now().UTC()
	initialClock := portmock.NewMockClock(currentTime)
	signer1, _ := NewJWTSigner(storageRepo, initialClock, "01234567890123456789012345678901")

	claims1 := model.TokenClaims{
		TokenID:   "token-1",
		Issuer:    issuer,
		Subject:   "user-1",
		ClientID:  "client-1",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	tokenStr1, err := signer1.SignAccessToken(ctx, claims1, model.AlgRS256)
	if err != nil {
		t.Fatalf("unexpected signing error: %v", err)
	}

	// 2. PHASE 2: Rotate keys using a fresh signer with an advanced clock (5 minutes ahead)
	// This forces UnixNano() to generate a completely distinct, unique suffix string!
	advancedTime := currentTime.Add(5 * time.Minute)
	rotatedClock := portmock.NewMockClock(advancedTime)
	signer2, _ := NewJWTSigner(storageRepo, rotatedClock, "01234567890123456789012345678901")

	// Prime signer2's memory map cache with the initial keyring data footprint from the DB
	_, _ = signer2.JWKSForTenant(ctx, domain, "https")

	// Execute key rotation smoothly
	if err := signer2.RotateKeys(ctx, domain); err != nil {
		t.Fatalf("unexpected key rotation error: %v", err)
	}

	// 3. PHASE 3: Sign a second token using the newly rotated keyset
	claims2 := model.TokenClaims{
		TokenID:   "token-2",
		Issuer:    issuer,
		Subject:   "user-1",
		ClientID:  "client-1",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	tokenStr2, err := signer2.SignAccessToken(ctx, claims2, model.AlgRS256)
	if err != nil {
		t.Fatalf("unexpected signing error: %v", err)
	}

	// 4. PHASE 4: Verify BOTH tokens are still fully verifiable on the active cluster
	// Verification checks use signer2 because its cache contains all 4 keys (2 old + 2 new)
	claimsVerified1, err := signer2.VerifyToken(tokenStr1)
	if err != nil {
		t.Fatalf("failed to verify token signed with initial key: %v", err)
	}
	if claimsVerified1["jti"] != "token-1" {
		t.Errorf("expected token-1, got %v", claimsVerified1["jti"])
	}

	claimsVerified2, err := signer2.VerifyToken(tokenStr2)
	if err != nil {
		t.Fatalf("failed to verify token signed with rotated key: %v", err)
	}
	if claimsVerified2["jti"] != "token-2" {
		t.Errorf("expected token-2, got %v", claimsVerified2["jti"])
	}
}

type mockStorage struct {
	deks    map[uuid.UUID][]byte
	nonces  map[uuid.UUID][]byte
	keys    map[uuid.UUID][]model.SigningKey
	tenants map[string]*model.Tenant
}

func newMockStorage() *mockStorage {
	tID := uuid.New()
	return &mockStorage{
		deks:   make(map[uuid.UUID][]byte),
		nonces: make(map[uuid.UUID][]byte),
		keys:   make(map[uuid.UUID][]model.SigningKey),
		tenants: map[string]*model.Tenant{
			"auth.example.com": {
				ID:       tID,
				Domain:   "auth.example.com",
				Scheme:   "https",
				IsActive: true,
			},
			"test-tenant.com": {
				ID:       tID,
				Domain:   "test-tenant.com",
				Scheme:   "https",
				IsActive: true,
			},
			"default": {
				ID:       tID,
				Domain:   "default",
				Scheme:   "https",
				IsActive: true,
			},
		},
	}
}

func (m *mockStorage) GetTenantDEK(ctx context.Context, tenantUUID uuid.UUID) ([]byte, []byte, error) {
	return m.deks[tenantUUID], m.nonces[tenantUUID], nil
}

func (m *mockStorage) InsertTenantDEK(ctx context.Context, tenantUUID uuid.UUID, encryptedDEK, nonce []byte) error {
	m.deks[tenantUUID] = encryptedDEK
	m.nonces[tenantUUID] = nonce
	return nil
}

func (m *mockStorage) GetActiveSigningKeys(ctx context.Context, tenantUUID uuid.UUID) ([]model.SigningKey, error) {
	return m.keys[tenantUUID], nil
}

func (m *mockStorage) GetActiveVerificationKeys(ctx context.Context, tenantUUID uuid.UUID) ([]model.SigningKey, error) {
	return m.keys[tenantUUID], nil
}

func (m *mockStorage) InsertSigningKey(ctx context.Context, tenantUUID uuid.UUID, key model.SigningKey, encryptedPrivateKey, nonce []byte) (string, error) {
	if key.Kid == "" {
		key.Kid = uuid.New().String()
	}
	key.RawEncryptedPrivateKey = encryptedPrivateKey
	key.CryptoNonce = nonce
	// Append the new active signing key
	m.keys[tenantUUID] = append(m.keys[tenantUUID], key)
	return key.Kid, nil
}

func (m *mockStorage) RotateSigningKeys(ctx context.Context, tenantUUID uuid.UUID) error {
	// Clear old keys out of the active slice or mark them verification-only
	// to allow the newly inserted keys to float to the top
	m.keys[tenantUUID] = nil
	return nil
}

func (m *mockStorage) ResolveTenantByDomain(ctx context.Context, domain string) (*model.Tenant, error) {
	t, ok := m.tenants[domain]
	if !ok {
		for _, v := range m.tenants {
			return v, nil
		}
	}
	return t, nil
}

func newTestSigner(t *testing.T) *JWTSigner {
	// A standard dynamic evaluation functions perfectly for your basic token tests
	staticClock := portmock.NewMockClock(time.Now().UTC())

	signer, err := NewJWTSigner(newMockStorage(), staticClock, "01234567890123456789012345678901")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	return signer
}
