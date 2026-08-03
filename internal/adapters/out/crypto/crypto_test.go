package crypto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTSigner_SignAccessToken_Success(t *testing.T) {
	signer := NewJWTSigner()

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

	tokenStr, err := signer.SignAccessToken(claims, model.AlgRS256)
	if err != nil {
		t.Fatalf("unexpected error signing access token: %v", err)
	}

	if tokenStr == "" {
		t.Fatal("expected non-empty signed token string")
	}

	// Verify JWT parsing using the generated public key in JWKS
	jwkSet, err := signer.JWKSForTenant("auth.example.com")
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
}

func TestJWTSigner_SignAccessToken_UnsupportedAlg(t *testing.T) {
	signer := NewJWTSigner()
	claims := model.TokenClaims{}

	_, err := signer.SignAccessToken(claims, "HS256")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm, got nil")
	}
}

func TestJWTSigner_SignIDToken_Success(t *testing.T) {
	signer := NewJWTSigner()

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

	tokenStr, err := signer.SignIDToken(claims, model.AlgRS256)
	if err != nil {
		t.Fatalf("unexpected error signing ID token: %v", err)
	}

	if tokenStr == "" {
		t.Fatal("expected non-empty signed token string")
	}
}

func TestJWTSigner_SignIDToken_UnsupportedAlg(t *testing.T) {
	signer := NewJWTSigner()
	claims := model.OIDCTokenClaims{}

	_, err := signer.SignIDToken(claims, "HS256")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm, got nil")
	}
}

func TestJWTSigner_MarshalJWKSet(t *testing.T) {
	signer := NewJWTSigner()

	domain := "test-tenant.com"
	jsonStr, err := signer.MarshalJWKSet(domain)
	if err != nil {
		t.Fatalf("unexpected error marshaling JWK set: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &payload); err != nil {
		t.Fatalf("failed to unmarshal JSON JWKS payload: %v", err)
	}

	keys, ok := payload["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatalf("JWKS JSON missing 'keys' or has empty keys list")
	}

	keyObj, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatalf("JWK is not a JSON object")
	}

	if keyObj["kty"] != "RSA" {
		t.Errorf("expected kty RSA, got %v", keyObj["kty"])
	}
}

func TestJWTSigner_SignLogoutToken_Success(t *testing.T) {
	signer := NewJWTSigner()

	claims := model.LogoutTokenClaims{
		TokenID:   "logout-token-123",
		Issuer:    "https://auth.example.com",
		Subject:   "user-sub",
		Audience:  "client-id",
		IssuedAt:  time.Now().UTC(),
	}

	tokenStr, err := signer.SignLogoutToken(claims, model.AlgRS256)
	if err != nil {
		t.Fatalf("unexpected error signing logout token: %v", err)
	}

	if tokenStr == "" {
		t.Fatal("expected non-empty signed logout token string")
	}
}

func TestJWTSigner_SignLogoutToken_UnsupportedAlg(t *testing.T) {
	signer := NewJWTSigner()
	claims := model.LogoutTokenClaims{}

	_, err := signer.SignLogoutToken(claims, "HS256")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm, got nil")
	}
}

func TestJWTSigner_VerifyToken_Success(t *testing.T) {
	signer := NewJWTSigner()

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

	tokenStr, err := signer.SignAccessToken(claims, model.AlgRS256)
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
	signer := NewJWTSigner()

	// 1. Mismatched method: HMAC token
	tokenHMAC := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "test"})
	tokenStrHMAC, _ := tokenHMAC.SignedString([]byte("secret"))
	_, err := signer.VerifyToken(tokenStrHMAC)
	if err == nil {
		t.Error("expected error for HMAC signing method, got nil")
	}

	// 2. Missing kid header
	// Sign using key directly to bypass kid injection
	privateKey, err := signer.getOrCreateKeyPair("auth.example.com", "https://auth.example.com", "kid-123")
	if err != nil {
		t.Fatalf("failed to get private key: %v", err)
	}
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
	tokenStrExpired, err := signer.SignAccessToken(claimsExpired, model.AlgRS256)
	if err != nil {
		t.Fatalf("failed to sign expired token: %v", err)
	}
	_, err = signer.VerifyToken(tokenStrExpired)
	if err == nil || !strings.Contains(err.Error(), "token is expired") {
		t.Errorf("expected token is expired error, got: %v", err)
	}

	// 4. Unknown key / Key not found for kid
	signerEmpty := NewJWTSigner()
	tokenWithKid := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "user-sub"})
	tokenWithKid.Header["kid"] = "unknown-kid"
	tokenStrWithKid, _ := tokenWithKid.SignedString(privateKey)
	_, err = signerEmpty.VerifyToken(tokenStrWithKid)
	if err == nil || !strings.Contains(err.Error(), "key not found") {
		t.Errorf("expected key not found error, got: %v", err)
	}
}

func TestJWTSigner_IssuerFallbackAndEmpty(t *testing.T) {
	signer := NewJWTSigner()

	// 1. SignAccessToken with empty Issuer
	claimsAccess := model.TokenClaims{
		TokenID:   "token-fallback",
		TenantID:  "https://auth.example.com",
		Subject:   "user-sub",
		ClientID:  "client-id",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	tokenStrAccess, err := signer.SignAccessToken(claimsAccess, model.AlgRS256)
	if err != nil {
		t.Fatalf("unexpected error signing access token with empty issuer: %v", err)
	}
	claimsVerifiedAccess, err := signer.VerifyToken(tokenStrAccess)
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}
	if claimsVerifiedAccess["iss"] != "https://auth.example.com" {
		t.Errorf("expected fallback issuer 'https://auth.example.com', got %v", claimsVerifiedAccess["iss"])
	}

	// 2. SignIDToken with empty Issuer
	claimsID := model.OIDCTokenClaims{
		TokenID:   "id-fallback",
		TenantID:  "https://auth.example.com",
		Subject:   "user-sub",
		Audience:  "client-id",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		AuthTime:  time.Now().UTC(),
	}
	tokenStrID, err := signer.SignIDToken(claimsID, model.AlgRS256)
	if err != nil {
		t.Fatalf("unexpected error signing ID token with empty issuer: %v", err)
	}
	claimsVerifiedID, err := signer.VerifyToken(tokenStrID)
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}
	if claimsVerifiedID["iss"] != "https://auth.example.com" {
		t.Errorf("expected fallback issuer 'https://auth.example.com', got %v", claimsVerifiedID["iss"])
	}

	// 3. SignLogoutToken with empty Issuer and empty Subject fallback
	claimsLogout := model.LogoutTokenClaims{
		TokenID:   "logout-fallback",
		Subject:   "https://auth.example.com",
		Audience:  "client-id",
		IssuedAt:  time.Now().UTC(),
	}
	tokenStrLogout, err := signer.SignLogoutToken(claimsLogout, model.AlgRS256)
	if err != nil {
		t.Fatalf("unexpected error signing logout token with empty issuer: %v", err)
	}
	claimsVerifiedLogout, err := signer.VerifyToken(tokenStrLogout)
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}
	if claimsVerifiedLogout["iss"] != "https://auth.example.com" {
		t.Errorf("expected fallback issuer 'https://auth.example.com', got %v", claimsVerifiedLogout["iss"])
	}
}
