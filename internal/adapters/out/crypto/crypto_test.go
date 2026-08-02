package crypto

import (
	"encoding/json"
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
