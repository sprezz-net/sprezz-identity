package http

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sprezz-identity/internal/adapters/out/clock"
	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func generateDPoPTestKey(t *testing.T) (*rsa.PrivateKey, map[string]any) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	nStr := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
	eBytes := big.NewInt(int64(privateKey.E)).Bytes()
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)
	jwkMap := map[string]any{
		"kty": "RSA",
		"n":   nStr,
		"e":   eStr,
	}
	return privateKey, jwkMap
}

func mintDPoPProofForTest(t *testing.T, privateKey *rsa.PrivateKey, jwkMap map[string]any, method, urlStr, jti string, iat time.Time) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"htm": method,
		"htu": urlStr,
		"jti": jti,
		"iat": iat.Unix(),
	})
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwkMap
	token.Header["alg"] = "RS256"

	str, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return str
}

func generateDPoPTestKeyEC(t *testing.T) (*ecdsa.PrivateKey, map[string]any) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	xStr := base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes())
	yStr := base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes())
	jwkMap := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   xStr,
		"y":   yStr,
	}
	return privateKey, jwkMap
}

func mintDPoPProofForTestEC(t *testing.T, privateKey *ecdsa.PrivateKey, jwkMap map[string]any, method, urlStr, jti string, iat time.Time) string {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"htm": method,
		"htu": urlStr,
		"jti": jti,
		"iat": iat.Unix(),
	})
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwkMap
	token.Header["alg"] = "ES256"

	str, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return str
}

func generateDPoPTestKeyOKP(t *testing.T) (ed25519.PrivateKey, map[string]any) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	xStr := base64.RawURLEncoding.EncodeToString(pub)
	jwkMap := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   xStr,
	}
	return priv, jwkMap
}

func mintDPoPProofForTestOKP(t *testing.T, privateKey ed25519.PrivateKey, jwkMap map[string]any, method, urlStr, jti string, iat time.Time) string {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"htm": method,
		"htu": urlStr,
		"jti": jti,
		"iat": iat.Unix(),
	})
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwkMap
	token.Header["alg"] = "EdDSA"

	str, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return str
}

func TestHttpAdapter_DPoPProofValidation_Success_OKP(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{
		ID:     tenantID,
		Domain: "test.com",
		Scheme: "https",
	}

	privateKey, jwkMap := generateDPoPTestKeyOKP(t)
	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	jti := "jti-okp-1"
	proof := mintDPoPProofForTestOKP(t, privateKey, jwkMap, "POST", "https://test.com/oauth/token", jti, time.Now())
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.Host = "test.com"
	req.Header.Set("DPoP", proof)

	storage.IsDPoPProofUsedMock.Set(func(ctx context.Context, gotJti string) (bool, error) {
		if gotJti != jti {
			t.Errorf("expected checked jti %s, got %s", jti, gotJti)
		}
		return false, nil
	})
	storage.SaveDPoPProofMock.Set(func(ctx context.Context, gotJti string, exp time.Time) error {
		if gotJti != jti {
			t.Errorf("expected jti %s, got %s", jti, gotJti)
		}
		return nil
	})

	jkt, err := adapter.validateDPoPProof(req, tenant)
	if err != nil {
		t.Fatalf("expected successful EdDSA/OKP validation, got: %v", err)
	}
	if jkt == "" {
		t.Error("expected non-empty JKT thumbprint for OKP")
	}
}

func TestHttpAdapter_DPoPProofValidation_Success_EC(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{
		ID:     tenantID,
		Domain: "test.com",
		Scheme: "https",
	}

	privateKey, jwkMap := generateDPoPTestKeyEC(t)
	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	jti := "jti-ec-1"
	proof := mintDPoPProofForTestEC(t, privateKey, jwkMap, "POST", "https://test.com/oauth/token", jti, time.Now())
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.Host = "test.com"
	req.Header.Set("DPoP", proof)

	storage.IsDPoPProofUsedMock.Set(func(ctx context.Context, gotJti string) (bool, error) {
		if gotJti != jti {
			t.Errorf("expected checked jti %s, got %s", jti, gotJti)
		}
		return false, nil
	})
	storage.SaveDPoPProofMock.Set(func(ctx context.Context, gotJti string, exp time.Time) error {
		if gotJti != jti {
			t.Errorf("expected jti %s, got %s", jti, gotJti)
		}
		return nil
	})

	jkt, err := adapter.validateDPoPProof(req, tenant)
	if err != nil {
		t.Fatalf("expected successful EC validation, got: %v", err)
	}
	if jkt == "" {
		t.Error("expected non-empty JKT thumbprint for EC")
	}
}

func TestHttpAdapter_DPoPProofValidation_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{
		ID:     tenantID,
		Domain: "test.com",
		Scheme: "https",
	}

	privateKey, jwkMap := generateDPoPTestKey(t)
	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	jti := "jti-1"
	proof := mintDPoPProofForTest(t, privateKey, jwkMap, "POST", "https://test.com/oauth/token", jti, time.Now())
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.Host = "test.com"
	req.Header.Set("DPoP", proof)

	storage.IsDPoPProofUsedMock.Set(func(ctx context.Context, gotJti string) (bool, error) {
		if gotJti != jti {
			t.Errorf("expected checked jti %s, got %s", jti, gotJti)
		}
		return false, nil
	})
	storage.SaveDPoPProofMock.Set(func(ctx context.Context, gotJti string, exp time.Time) error {
		if gotJti != jti {
			t.Errorf("expected jti %s, got %s", jti, gotJti)
		}
		return nil
	})

	jkt, err := adapter.validateDPoPProof(req, tenant)
	if err != nil {
		t.Fatalf("expected successful validation, got: %v", err)
	}
	if jkt == "" {
		t.Error("expected non-empty JKT thumbprint")
	}
}

func TestHttpAdapter_DPoPProofValidation_Expired(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{
		ID:     tenantID,
		Domain: "test.com",
		Scheme: "https",
	}

	privateKey, jwkMap := generateDPoPTestKey(t)
	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	jti := "jti-2"
	proof := mintDPoPProofForTest(t, privateKey, jwkMap, "POST", "https://test.com/oauth/token", jti, time.Now().Add(-5*time.Minute))
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.Host = "test.com"
	req.Header.Set("DPoP", proof)

	_, err := adapter.validateDPoPProof(req, tenant)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expired proof error, got: %v", err)
	}
}

func TestHttpAdapter_DPoPProofValidation_Replay(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{
		ID:     tenantID,
		Domain: "test.com",
		Scheme: "https",
	}

	privateKey, jwkMap := generateDPoPTestKey(t)
	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	jti := "jti-3"
	proof := mintDPoPProofForTest(t, privateKey, jwkMap, "POST", "https://test.com/oauth/token", jti, time.Now())
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.Host = "test.com"
	req.Header.Set("DPoP", proof)

	storage.IsDPoPProofUsedMock.Set(func(ctx context.Context, gotJti string) (bool, error) {
		if gotJti != jti {
			t.Errorf("expected checked jti %s, got %s", jti, gotJti)
		}
		return true, nil
	})

	_, err := adapter.validateDPoPProof(req, tenant)
	if err == nil || !strings.Contains(err.Error(), "already been used") {
		t.Errorf("expected already used error, got: %v", err)
	}
}

func TestHttpAdapter_DPoPProofValidation_HtmMismatch(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{
		ID:     tenantID,
		Domain: "test.com",
		Scheme: "https",
	}

	privateKey, jwkMap := generateDPoPTestKey(t)
	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	jti := "jti-4"
	proof := mintDPoPProofForTest(t, privateKey, jwkMap, "GET", "https://test.com/oauth/token", jti, time.Now())
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.Host = "test.com"
	req.Header.Set("DPoP", proof)

	_, err := adapter.validateDPoPProof(req, tenant)
	if err == nil || !strings.Contains(err.Error(), "htm mismatch") {
		t.Errorf("expected htm mismatch error, got: %v", err)
	}
}

func TestHttpAdapter_Token_ClientCredentials_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", Scheme: "https"}
	secret := "supersecret"
	client := &model.ClientApplication{
		ID:                  uuid.NewString(),
		TenantID:            tenantID,
		ClientID:            "cc-client",
		ClientSecret:        &secret,
		DefaultScopes:       []string{"openid"},
		AccessTokenLifetime: time.Hour,
		Algorithm:           model.AlgRS256,
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})
	crypto.SignAccessTokenMock.Set(func(ctx context.Context, claims model.TokenClaims, alg model.SignatureAlgorithm) (string, error) {
		return "mock-access-token", nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewBufferString("grant_type=client_credentials&client_id=cc-client&client_secret=supersecret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "mock-access-token") {
		t.Fatalf("expected response to contain access token")
	}
}

func TestHttpAdapter_Token_AuthCodeExchange_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	auth.ExchangeCodeForTokensMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string, code string, codeVerifier string, dpopJKT string) (*model.TokenSetResponse, error) {
		return &model.TokenSetResponse{
			AccessToken:  "at-123",
			IDToken:      "id-123",
			RefreshToken: "rt-123",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewBufferString("grant_type=authorization_code&client_id=ac-client&code=code123&code_verifier=verifier123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "at-123") || !strings.Contains(rec.Body.String(), "id-123") {
		t.Fatalf("response missing expected tokens: %s", rec.Body.String())
	}
}

func TestHttpAdapter_Token_InvalidGrantType(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewBufferString("grant_type=invalid_grant"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestHttpAdapter_Token_ClientCredentials_BasicAuth(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}
	secret := "supersecret"
	client := &model.ClientApplication{
		ID:                  uuid.NewString(),
		TenantID:            tenantID,
		ClientID:            "cc-client",
		ClientSecret:        &secret,
		DefaultScopes:       []string{"openid"},
		AccessTokenLifetime: time.Hour,
		Algorithm:           model.AlgRS256,
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})
	crypto.SignAccessTokenMock.Set(func(ctx context.Context, claims model.TokenClaims, alg model.SignatureAlgorithm) (string, error) {
		return "mock-access-token-basic", nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewBufferString("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("cc-client", "supersecret")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "mock-access-token-basic") {
		t.Fatalf("expected response to contain access token from basic auth")
	}
}

func TestHttpAdapter_Introspect_BasicAuth(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}
	secret := "clientsecret"
	client := &model.ClientApplication{
		ID:           uuid.NewString(),
		TenantID:     tenantID,
		ClientID:     "test-client",
		ClientSecret: &secret,
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})
	auth.IntrospectTokenMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string, token string) (*model.IntrospectionResponse, error) {
		return &model.IntrospectionResponse{
			Active:   true,
			ClientID: clientID,
			Subject:  "user-1",
		}, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", bytes.NewBufferString("token=some-token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("test-client", "clientsecret")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}

func TestHttpAdapter_Token_TokenExchange_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}
	client := &model.ClientApplication{
		ID:         uuid.NewString(),
		TenantID:   tenantID,
		ClientID:   "public-client",
		ClientType: model.ClientTypePublic,
		Algorithm:  model.AlgRS256,
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})
	auth.ExchangeExternalTokenMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string, subjectToken string, subjectTokenType string, dpopJKT string) (*model.TokenSetResponse, error) {
		if subjectToken != "some-ext-token-123" {
			t.Errorf("expected subjectToken 'some-ext-token-123', got %s", subjectToken)
		}
		if subjectTokenType != "urn:ietf:params:oauth:token-type:jwt" {
			t.Errorf("expected subjectTokenType 'urn:ietf:params:oauth:token-type:jwt', got %s", subjectTokenType)
		}
		return &model.TokenSetResponse{
			AccessToken: "native-token-abc",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewBufferString("grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=public-client&subject_token=some-ext-token-123&subject_token_type=urn:ietf:params:oauth:token-type:jwt"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	if resp["access_token"] != "native-token-abc" {
		t.Errorf("expected access_token 'native-token-abc', got %v", resp["access_token"])
	}
}

func TestHttpAdapter_Introspect_Post(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}
	secret := "clientsecret"
	client := &model.ClientApplication{
		ID:           uuid.NewString(),
		TenantID:     tenantID,
		ClientID:     "test-client",
		ClientSecret: &secret,
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})
	auth.IntrospectTokenMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string, token string) (*model.IntrospectionResponse, error) {
		return &model.IntrospectionResponse{
			Active:   true,
			ClientID: clientID,
			Subject:  "user-1",
		}, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", bytes.NewBufferString("client_id=test-client&client_secret=clientsecret&token=some-token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}

func TestHttpAdapter_Introspect_None_Unauthorized(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", bytes.NewBufferString("token=some-token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestHttpAdapter_Token_RefreshToken_None_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}
	client := &model.ClientApplication{
		ID:         uuid.NewString(),
		TenantID:   tenantID,
		ClientID:   "public-client",
		ClientType: model.ClientTypePublic,
		Algorithm:  model.AlgRS256,
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})
	auth.ExchangeRefreshTokenForTokensMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string, refreshTokenStr string, dpopJKT string) (*model.TokenSetResponse, error) {
		return &model.TokenSetResponse{
			AccessToken:  "new-at-123",
			RefreshToken: "new-rt-123",
			TokenType:    "Bearer",
		}, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewBufferString("grant_type=refresh_token&client_id=public-client&refresh_token=rt-123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}
