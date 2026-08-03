package http

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
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

func TestHttpAdapter_DPoPProofValidation_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	privateKey, jwkMap := generateDPoPTestKey(t)
	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

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

	jkt, err := adapter.validateDPoPProof(req)
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

	privateKey, jwkMap := generateDPoPTestKey(t)
	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	jti := "jti-2"
	proof := mintDPoPProofForTest(t, privateKey, jwkMap, "POST", "https://test.com/oauth/token", jti, time.Now().Add(-5*time.Minute))
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.Host = "test.com"
	req.Header.Set("DPoP", proof)

	_, err := adapter.validateDPoPProof(req)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expired proof error, got: %v", err)
	}
}

func TestHttpAdapter_DPoPProofValidation_Replay(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	privateKey, jwkMap := generateDPoPTestKey(t)
	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

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

	_, err := adapter.validateDPoPProof(req)
	if err == nil || !strings.Contains(err.Error(), "already been used") {
		t.Errorf("expected already used error, got: %v", err)
	}
}

func TestHttpAdapter_DPoPProofValidation_HtmMismatch(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	privateKey, jwkMap := generateDPoPTestKey(t)
	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	jti := "jti-4"
	proof := mintDPoPProofForTest(t, privateKey, jwkMap, "GET", "https://test.com/oauth/token", jti, time.Now())
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.Host = "test.com"
	req.Header.Set("DPoP", proof)

	_, err := adapter.validateDPoPProof(req)
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
	crypto.SignAccessTokenMock.Set(func(claims model.TokenClaims, alg model.SignatureAlgorithm) (string, error) {
		return "mock-access-token", nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

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

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

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

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewBufferString("grant_type=invalid_grant"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}
