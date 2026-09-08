package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwtcrypto "sprezz-identity/internal/adapters/out/crypto"
	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestHttpAdapter_OpenIDConfiguration_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _ := buildTestAdapter(ctrl)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	scopes, ok := resp["scopes_supported"].([]any)
	if !ok {
		t.Fatal("scopes_supported is missing or not a list")
	}

	if len(scopes) != 2 || scopes[0] != "openid" || scopes[1] != "custom-scope" {
		t.Fatalf("unexpected scopes in configuration: %v", scopes)
	}

	acrValues, ok := resp["acr_values_supported"].([]any)
	if !ok {
		t.Fatal("acr_values_supported is missing or not a list")
	}

	if len(acrValues) != 2 || acrValues[0] != "acr:a" || acrValues[1] != "acr:b" {
		t.Fatalf("unexpected acr values order (must be sorted): %v", acrValues)
	}

	if resp["end_session_endpoint"] != "https://test.com/oauth/logout" {
		t.Fatalf("unexpected end_session_endpoint: %v", resp["end_session_endpoint"])
	}

	// Verify OAuth 2.0 Auth Server endpoint
	req2 := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	req2.Host = "test.com"
	rec2 := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec2.Code)
	}

	var resp2 map[string]any
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	oidcFields := []string{
		"userinfo_endpoint",
		"end_session_endpoint",
		"frontchannel_logout_supported",
		"frontchannel_logout_session_supported",
		"claims_supported",
		"idtoken_signing_alg_values_supported",
		"subject_types_supported",
	}

	for _, f := range oidcFields {
		if _, exists := resp2[f]; exists {
			t.Fatalf("expected field %q to be absent in OAuth 2.0 metadata, but it exists", f)
		}
	}

	if resp2["issuer"] != "https://test.com" || resp2["authorization_endpoint"] != "https://test.com/oauth/authorize" {
		t.Fatalf("unexpected OAuth 2.0 metadata endpoint values: %v", resp2)
	}
}

func TestHttpAdapter_JWKS_CacheControl(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	clock := portmock.NewMockClock(time.Now())

	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)

	tenantID := uuid.New()
	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return &model.Tenant{
			ID:       tenantID,
			Name:     "test-tenant",
			Domain:   "test.com",
			Scheme:   "https",
			IsActive: true,
		}, nil
	})

	auth.ProcessJWKSetRetrievalMock.Set(func(ctx context.Context, tID uuid.UUID, host string, scheme string) (map[string]any, error) {
		if tID != tenantID {
			t.Errorf("expected tenant ID %s, got %s", tenantID, tID)
		}
		return map[string]any{
			"keys": []any{},
		}, nil
	})

	mockStore := &handlerMockStorage{
		StorageMock: storage,
		deks:        make(map[uuid.UUID][]byte),
		nonces:      make(map[uuid.UUID][]byte),
		keys:        make(map[uuid.UUID][]model.SigningKey),
	}

	crypto, err := jwtcrypto.NewJWTSigner(mockStore, clock, http.DefaultClient, "01234567890123456789012345678901", "admin-domain.com", "unittest")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	adapter := NewHttpAdapter(tuc, auth, fuc, nil, suc, upuc, uruc, portmock.NewLocalAuthUseCaseMock(ctrl), nil, nil, nil, storage, crypto, "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Fatalf("expected Content-Type to contain application/json, got %q", contentType)
	}

	cacheControl := rec.Header().Get("Cache-Control")
	expectedCacheControl := "public, max-age=600, stale-while-revalidate=86400"
	if cacheControl != expectedCacheControl {
		t.Fatalf("expected Cache-Control %q, got %q", expectedCacheControl, cacheControl)
	}
}
