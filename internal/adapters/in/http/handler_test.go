package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"sprezz-identity/internal/adapters/out/clock"
	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestHttpAdapter_OpenIDConfiguration_Success(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{
		ID:               tenantID,
		Name:             "test-tenant",
		Domain:           "test.com",
		IsActive:         true,
		PredefinedScopes: []string{"openid", "custom-scope"},
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

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

	if len(scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %v", scopes)
	}

	if scopes[0] != "openid" || scopes[1] != "custom-scope" {
		t.Fatalf("unexpected scopes in configuration: %v", scopes)
	}

	if resp["end_session_endpoint"] != "https://test.com/oauth/logout" {
		t.Fatalf("expected end_session_endpoint https://test.com/oauth/logout, got %v", resp["end_session_endpoint"])
	}

	if resp["frontchannel_logout_supported"] != true {
		t.Fatalf("expected frontchannel_logout_supported true, got %v", resp["frontchannel_logout_supported"])
	}

	if resp["frontchannel_logout_session_supported"] != true {
		t.Fatalf("expected frontchannel_logout_session_supported true, got %v", resp["frontchannel_logout_session_supported"])
	}
}

type registerTestCase struct {
	name                string
	predefinedScopes    []string
	allowedScopes       []string
	defaultScopes       []string
	predefinedAudiences []string
	allowedAudiences    []string
	expectedStatusCode  int
	expectedError       string
}

func TestHttpAdapter_Register_Validation(t *testing.T) {
	tests := []registerTestCase{
		{
			name:               "Valid scopes subset",
			predefinedScopes:   []string{"openid", "profile", "custom"},
			allowedScopes:      []string{"openid", "custom"},
			defaultScopes:      []string{"openid"},
			expectedStatusCode: http.StatusCreated,
		},
		{
			name:               "Invalid allowed scope",
			predefinedScopes:   []string{"openid", "profile"},
			allowedScopes:      []string{"openid", "illegal-scope"},
			defaultScopes:      []string{"openid"},
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      "requested allowed_scopes are not predefined/allowed by the tenant",
		},
		{
			name:               "Invalid default scope",
			predefinedScopes:   []string{"openid", "profile"},
			allowedScopes:      []string{"openid", "profile"},
			defaultScopes:      []string{"illegal-scope"},
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      "requested default_scopes are not predefined/allowed by the tenant",
		},
		{
			name:                "Valid allowed audience subset",
			predefinedAudiences: []string{"https://api.one.com", "https://api.two.com"},
			allowedAudiences:    []string{"https://api.one.com"},
			expectedStatusCode:  http.StatusCreated,
		},
		{
			name:                "Invalid allowed audience subset",
			predefinedAudiences: []string{"https://api.one.com"},
			allowedAudiences:    []string{"https://api.rogue.com"},
			expectedStatusCode:  http.StatusBadRequest,
			expectedError:       "requested allowed_audiences are not predefined/allowed by the tenant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runRegisterTestCase(t, tt)
		})
	}
}

func runRegisterTestCase(t *testing.T, tt registerTestCase) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{
		ID:                  tenantID,
		Name:                "test-tenant",
		Domain:              "test.com",
		IsActive:            true,
		PredefinedScopes:    tt.predefinedScopes,
		PredefinedAudiences: tt.predefinedAudiences,
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})

	if tt.expectedStatusCode == http.StatusCreated {
		storage.SaveClientMock.Set(func(ctx context.Context, client model.ClientApplication) error {
			return nil
		})
	}

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	payload := registerRequest{
		ClientName:       "test-app",
		RedirectURIs:     []string{"https://test.com/callback"},
		AllowedScopes:    tt.allowedScopes,
		DefaultScopes:    tt.defaultScopes,
		AllowedAudiences: tt.allowedAudiences,
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewReader(body))
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != tt.expectedStatusCode {
		t.Fatalf("expected status %d, got %d. Body: %s", tt.expectedStatusCode, rec.Code, rec.Body.String())
	}

	if tt.expectedError != "" {
		verifyRegisterErrorResponse(t, rec.Body.Bytes(), tt.expectedError)
	}
}

func verifyRegisterErrorResponse(t *testing.T, bodyBytes []byte, expectedError string) {
	var resp map[string]string
	if err := json.Unmarshal(bodyBytes, &resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp["error"] != expectedError {
		t.Fatalf("expected error %q, got %q", expectedError, resp["error"])
	}
}
