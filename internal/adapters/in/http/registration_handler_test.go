package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

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
		ID:       tenantID,
		Name:     "test-tenant",
		Domain:   "test.com",
		IsActive: true,
		Config: model.TenantConfig{
			PredefinedScopes:    tt.predefinedScopes,
			PredefinedAudiences: tt.predefinedAudiences,
			RedirectWhitelist:   []string{"https://test.com/callback"},
		},
	}

	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	if tt.expectedStatusCode == http.StatusCreated {
		auth.ProcessDynamicRegistrationMock.Set(func(ctx context.Context, tenantID uuid.UUID, payload model.DynamicRegistrationPayload) (*port.DynamicRegistrationResult, error) {
			return &port.DynamicRegistrationResult{
				Application: &model.Application{
					ClientID:        "dyn-client-123",
					ApplicationName: "test-app",
					CreatedAt:       time.Now(),
				},
				PlaintextSecret: "some-secret",
			}, nil
		})
	} else {
		auth.ProcessDynamicRegistrationMock.Set(func(ctx context.Context, tenantID uuid.UUID, payload model.DynamicRegistrationPayload) (*port.DynamicRegistrationResult, error) {
			return nil, errors.New(tt.expectedError)
		})
	}

	adapter := NewHttpAdapter(tuc, auth, fuc, suc, upuc, uruc, portmock.NewLocalAuthUseCaseMock(ctrl), storage, crypto, "unittest", "admin-domain.com")

	payload := registerRequest{
		ClientName:       "test-app",
		RedirectURIs:     []string{"https://test.com/callback"},
		AllowedScopes:    tt.allowedScopes,
		DefaultScopes:    tt.defaultScopes,
		AllowedAudiences: tt.allowedAudiences,
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
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
	if resp["error"] != "invalid_client_metadata" {
		t.Fatalf("expected error invalid_client_metadata, got %q", resp["error"])
	}
	if !strings.Contains(resp["error_description"], expectedError) {
		t.Fatalf("expected error_description containing %q, got %q", expectedError, resp["error_description"])
	}
}
