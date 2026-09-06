package http

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestHttpAdapter_Token_ClientCredentials_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", Scheme: "https"}
	secret := "supersecret"
	fakeHash := "$argon2id$v=19$m=65536,t=3,p=4$storedsecurecredentialhash"

	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	storage.GetApplicationByClientIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, clientID string) (*model.Application, *model.ApplicationProfile, *model.ApplicationGroup, error) {
		return &model.Application{
				ClientID:         "cc-client",
				ClientSecretHash: &fakeHash,
			},
			&model.ApplicationProfile{
				TokenEndpointAuthMethod: model.AuthMethodClientSecretPost,
			},
			&model.ApplicationGroup{},
			nil
	})

	crypto.CompareCredentialMock.Expect(fakeHash, secret).Return(true, nil)

	auth.ExchangeClientCredentialsMock.Set(func(ctx context.Context, cmd port.ExchangeClientCredentialsCommand) (*model.TokenSetResponse, error) {
		return &model.TokenSetResponse{
			AccessToken: "mock-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}, nil
	})

	adapter := NewHttpAdapter(tuc, auth, fuc, suc, upuc, uruc, portmock.NewLocalAuthUseCaseMock(ctrl), nil, nil, nil, storage, crypto, "unittest", "admin-domain.com")

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
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", Scheme: "https"}

	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	storage.GetApplicationByClientIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, clientID string) (*model.Application, *model.ApplicationProfile, *model.ApplicationGroup, error) {
		return &model.Application{ClientID: "ac-client"},
			&model.ApplicationProfile{TokenEndpointAuthMethod: model.AuthMethodNone},
			&model.ApplicationGroup{},
			nil
	})

	auth.ExchangeCodeForTokensMock.Set(func(ctx context.Context, cmd port.ExchangeCodeForTokensCommand) (*model.TokenSetResponse, error) {
		return &model.TokenSetResponse{
			AccessToken:  "at-123",
			IDToken:      "id-123",
			RefreshToken: "rt-123",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}, nil
	})

	adapter := NewHttpAdapter(tuc, auth, fuc, suc, upuc, uruc, portmock.NewLocalAuthUseCaseMock(ctrl), nil, nil, nil, storage, crypto, "unittest", "admin-domain.com")

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
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", Scheme: "https"}

	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	storage.GetApplicationByClientIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, clientID string) (*model.Application, *model.ApplicationProfile, *model.ApplicationGroup, error) {
		return &model.Application{ClientID: "cc-client"},
			&model.ApplicationProfile{TokenEndpointAuthMethod: model.AuthMethodNone},
			&model.ApplicationGroup{},
			nil
	})

	adapter := NewHttpAdapter(tuc, auth, fuc, suc, upuc, uruc, portmock.NewLocalAuthUseCaseMock(ctrl), nil, nil, nil, storage, crypto, "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewBufferString("grant_type=invalid_grant&client_id=cc-client"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}
