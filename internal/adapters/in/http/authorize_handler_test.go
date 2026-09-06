package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func setupTestEnv(ctrl *minimock.Controller) (
	*HttpAdapter,
	*portmock.StorageMock,
	*portmock.AuthMock,
	*portmock.CryptoMock,
	*portmock.TenantUseCaseMock,
	*portmock.FederatedLoginUseCaseMock,
	*portmock.SSOSessionUseCaseMock,
	*portmock.UserProfileUseCaseMock,
	*portmock.UserRegistrationUseCaseMock,
) {
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)
	lauc := portmock.NewLocalAuthUseCaseMock(ctrl)

	adapter := NewHttpAdapter(tuc, auth, fuc, suc, upuc, uruc, lauc, nil, nil, nil, storage, crypto, "unittest", "admin-domain.com")
	return adapter, storage, auth, crypto, tuc, fuc, suc, upuc, uruc
}
func mockSessionCookie(suc *portmock.SSOSessionUseCaseMock) {
	suc.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: "spz_session"}, nil
	})
}

func TestHttpAdapter_Authorize_PreservesParams(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, auth, _, tuc, _, suc, _, _ := setupTestEnv(ctrl)
	mockSessionCookie(suc)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	auth.ProcessAuthorizeRequestMock.Set(func(ctx context.Context, cmd port.AuthorizeRequestCommand) (*port.AuthorizeExecutionResult, error) {
		if cmd.ClientID != "test-client" {
			t.Errorf("expected ClientID 'test-client', got %s", cmd.ClientID)
		}
		if cmd.State != "state-1234567890-abcdef" {
			t.Errorf("expected State 'state-1234567890-abcdef', got %s", cmd.State)
		}
		return &port.AuthorizeExecutionResult{
			Action:      port.ActionRedirectToLoginUI,
			RedirectURL: "https://test.com/login",
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=test-client&redirect_uri=https://test.com/callback&state=state-1234567890-abcdef&nonce=nonce-456&acr_values=acr-silver", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", rec.Code)
	}
}

func TestHttpAdapter_Authorize_InvalidClient(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, auth, _, tuc, _, suc, _, _ := setupTestEnv(ctrl)
	mockSessionCookie(suc)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})
	auth.ProcessAuthorizeRequestMock.Set(func(ctx context.Context, cmd port.AuthorizeRequestCommand) (*port.AuthorizeExecutionResult, error) {
		return nil, errors.New("client is not registered")
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=unknown-client&redirect_uri=https://test.com/callback", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestHttpAdapter_Authorize_DisallowedRedirectURI(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, auth, _, tuc, _, suc, _, _ := setupTestEnv(ctrl)
	mockSessionCookie(suc)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})
	auth.ProcessAuthorizeRequestMock.Set(func(ctx context.Context, cmd port.AuthorizeRequestCommand) (*port.AuthorizeExecutionResult, error) {
		return nil, errors.New("disallowed redirect uri")
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=test-client&redirect_uri=https://malicious.com/callback", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestHttpAdapter_Authorize_AuthenticatedSSO(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, auth, _, tuc, _, suc, _, _ := setupTestEnv(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	suc.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{
			CookieName: "spz_session",
		}, nil
	})

	suc.ParseSessionCookieMock.Set(func(ctx context.Context, val string) (string, string, error) {
		return "bearer", "some-user-session-id", nil
	})

	auth.ProcessAuthorizeRequestMock.Set(func(ctx context.Context, cmd port.AuthorizeRequestCommand) (*port.AuthorizeExecutionResult, error) {
		return &port.AuthorizeExecutionResult{
			Action:          port.ActionEmitAuthorizationCode,
			RedirectURL:     "https://test.com/callback?code=code123&state=state123",
			HasCookieIntent: true,
			CookieName:      "spz_session",
			CookieValue:     "new-cookie-val",
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=test-client&redirect_uri=https://test.com/callback&state=state123", nil)
	req.Host = "test.com"
	req.AddCookie(&http.Cookie{Name: "spz_session", Value: "existing-cookie-val"})
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", rec.Code)
	}
}
