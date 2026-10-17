package http

import (
	"context"
	"errors"
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

func setupTestEnv(ctrl *minimock.Controller) (
	*HttpAdapter,
	*portmock.StorageMock,
	*portmock.AuthUseCaseMock,
	*portmock.CryptoMock,
	*portmock.TenantUseCaseMock,
	*portmock.FederatedLoginUseCaseMock,
	*portmock.SSOSessionUseCaseMock,
	*portmock.UserProfileUseCaseMock,
	*portmock.UserRegistrationUseCaseMock,
) {
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthUseCaseMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)
	lauc := portmock.NewLocalAuthUseCaseMock(ctrl)

	adapter := NewHttpAdapter(tuc, auth, fuc, nil, suc, upuc, uruc, lauc, nil, nil, nil, storage, crypto, "unittest", "admin-domain.com")
	return adapter, storage, auth, crypto, tuc, fuc, suc, upuc, uruc
}

func TestHttpAdapter_Authorize_PreservesParams(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, auth, _, tuc, _, _, _, _ := setupTestEnv(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", IsActive: true}

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
		if len(cmd.Scopes) != 3 || cmd.Scopes[0] != "openid" || cmd.Scopes[1] != "profile" || cmd.Scopes[2] != "email" {
			t.Errorf("expected Scopes '[openid profile email]', got %v", cmd.Scopes)
		}
		return &port.AuthorizeExecutionResult{
			Action:      port.ActionRedirectToLoginUI,
			RedirectURL: "https://test.com/login",
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=test-client&redirect_uri=https://test.com/callback&state=state-1234567890-abcdef&nonce=nonce-456&acr_values=acr-silver&scope=openid+profile+email", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", rec.Code)
	}
}

func TestHttpAdapter_Authorize_InvalidClient(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, auth, _, tuc, _, _, _, _ := setupTestEnv(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", IsActive: true}

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
	adapter, _, auth, _, tuc, _, _, _, _ := setupTestEnv(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", IsActive: true}

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

func TestHttpAdapter_Authorize_HandsTheCookiesToTheDomain(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, auth, _, tuc, _, _, _, _ := setupTestEnv(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", IsActive: true}
	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	// The domain, not the transport layer, finds the session: it knows the partition of the client.
	auth.ProcessAuthorizeRequestMock.Set(func(ctx context.Context, cmd port.AuthorizeRequestCommand) (*port.AuthorizeExecutionResult, error) {
		if cmd.ActiveSession != nil {
			t.Errorf("the handler must not resolve sessions itself, got %+v", cmd.ActiveSession)
		}
		if cmd.Cookies["spz_session_default"] != "existing-cookie-val" {
			t.Errorf("the session cookies must reach the use case, got %v", cmd.Cookies)
		}
		if _, leaked := cmd.Cookies["unrelated"]; leaked {
			t.Errorf("only session cookies are handed over, got %v", cmd.Cookies)
		}
		return &port.AuthorizeExecutionResult{
			Action:          port.ActionEmitAuthorizationCode,
			RedirectURL:     "https://test.com/callback?code=code123&state=state123",
			HasCookieIntent: true,
			CookieName:      "spz_session_default",
			CookieValue:     "new-cookie-val",
			CookieMaxAge:    900,
			CookieSecure:    true,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=test-client&redirect_uri=https://test.com/callback&state=state123", nil)
	req.Host = "test.com"
	req.AddCookie(&http.Cookie{Name: "spz_session_default", Value: "existing-cookie-val"})
	req.AddCookie(&http.Cookie{Name: "unrelated", Value: "x"})
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", rec.Code)
	}
	cookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "spz_session_default=new-cookie-val") || !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "Max-Age=900") {
		t.Errorf("the cookie intent of the domain must be applied HttpOnly, got %q", cookie)
	}
}
