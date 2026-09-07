package http

import (
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

func buildLocalLoginTestAdapter(ctrl *minimock.Controller) (*HttpAdapter, *portmock.LocalAuthUseCaseMock, *portmock.SSOSessionUseCaseMock, *portmock.TenantUseCaseMock, *portmock.AuthMock) {
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)
	lauc := portmock.NewLocalAuthUseCaseMock(ctrl)

	adapter := NewHttpAdapter(tuc, auth, fuc, nil, suc, upuc, uruc, lauc, nil, nil, nil, storage, crypto, "unittest", "admin-domain.com")
	return adapter, lauc, suc, tuc, auth
}

func TestHttpAdapter_LoginRoot_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, lauc, suc, tuc, _ := buildLocalLoginTestAdapter(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", Config: model.TenantConfig{AllowSignup: true}}
	provider := model.IdentityProvider{
		ID:       uuid.New(),
		TenantID: tenantID,
		IDPType:  model.UsernamePasswordIDPType,
		Enabled:  true,
	}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	suc.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: "spz_session"}, nil
	})

	lauc.GetLoginContextMock.Set(func(ctx context.Context, cmd port.GetLoginContextCommand) (*port.LoginContextResponse, error) {
		return &port.LoginContextResponse{
			AllowSignup:              true,
			Providers:                []model.IdentityProvider{provider},
			ShowUsernamePasswordForm: true,
			PartitionID:              0,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Sign up first") {
		t.Fatalf("expected body to contain sign up link")
	}
}

func TestHttpAdapter_LoginSubmit_MissingCredentials(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, _, tuc, _ := buildLocalLoginTestAdapter(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=&password="))
	req.Header.Set(model.HeaderContentType, model.ContentTypeFormUrlEncoded)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Username and password fields are both required") {
		t.Fatalf("expected error message in response body")
	}
}

func TestHttpAdapter_LoginSubmit_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, lauc, suc, tuc, auth := buildLocalLoginTestAdapter(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", Config: model.TenantConfig{AllowSignup: true}}
	providerID := uuid.New()
	userUUID := uuid.New()

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	// Mock cookie building for both handshake parsing and bearer creation
	suc.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		if cmd.LifecycleStage == "handshake" {
			return &port.CookieIntentResponse{CookieName: "spz_auth_session_id", CookieValue: "handshake:session123"}, nil
		}
		if cmd.LifecycleStage == "bearer" {
			if !strings.Contains(cmd.PayloadValue, userUUID.String()) {
				t.Errorf("expected session cookie payload to contain user UUID '%s', got '%s'", userUUID.String(), cmd.PayloadValue)
			}
			return &port.CookieIntentResponse{CookieName: "spz_session_default", CookieValue: "bearer:session123"}, nil
		}
		return &port.CookieIntentResponse{CookieName: "spz_session_default"}, nil
	})

	suc.ParseSessionCookieMock.Set(func(ctx context.Context, cookieValue string) (string, string, error) {
		return "handshake", "session123", nil
	})

	lauc.GetInteractionSessionMock.Expect(minimock.AnyContext, tenantID, "session123").Return(&model.InteractionSession{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		PartitionID:        1,
		ClientID:           "client-abc",
		RedirectURI:        "https://callback",
		IdentityProviderID: providerID,
	}, nil)

	lauc.AuthenticateLocalCredentialsMock.Expect(minimock.AnyContext, port.LocalLoginCommand{
		TenantID:          tenantID,
		PartitionID:       1,
		ProviderID:        providerID,
		Identifier:        "testuser",
		PlaintextPassword: "password123",
	}).Return(&port.LocalLoginResponse{
		UserProfileID: userUUID,
		PartitionID:   1,
		SessionID:     "sso-session-id",
		Subject:       userUUID.String(),
	}, nil)

	auth.ProcessAuthorizeRequestMock.Set(func(ctx context.Context, cmd port.AuthorizeRequestCommand) (*port.AuthorizeExecutionResult, error) {
		if cmd.ActiveSessionID != userUUID.String()+":1" {
			t.Errorf("expected ActiveSessionID containing user UUID, got '%s'", cmd.ActiveSessionID)
		}
		if cmd.RequestURI != "" {
			t.Errorf("expected RequestURI to be empty on login complete, got '%s'", cmd.RequestURI)
		}
		return &port.AuthorizeExecutionResult{
			Action:      port.ActionEmitAuthorizationCode,
			RedirectURL: "https://callback?code=abc",
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=password123"))
	req.Header.Set(model.HeaderContentType, model.ContentTypeFormUrlEncoded)
	req.Header.Set("Cookie", "spz_auth_session_id=handshake:session123")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	hxRedirect := rec.Header().Get(model.HeaderHXRedirect)
	if hxRedirect != "https://callback?code=abc" {
		t.Errorf("expected HX-Redirect 'https://callback?code=abc', got '%s'", hxRedirect)
	}
}

func TestHttpAdapter_LoginWithInteractionID_QueryAndForm(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, lauc, suc, tuc, auth := buildLocalLoginTestAdapter(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", Config: model.TenantConfig{AllowSignup: true}}
	provider := model.IdentityProvider{
		ID:       uuid.New(),
		TenantID: tenantID,
		IDPType:  model.UsernamePasswordIDPType,
		Enabled:  true,
	}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	suc.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: "spz_session_default", CookieValue: "bearer:session123"}, nil
	})

	// 1. Verify HandleLoginRoot correctly reads tx from URL query parameter
	lauc.GetLoginContextMock.Set(func(ctx context.Context, cmd port.GetLoginContextCommand) (*port.LoginContextResponse, error) {
		if cmd.InteractionID != "url_interaction_123" {
			t.Errorf("expected InteractionID 'url_interaction_123', got '%s'", cmd.InteractionID)
		}
		return &port.LoginContextResponse{
			AllowSignup:              true,
			Providers:                []model.IdentityProvider{provider},
			ShowUsernamePasswordForm: true,
			PartitionID:              0,
		}, nil
	})

	reqRoot := httptest.NewRequest(http.MethodGet, "/login?tx=url_interaction_123", nil)
	reqRoot.Host = "test.com"
	recRoot := httptest.NewRecorder()

	adapter.Router().ServeHTTP(recRoot, reqRoot)

	if recRoot.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recRoot.Code)
	}

	// 1.1 Verify HandleLoginRootRedirect redirects from "/" to "/login" keeping parameters
	reqRedirect := httptest.NewRequest(http.MethodGet, "/?tx=url_interaction_123", nil)
	reqRedirect.Host = "test.com"
	recRedirect := httptest.NewRecorder()

	adapter.Router().ServeHTTP(recRedirect, reqRedirect)

	if recRedirect.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", recRedirect.Code)
	}
	if loc := recRedirect.Header().Get("Location"); loc != "/login?tx=url_interaction_123" {
		t.Errorf("expected redirect location '/login?tx=url_interaction_123', got '%s'", loc)
	}

	// 2. Verify HandleLoginSubmit correctly reads tx from form payload
	lauc.GetInteractionSessionMock.Expect(minimock.AnyContext, tenantID, "form_interaction_456").Return(&model.InteractionSession{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		PartitionID:        1,
		ClientID:           "client-abc",
		RedirectURI:        "https://callback",
		IdentityProviderID: provider.ID,
	}, nil)

	lauc.AuthenticateLocalCredentialsMock.Set(func(ctx context.Context, cmd port.LocalLoginCommand) (*port.LocalLoginResponse, error) {
		return &port.LocalLoginResponse{
			UserProfileID: uuid.New(),
			PartitionID:   1,
			SessionID:     "sso-session-id",
			Subject:       "user-123",
		}, nil
	})

	auth.ProcessAuthorizeRequestMock.Set(func(ctx context.Context, cmd port.AuthorizeRequestCommand) (*port.AuthorizeExecutionResult, error) {
		return &port.AuthorizeExecutionResult{
			Action:      port.ActionEmitAuthorizationCode,
			RedirectURL: "https://callback?code=abc",
		}, nil
	})

	reqSubmit := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=password123&tx=form_interaction_456"))
	reqSubmit.Header.Set(model.HeaderContentType, model.ContentTypeFormUrlEncoded)
	reqSubmit.Host = "test.com"
	recSubmit := httptest.NewRecorder()

	adapter.Router().ServeHTTP(recSubmit, reqSubmit)

	if recSubmit.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recSubmit.Code)
	}
}
