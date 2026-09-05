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

func buildLocalLoginTestAdapter(ctrl *minimock.Controller) (*HttpAdapter, *portmock.LocalAuthUseCaseMock, *portmock.SSOSessionUseCaseMock, *portmock.TenantUseCaseMock) {
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)
	lauc := portmock.NewLocalAuthUseCaseMock(ctrl)

	adapter := NewHttpAdapter(tuc, auth, fuc, suc, upuc, uruc, lauc, storage, crypto, "unittest", "admin-domain.com")
	return adapter, lauc, suc, tuc
}

func TestHttpAdapter_LoginRoot_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, lauc, suc, tuc := buildLocalLoginTestAdapter(ctrl)

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

	req := httptest.NewRequest(http.MethodGet, "/", nil)
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
	adapter, _, _, tuc := buildLocalLoginTestAdapter(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/login?username=&password=", nil)
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
