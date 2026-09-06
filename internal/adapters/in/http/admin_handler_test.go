package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func buildLocalAdminTestAdapter(ctrl *minimock.Controller) (*HttpAdapter, *portmock.AdminLogonUseCaseMock, *portmock.TenantUseCaseMock, *portmock.StorageMock, *portmock.SSOSessionUseCaseMock) {
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	aluc := portmock.NewAdminLogonUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)
	lauc := portmock.NewLocalAuthUseCaseMock(ctrl)

	adapter := NewHttpAdapter(tuc, auth, fuc, aluc, suc, upuc, uruc, lauc, nil, nil, nil, storage, crypto, "unittest", "admin-domain.com")
	return adapter, aluc, tuc, storage, suc
}

func TestHttpAdapter_AdminOIDC_Initiation_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, aluc, tuc, storage, suc := buildLocalAdminTestAdapter(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "admin-domain.com", Name: "Administrative Tenant", Scheme: "http"}
	providerID := uuid.New()

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	suc.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		if cmd.LifecycleStage == "clear" {
			return &port.CookieIntentResponse{CookieName: "spz_session_sprezz_admin"}, nil
		}
		if cmd.LifecycleStage == "handshake" {
			return &port.CookieIntentResponse{CookieName: "spz_session_sprezz_admin", CookieValue: "handshake:test-state-token"}, nil
		}
		return nil, nil
	})

	storage.GetIdentityProvidersMock.Expect(minimock.AnyContext, tenantID).Return([]model.IdentityProvider{
		{
			ID:       providerID,
			TenantID: tenantID,
			IDPType:  "oidc",
			Alias:    "admin-sso",
			Enabled:  true,
			Config:   model.IdentityProviderConfig{},
		},
	}, nil)

	aluc.InitiateAdminLogonMock.Expect(minimock.AnyContext, tenantID, "http://admin-domain.com/oauth/federation/callback", "http://admin-domain.com/admin").Return(&port.InitiateFederatedLoginResponse{
		TargetRedirectURL: "https://admin.com/oauth/authorize?client_id=registered-client-id",
		StateToken:        "test-state-token",
	}, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Host = "admin-domain.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	if location != "https://admin.com/oauth/authorize?client_id=registered-client-id" {
		t.Errorf("expected redirect location, got %s", location)
	}

	cookie := rec.Header().Get("Set-Cookie")
	if cookie == "" {
		t.Error("expected session tracking state cookie to be set")
	}
}
