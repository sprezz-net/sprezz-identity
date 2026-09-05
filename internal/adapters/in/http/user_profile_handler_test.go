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

func buildLocalProfileTestAdapter(ctrl *minimock.Controller) (*HttpAdapter, *portmock.UserProfileUseCaseMock, *portmock.SSOSessionUseCaseMock, *portmock.TenantUseCaseMock) {
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
	return adapter, upuc, suc, tuc
}

func TestHttpAdapter_ViewProfile_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, upuc, suc, tuc := buildLocalProfileTestAdapter(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	suc.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: "spz_session", CookieValue: "bearer-token"}, nil
	})

	userUUID := uuid.New()

	suc.ParseSessionCookieMock.Set(func(ctx context.Context, cookieValue string) (string, string, error) {
		return "bearer", userUUID.String() + ":0", nil
	})

	upuc.GetUserProfileDashboardMock.Set(func(ctx context.Context, cmd port.GetUserProfileDashboardCommand) (*port.GetUserProfileDashboardResponse, error) {
		return &port.GetUserProfileDashboardResponse{
			UserProfile: model.UserProfile{
				ID:                userUUID,
				PreferredUsername: "alice",
				Email:             "alice@example.com",
				Name:              "Alice",
			},
			Identities:     []model.UserIdentity{},
			Providers:      []model.IdentityProvider{},
			HasPasswordIDP: true,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/profile", nil)
	req.Header.Set("Cookie", "spz_session=bearer-token")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Alice") || !strings.Contains(body, "alice@example.com") {
		t.Fatalf("profile dashboard response missing expected user profile metrics")
	}
}
