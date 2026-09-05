package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestHttpAdapter_Logout_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, auth, _, tuc, _, suc, _, _ := setupTestEnv(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	suc.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: "spz_session", CookieValue: "bearer-token"}, nil
	})

	suc.ParseSessionCookieMock.Set(func(ctx context.Context, cookieValue string) (string, string, error) {
		return "bearer", "user123:0", nil
	})

	auth.ProcessLogoutRequestMock.Set(func(ctx context.Context, cmd port.LogoutRequestCommand) (*port.LogoutExecutionResult, error) {
		return &port.LogoutExecutionResult{
			PostLogoutRedirectURI: "https://redirect-after-logout.com",
			HasCookieIntent:       true,
			CookieName:            "spz_session",
			CookieValue:           "",
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth/logout?post_logout_redirect_uri=https://redirect-after-logout.com", nil)
	req.Header.Set("Cookie", "spz_session=bearer-token")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if loc != "https://redirect-after-logout.com" {
		t.Fatalf("unexpected redirect location: %s", loc)
	}
}
