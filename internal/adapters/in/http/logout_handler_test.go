package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

// TestHttpAdapter_Logout_Success verifies standard OIDC redirect behavior
func TestHttpAdapter_Logout_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, auth, _, tuc, _, suc, _, _ := setupTestEnv(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	// pdated mock target to use suc instead of tuc to match factory definitions
	suc.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: "spz_session_default", CookieValue: "bearer-token"}, nil
	})

	suc.ParseSessionCookieMock.Set(func(ctx context.Context, cookieValue string) (string, string, error) {
		// Set partition index to 33 to match our clean public consumer layout boundary tests
		return "bearer", "user123:33", nil
	})

	auth.ProcessLogoutRequestMock.Set(func(ctx context.Context, cmd port.LogoutRequestCommand) (*port.LogoutExecutionResult, error) {
		return &port.LogoutExecutionResult{
			PostLogoutRedirectURI: "https://redirect-after-logout.com",
			HasCookieIntent:       true,
			CookieName:            "spz_session_default",
			CookieValue:           "",
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/logout?post_logout_redirect_uri=https://redirect-after-logout.com", nil)
	req.Header.Set("Cookie", "spz_session_default=bearer-token")
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

// TestHttpAdapter_Logout_FallbackRedirectURI verifies loop recovery when no explicit URL exists
func TestHttpAdapter_Logout_FallbackRedirectURI(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, auth, _, tuc, _, suc, _, _ := setupTestEnv(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	suc.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: "spz_session_default"}, nil
	})

	suc.ParseSessionCookieMock.Set(func(ctx context.Context, cookieValue string) (string, string, error) {
		return "bearer", "user123:33", nil
	})

	auth.ProcessLogoutRequestMock.Set(func(ctx context.Context, cmd port.LogoutRequestCommand) (*port.LogoutExecutionResult, error) {
		return &port.LogoutExecutionResult{
			PostLogoutRedirectURI: port.RouteWebLogin,
			HasCookieIntent:       true,
			CookieName:            "spz_session_default",
			CookieValue:           "",
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.Header.Set("Cookie", "spz_session_default=bearer-token")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if loc != port.RouteWebLogin {
		t.Fatalf("expected default login fallback redirect loop path, got: %s", loc)
	}
}

// TestHttpAdapter_Logout_FrontChannelIframe verifies that front-channel loops skip HTTP 302 redirections
func TestHttpAdapter_Logout_FrontChannelIframe(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, auth, _, tuc, _, suc, _, _ := setupTestEnv(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	suc.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: "spz_session_default"}, nil
	})

	suc.ParseSessionCookieMock.Set(func(ctx context.Context, cookieValue string) (string, string, error) {
		return "bearer", "user123:33", nil
	})

	auth.ProcessLogoutRequestMock.Set(func(ctx context.Context, cmd port.LogoutRequestCommand) (*port.LogoutExecutionResult, error) {
		return &port.LogoutExecutionResult{
			PostLogoutRedirectURI:  "https://redirect-after-logout.com",
			HasCookieIntent:        true,
			CookieName:             "spz_session_default",
			CookieValue:            "",
			FrontChannelLogoutURIs: []string{"https://app-one.com", "https://app-two.com"},
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.Header.Set("Cookie", "spz_session_default=bearer-token")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 for front-channel iframe generation canvas, got %d", rec.Code)
	}

	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("unexpected redirect Location found in front channel sequence frame execution: %s", loc)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Fatalf("expected text/html template asset payload stream response, got: %s", contentType)
	}
}

// TestHttpAdapter_Logout_UnwhitelistedRedirectURI_Fallback verifies that an un-whitelisted
// post_logout_redirect_uri parameter is rejected, causing the handler to fallback safely to the login wall.
func TestHttpAdapter_Logout_UnwhitelistedRedirectURI_Fallback(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, auth, _, tuc, _, suc, _, _ := setupTestEnv(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	suc.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: "spz_session_default"}, nil
	})

	suc.ParseSessionCookieMock.Set(func(ctx context.Context, cookieValue string) (string, string, error) {
		return "bearer", "user123:33", nil
	})

	auth.ProcessLogoutRequestMock.Set(func(ctx context.Context, cmd port.LogoutRequestCommand) (*port.LogoutExecutionResult, error) {
		// Mock behavior when domain validation fails: the use-case strips the untrusted
		// malicious target and forces the destination back to your local unauthenticated login gate.
		return &port.LogoutExecutionResult{
			PostLogoutRedirectURI: port.RouteWebLogin, // Enforces secure /login fallback profile
			HasCookieIntent:       true,
			CookieName:            "spz_session_default",
			CookieValue:           "",
		}, nil
	})

	// An attacker attempts an open redirect exploit by passing a malicious destination parameter
	req := httptest.NewRequest(http.MethodGet, "/logout?post_logout_redirect_uri=https://malicious-attacker-site.com", nil)
	req.Header.Set("Cookie", "spz_session_default=bearer-token")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	// The transaction must still succeed, but redirect the user to a secure internal route instead of the attacker's path
	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if loc != port.RouteWebLogin {
		t.Fatalf("SECURITY VIOLATION: system failed to trap unwhitelisted URL and redirected to: %s", loc)
	}
}
