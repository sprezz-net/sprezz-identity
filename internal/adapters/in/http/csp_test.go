package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"
	"sprezz-identity/internal/views/assets"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func directive(csp, name string) string {
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if part == name || strings.HasPrefix(part, name+" ") {
			return part
		}
	}
	return ""
}

func TestBuildCSP_IsStrict(t *testing.T) {
	csp := buildCSP("abc123", "/admin/applications")

	assert.Equal(t, "script-src 'self' 'nonce-abc123'", directive(csp, "script-src"))
	assert.Equal(t, "style-src 'self'", directive(csp, "style-src"))
	assert.Equal(t, "object-src 'none'", directive(csp, "object-src"))
	assert.Equal(t, "frame-ancestors 'none'", directive(csp, "frame-ancestors"))
	assert.Equal(t, "base-uri 'self'", directive(csp, "base-uri"))
	assert.Equal(t, "form-action 'self'", directive(csp, "form-action"))

	for _, banned := range []string{"unsafe-inline", "unsafe-eval", "unpkg.com", "cdn.", "jsdelivr", "googleapis"} {
		assert.NotContains(t, csp, banned)
	}
	assert.Empty(t, directive(csp, "frame-src"), "framing is only opened for the logout pages")
}

func TestBuildCSP_LogoutPagesMayFrameClients(t *testing.T) {
	for _, path := range []string{port.RouteLogout, port.RouteWebLogout} {
		csp := buildCSP("n", path)
		assert.Equal(t, "frame-src https: http:", directive(csp, "frame-src"), path)
		assert.Equal(t, "frame-ancestors 'none'", directive(csp, "frame-ancestors"), path)
	}
}

func TestBuildCSP_AdminLogoutCanBeFramedByTheProvider(t *testing.T) {
	csp := buildCSP("n", port.RouteAdmin+port.RouteAdminLogout)
	assert.Empty(t, directive(csp, "frame-ancestors"))
}

func newCSPTestAdapter(t *testing.T) *HttpAdapter {
	t.Helper()
	ctrl := minimock.NewController(t)
	adapter, _, tuc, _, _ := buildLocalAdminTestAdapter(ctrl)
	tenant := &model.Tenant{ID: uuid.New(), Domain: "admin-domain.com", Name: "Tenant", Scheme: "http", IsActive: true}
	tuc.ResolveTenantContextMock.Optional().Set(func(ctx context.Context, host string) (*model.Tenant, error) { return tenant, nil })
	return adapter
}

func TestAssets_AreServedWithoutATenant(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, tuc, _, _ := buildLocalAdminTestAdapter(ctrl)
	tuc.ResolveTenantContextMock.Optional().Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		t.Error("static assets must not need a tenant lookup")
		return nil, port.ErrTenantNotFound
	})

	req := httptest.NewRequest(http.MethodGet, assets.URL("app.css"), nil)
	req.Host = "unknown-host.example"
	rec := httptest.NewRecorder()
	adapter.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/css")
}

func TestAssets_ResponsesCarryTheCSPAndNosniff(t *testing.T) {
	adapter := newCSPTestAdapter(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, assets.URL("htmx.min.js"), nil)
	req.Host = "admin-domain.com"
	adapter.Router().ServeHTTP(rec, req)

	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.NotEmpty(t, rec.Header().Get("Content-Security-Policy"))
}

// Every page head must load only same-origin assets, and every script tag must carry the request nonce.
func TestPages_LoadOnlySameOriginAssets(t *testing.T) {
	ctrl := minimock.NewController(t)
	tuc := portmock.NewTenantUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	lauc := portmock.NewLocalAuthUseCaseMock(ctrl)

	tenant := &model.Tenant{ID: uuid.New(), Domain: "admin-domain.com", Scheme: "http", IsActive: true}
	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) { return tenant, nil })
	suc.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: "spz_session"}, nil
	})
	lauc.GetLoginContextMock.Set(func(ctx context.Context, cmd port.GetLoginContextCommand) (*port.LoginContextResponse, error) {
		return &port.LoginContextResponse{Providers: []model.IdentityProvider{}, ShowUsernamePasswordForm: true}, nil
	})

	adapter := NewHttpAdapter(tuc, portmock.NewAuthUseCaseMock(ctrl), portmock.NewFederatedLoginUseCaseMock(ctrl), nil, suc,
		portmock.NewUserProfileUseCaseMock(ctrl), portmock.NewUserRegistrationUseCaseMock(ctrl), lauc, nil, nil, nil,
		portmock.NewStorageMock(ctrl), portmock.NewCryptoMock(ctrl), "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Host = "admin-domain.com"
	rec := httptest.NewRecorder()
	adapter.Router().ServeHTTP(rec, req)

	body := rec.Body.String()
	csp := rec.Header().Get("Content-Security-Policy")
	nonce := regexp.MustCompile(`'nonce-([^']+)'`).FindStringSubmatch(csp)
	require.Len(t, nonce, 2)

	assert.NotContains(t, body, "cdn.tailwindcss.com")
	assert.NotContains(t, body, "unpkg.com")
	assert.NotContains(t, body, "cdn.jsdelivr.net")
	assert.Contains(t, body, `href="/assets/app.css?v=`)
	assert.Contains(t, body, `src="/assets/htmx.min.js?v=`)
	assert.Contains(t, body, `name="htmx-config"`)

	for _, tag := range regexp.MustCompile(`<script[^>]*>`).FindAllString(body, -1) {
		assert.Contains(t, tag, `nonce="`+nonce[1]+`"`, "script tag without the request nonce: %s", tag)
	}
	assert.NotRegexp(t, regexp.MustCompile(` style="`), body, "inline style attributes are blocked by the CSP")
}
