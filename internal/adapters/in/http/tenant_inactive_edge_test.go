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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func inactiveEdgeAdapter(t *testing.T) *HttpAdapter {
	t.Helper()
	ctrl := minimock.NewController(t)
	tuc := portmock.NewTenantUseCaseMock(ctrl)
	tuc.ResolveTenantContextMock.Optional().Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return nil, port.ErrTenantInactive
	})
	return NewHttpAdapter(tuc, portmock.NewAuthUseCaseMock(ctrl), portmock.NewFederatedLoginUseCaseMock(ctrl), nil,
		portmock.NewSSOSessionUseCaseMock(ctrl), portmock.NewUserProfileUseCaseMock(ctrl), portmock.NewUserRegistrationUseCaseMock(ctrl),
		portmock.NewLocalAuthUseCaseMock(ctrl), portmock.NewAdminApplicationUseCaseMock(ctrl), nil, portmock.NewIdentityProviderUseCaseMock(ctrl),
		portmock.NewStorageMock(ctrl), portmock.NewCryptoMock(ctrl), "unittest", "admin.example.com")
}

func serve(a *HttpAdapter, method, path, accept string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Host = "off.example.com"
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rec := httptest.NewRecorder()
	a.Router().ServeHTTP(rec, req)
	return rec
}

func TestInactiveTenant_EveryRouteAnswersForbiddenAtTheEdge(t *testing.T) {
	a := inactiveEdgeAdapter(t)
	routes := []struct{ method, path string }{
		{http.MethodGet, "/.well-known/openid-configuration"},
		{http.MethodGet, "/oauth/authorize"},
		{http.MethodPost, "/oauth/token"},
		{http.MethodPost, "/oauth/introspect"},
		{http.MethodGet, "/login"},
		{http.MethodGet, "/signup"},
		{http.MethodGet, "/admin"},
	}
	for _, rt := range routes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			rec := serve(a, rt.method, rt.path, "application/json")
			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Contains(t, rec.Body.String(), "access_denied")
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		})
	}
}

func TestInactiveTenant_BrowsersGetAPlainPageThatRevealsNothing(t *testing.T) {
	a := inactiveEdgeAdapter(t)

	rec := serve(a, http.MethodGet, "/login", "text/html,application/xhtml+xml")

	require.Equal(t, http.StatusForbidden, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "not available")
	assert.NotContains(t, body, "off.example.com", "the page does not name the tenant")
	assert.NotContains(t, body, port.ErrTenantInactive.Error())
}

// The error page needs its stylesheet. Assets bypass the tenant lookup entirely, so they are served whatever the
// state of the tenant is, and nothing about the tenant can leak through them.
func TestInactiveTenant_StaticAssetsStillLoadSoTheErrorPageRenders(t *testing.T) {
	ctrl := minimock.NewController(t)
	tuc := portmock.NewTenantUseCaseMock(ctrl)
	tuc.ResolveTenantContextMock.Optional().Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		t.Error("a static asset must not trigger a tenant lookup")
		return nil, port.ErrTenantInactive
	})
	a := NewHttpAdapter(tuc, portmock.NewAuthUseCaseMock(ctrl), portmock.NewFederatedLoginUseCaseMock(ctrl), nil,
		portmock.NewSSOSessionUseCaseMock(ctrl), portmock.NewUserProfileUseCaseMock(ctrl), portmock.NewUserRegistrationUseCaseMock(ctrl),
		portmock.NewLocalAuthUseCaseMock(ctrl), portmock.NewAdminApplicationUseCaseMock(ctrl), nil, portmock.NewIdentityProviderUseCaseMock(ctrl),
		portmock.NewStorageMock(ctrl), portmock.NewCryptoMock(ctrl), "unittest", "admin.example.com")

	rec := serve(a, http.MethodGet, "/assets/app.css", "")
	assert.NotEqual(t, http.StatusForbidden, rec.Code)
}
