package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestRequireAdminSession_ValidSessionReachesHandler(t *testing.T) {
	f := newAdminGuardFixture(t)
	f.stubProfile(f.activeProfile(), nil)

	rec := f.do(http.MethodGet, "/admin/applications/generate-secret", f.withCookie(f.bearer()))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

func TestRequireAdminSession_InvalidCookies(t *testing.T) {
	tests := []struct {
		name   string
		cookie string
	}{
		{name: "missing cookie", cookie: ""},
		{name: "handshake stage", cookie: fmt.Sprintf("handshake:%s", uuid.New())},
		{name: "garbage", cookie: "nonsense"},
		{name: "not a uuid", cookie: "bearer:not-a-uuid:12"},
		{name: "wrong partition", cookie: fmt.Sprintf("bearer:%s:99", uuid.New())},
		{name: "extra segments", cookie: fmt.Sprintf("bearer:%s:12:extra", uuid.New())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newAdminGuardFixture(t)
			// HTMX requests make the outcome observable without starting a real OIDC handshake.
			rec := f.do(http.MethodGet, "/admin/users", func(r *http.Request) {
				r.Header.Set(model.HeaderHxRequest, "true")
				if tt.cookie != "" {
					f.withCookie(tt.cookie)(r)
				}
			})

			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Equal(t, port.RouteAdmin, rec.Header().Get(model.HeaderHxRedirect))
			assert.NotContains(t, rec.Body.String(), "<table", "no admin content may leak")
		})
	}
}

func TestRequireAdminSession_UnknownUserIsRejected(t *testing.T) {
	f := newAdminGuardFixture(t)
	f.stubProfile(nil, port.ErrUserProfileNotFound)

	rec := f.do(http.MethodGet, "/admin/users", func(r *http.Request) {
		r.Header.Set(model.HeaderHxRequest, "true")
		f.withCookie(f.bearer())(r)
	})

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("Set-Cookie"), "Max-Age=0", "a stale cookie must be evicted")
}

func TestRequireAdminSession_BlockedAccountIsForbidden(t *testing.T) {
	f := newAdminGuardFixture(t)
	profile := f.activeProfile()
	profile.Blocked = true
	f.stubProfile(profile, nil)

	rec := f.do(http.MethodGet, "/admin/users", f.withCookie(f.bearer()))

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequireAdminSession_StorageFailureFailsClosed(t *testing.T) {
	f := newAdminGuardFixture(t)
	f.stubProfile(nil, fmt.Errorf("connection refused"))

	rec := f.do(http.MethodGet, "/admin/users", f.withCookie(f.bearer()))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "connection refused")
}

func TestRequireAdminSession_UnauthenticatedMutationsGet401(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			f := newAdminGuardFixture(t)

			rec := f.do(method, "/admin/applications/some-client", nil)

			assert.Equal(t, http.StatusUnauthorized, rec.Code)
		})
	}
}

func TestRequireAdminSession_LogoutStaysPublic(t *testing.T) {
	f := newAdminGuardFixture(t)

	rec := f.do(http.MethodGet, "/admin/logout?state=abc", nil)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireAdminSession_RejectsCrossSiteMutations(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{name: "cross-site fetch metadata", headers: map[string]string{"Sec-Fetch-Site": "cross-site"}, want: http.StatusForbidden},
		{name: "same-site sibling subdomain", headers: map[string]string{"Sec-Fetch-Site": "same-site"}, want: http.StatusForbidden},
		{name: "foreign origin", headers: map[string]string{"Origin": "https://evil.example"}, want: http.StatusForbidden},
		{name: "same-origin passes the origin check", headers: map[string]string{"Sec-Fetch-Site": "same-origin"}, want: http.StatusUnauthorized},
		{name: "own origin passes the origin check", headers: map[string]string{"Origin": "http://" + testAdminHost}, want: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newAdminGuardFixture(t)

			// Without a session, same-origin requests fall through to 401 while cross-site ones are stopped earlier.
			rec := f.do(http.MethodPost, "/admin/applications/app-1/toggle-status", func(r *http.Request) {
				for k, v := range tt.headers {
					r.Header.Set(k, v)
				}
			})

			assert.Equal(t, tt.want, rec.Code)
		})
	}
}

func TestIsCrossSiteStateChange(t *testing.T) {
	tests := []struct {
		name   string
		method string
		header map[string]string
		want   bool
	}{
		{name: "GET is never a state change", method: http.MethodGet, header: map[string]string{"Sec-Fetch-Site": "cross-site"}, want: false},
		{name: "no browser headers", method: http.MethodPost, want: false},
		{name: "fetch metadata wins over origin", method: http.MethodPost, header: map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://evil.example"}, want: false},
		{name: "user initiated navigation", method: http.MethodPost, header: map[string]string{"Sec-Fetch-Site": "none"}, want: false},
		{name: "unparseable origin", method: http.MethodPost, header: map[string]string{"Origin": "://bad"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/admin/x", nil)
			req.Host = testAdminHost
			for k, v := range tt.header {
				req.Header.Set(k, v)
			}
			assert.Equal(t, tt.want, isCrossSiteStateChange(req))
		})
	}
}
