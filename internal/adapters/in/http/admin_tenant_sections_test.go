package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (f *pagesFixture) capturePatch() *port.PatchTenantCommand {
	got := &port.PatchTenantCommand{}
	f.tenants.PatchTenantMock.Set(func(ctx context.Context, cmd port.PatchTenantCommand) error {
		*got = cmd
		return nil
	})
	return got
}

func TestTenantSection_GeneralPassesTheTargetAndTheActingTenant(t *testing.T) {
	f := newPagesFixture(t)
	acme := testTenant("Acme", "acme.example.com")
	f.stubTenantPage(acme, model.TenantUsage{})
	got := f.capturePatch()

	rec := f.do(http.MethodPut, tenantPath(acme)+"/general", url.Values{"name": {"Acme Corp"}, "domain": {"acme.example.com"}}, htmx())

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, acme.ID, got.TenantID, "the tenant named in the URL is the one edited")
	assert.Equal(t, f.tenantID, got.ActingTenant, "the signed-in tenant is passed so the service can decide")
	assert.Equal(t, port.TenantSectionGeneral, got.Section)
	body := rec.Body.String()
	assert.Contains(t, body, `id="section-general"`)
	assert.NotContains(t, body, `id="section-scopes"`, "only the saved card is returned")
}

func TestTenantSection_ParsesEachSection(t *testing.T) {
	f := newPagesFixture(t)
	acme := testTenant("Acme", "acme.example.com")
	f.stubTenantPage(acme, model.TenantUsage{})
	got := f.capturePatch()

	f.do(http.MethodPut, tenantPath(acme)+"/redirects", url.Values{
		"redirect_uris": {" https://a.example.com/cb ", "", "https://b.example.com/cb"}, "default_redirect_uri": {"https://b.example.com/cb"},
	}, htmx())
	assert.Equal(t, []string{"https://a.example.com/cb", "https://b.example.com/cb"}, got.RedirectWhitelist)
	assert.Equal(t, "https://b.example.com/cb", got.DefaultRedirectURI)

	f.do(http.MethodPut, tenantPath(acme)+"/scopes", url.Values{
		"predefined_scopes_text": {"openid  email\tread:orders"}, "predefined_audiences": {"https://api.example.com", " "},
	}, htmx())
	assert.Equal(t, []string{"openid", "email", "read:orders"}, got.PredefinedScopes)
	assert.Equal(t, []string{"https://api.example.com"}, got.PredefinedAudiences)

	f.do(http.MethodPut, tenantPath(acme)+"/signup", url.Values{"allow_signup": {"true"}}, htmx())
	assert.True(t, got.AllowSignup)
	f.do(http.MethodPut, tenantPath(acme)+"/signup", url.Values{}, htmx())
	assert.False(t, got.AllowSignup, "an unchecked box means closed registration")
}

func TestTenantSection_ErrorsAreSanitized(t *testing.T) {
	verr := port.NewValidationError()
	verr.Add("domain", "another tenant already uses this domain")
	cases := map[string]struct {
		err    error
		status int
		text   string
	}{
		"validation": {verr, http.StatusUnprocessableEntity, "another tenant already uses this domain"},
		"forbidden":  {port.ErrForbidden, http.StatusForbidden, port.ErrForbidden.Error()},
		"system":     {port.ErrSystemManaged, http.StatusForbidden, port.ErrSystemManaged.Error()},
		"unexpected": {errors.New("pq: password authentication failed for user sprezz_db"), http.StatusInternalServerError, "an unexpected error occurred"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newPagesFixture(t)
			acme := testTenant("Acme", "acme.example.com")
			f.stubTenantPage(acme, model.TenantUsage{})
			f.tenants.PatchTenantMock.Return(tc.err)

			rec := f.do(http.MethodPut, tenantPath(acme)+"/general", url.Values{"name": {"A"}, "domain": {"x"}}, htmx())

			assert.Equal(t, tc.status, rec.Code)
			assert.Contains(t, rec.Body.String(), tc.text)
			assert.NotContains(t, rec.Body.String(), "sprezz_db")
		})
	}
}

func TestTenantSection_UnknownSectionAndMalformedID(t *testing.T) {
	f := newPagesFixture(t)
	acme := testTenant("Acme", "acme.example.com")
	f.stubTenantPage(acme, model.TenantUsage{})

	assert.Equal(t, http.StatusNotFound, f.do(http.MethodPut, tenantPath(acme)+"/bogus", url.Values{}, htmx()).Code)
	assert.Equal(t, http.StatusNotFound, f.do(http.MethodPut, "/admin/tenants/not-a-uuid/general", url.Values{}, htmx()).Code)
}

// The whole-form settings save and the toggle endpoint are gone. The paths still match other routes (a section
// of the tenant, the tenant itself), so the router answers "method not allowed" or "not found" instead of running
// the old handlers. What matters is that neither request is ever served successfully.
func TestTenantRoutes_OldEndpointsAreGone(t *testing.T) {
	f := newPagesFixture(t)
	f.tenants.PatchTenantMock.Optional().Set(func(ctx context.Context, cmd port.PatchTenantCommand) error {
		t.Error("the removed endpoints must not reach the service")
		return nil
	})

	for _, rec := range []*httptest.ResponseRecorder{
		f.do(http.MethodPost, "/admin/tenants/settings", url.Values{"name": {"x"}}, htmx()),
		f.do(http.MethodPatch, "/admin/tenants/"+f.tenantID.String()+"/toggle-signup", nil, htmx()),
	} {
		assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rec.Code)
	}
}
