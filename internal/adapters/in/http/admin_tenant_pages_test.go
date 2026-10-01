package http

import (
	"context"
	"net/http"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testTenant(name, domain string) model.Tenant {
	return model.Tenant{
		ID: uuid.New(), Name: name, Domain: domain, Scheme: "https",
		Config: model.TenantConfig{
			PredefinedScopes: []string{"openid", "profile"}, RedirectWhitelist: []string{"https://" + domain + "/cb"},
			DefaultRedirectURI: "https://" + domain + "/cb", PredefinedAudiences: []string{"https://api." + domain},
		},
		IsActive: true,
	}
}

func tenantPath(t model.Tenant) string {
	return "/admin/tenants/" + t.ID.String()
}

func (f *pagesFixture) stubTenantPage(t model.Tenant, usage model.TenantUsage) {
	f.tenants.GetTenantMock.Optional().Set(func(ctx context.Context, acting, id uuid.UUID) (*port.TenantDetail, error) {
		if id != t.ID {
			return nil, port.ErrForbidden
		}
		return &port.TenantDetail{Tenant: t, Usage: usage}, nil
	})
}

func TestTenantList_SystemSessionSeesUsageAndMayAdd(t *testing.T) {
	f := newPagesFixture(t)
	acme, globex := testTenant("Acme", "acme.example.com"), testTenant("Globex", "globex.example.com")
	acme.Config.AllowSignup = true
	f.tenants.ListTenantsMock.Return([]port.TenantDetail{
		{Tenant: acme, Usage: model.TenantUsage{Users: 41, Applications: 3}}, {Tenant: globex},
	}, nil)

	body := f.do(http.MethodGet, "/admin/tenants", nil, htmx()).Body.String()
	assert.Contains(t, body, `href="`+tenantPath(acme)+`"`, "rows link to routed pages, not modals")
	assert.Contains(t, body, ">41<")
	assert.Contains(t, body, "+ Add tenant")
	assert.Contains(t, body, "Open", "open registration is flagged")

	assert.NotContains(t, f.do(http.MethodGet, "/admin/tenants?q=GLOBEX", nil, htmx()).Body.String(), ">Acme<", "search ignores case")
	assert.Contains(t, f.do(http.MethodGet, "/admin/tenants?q=nomatch", nil, htmx()).Body.String(), "No tenants found")
}

func TestTenantList_CustomerSessionHasNoAddButton(t *testing.T) {
	f := newPagesFixture(t)
	f.tenant.IsSystem = false
	own := *f.tenant
	f.tenants.ListTenantsMock.Return([]port.TenantDetail{{Tenant: own}}, nil)

	body := f.do(http.MethodGet, "/admin/tenants", nil, htmx()).Body.String()
	assert.NotContains(t, body, "+ Add tenant")
}

func TestTenantDetail_RendersCardsAndTheContents(t *testing.T) {
	f := newPagesFixture(t)
	acme := testTenant("Acme", "acme.example.com")
	f.stubTenantPage(acme, model.TenantUsage{Users: 12, Applications: 4, Providers: 2, Partitions: 1})

	full := f.do(http.MethodGet, tenantPath(acme), nil, nil)
	require.Equal(t, http.StatusOK, full.Code)
	body := full.Body.String()
	assert.Contains(t, body, "<html")
	for _, section := range []string{"general", "signup", "redirects", "scopes"} {
		assert.Contains(t, body, `hx-put="`+tenantPath(acme)+`/`+section+`"`)
	}
	assert.Contains(t, body, `id="section-contents"`)
	assert.NotContains(t, f.do(http.MethodGet, tenantPath(acme), nil, htmx()).Body.String(), "<html")
}

func TestTenantDetail_DangerZoneSaysWhatWouldBeRemoved(t *testing.T) {
	f := newPagesFixture(t)
	acme := testTenant("Acme", "acme.example.com")
	f.stubTenantPage(acme, model.TenantUsage{Users: 12, Applications: 4, Groups: 3, Profiles: 2, Providers: 2, Partitions: 1})

	body := f.do(http.MethodGet, tenantPath(acme), nil, nil).Body.String()
	assert.Contains(t, body, "12 user(s)")
	assert.Contains(t, body, "4 application(s)")
	assert.Contains(t, body, "audit trail")
	assert.Contains(t, body, `hx-delete="`+tenantPath(acme)+`"`)
}

func TestTenantDetail_NoDeletionForSystemOrOwnTenantOrCustomerSessions(t *testing.T) {
	t.Run("the administrative tenant", func(t *testing.T) {
		f := newPagesFixture(t)
		system := testTenant("Platform", "admin.example.com")
		system.IsSystem = true
		f.stubTenantPage(system, model.TenantUsage{})
		body := f.do(http.MethodGet, tenantPath(system), nil, nil).Body.String()
		assert.NotContains(t, body, "Danger zone")
		assert.Contains(t, body, "domain of the administrative tenant is fixed")
	})
	t.Run("the tenant you are signed in to", func(t *testing.T) {
		f := newPagesFixture(t)
		f.tenant.IsSystem = true
		own := *f.tenant
		own.IsSystem = false
		f.tenant.ID = own.ID
		f.stubTenantPage(own, model.TenantUsage{})
		body := f.do(http.MethodGet, tenantPath(own), nil, nil).Body.String()
		assert.Contains(t, body, "cannot be deleted from here")
		assert.NotContains(t, body, `hx-delete=`)
	})
	t.Run("a customer session", func(t *testing.T) {
		f := newPagesFixture(t)
		f.tenant.IsSystem = false
		own := *f.tenant
		f.stubTenantPage(own, model.TenantUsage{})
		assert.NotContains(t, f.do(http.MethodGet, tenantPath(own), nil, nil).Body.String(), "Danger zone")
	})
}

func TestTenantDetail_ForeignOrMalformedID(t *testing.T) {
	f := newPagesFixture(t)
	f.tenants.GetTenantMock.Optional().Return(nil, port.ErrForbidden)

	assert.Equal(t, http.StatusNotFound, f.do(http.MethodGet, "/admin/tenants/not-a-uuid", nil, nil).Code)
	assert.Equal(t, http.StatusForbidden, f.do(http.MethodGet, "/admin/tenants/"+uuid.NewString(), nil, nil).Code)
}

func TestTenantNew_OnlyForTheSystemTenant(t *testing.T) {
	f := newPagesFixture(t)
	assert.Contains(t, f.do(http.MethodGet, "/admin/tenants/new", nil, htmx()).Body.String(), `name="domain"`)

	customer := newPagesFixture(t)
	customer.tenant.IsSystem = false
	assert.Equal(t, http.StatusForbidden, customer.do(http.MethodGet, "/admin/tenants/new", nil, htmx()).Code)
}
