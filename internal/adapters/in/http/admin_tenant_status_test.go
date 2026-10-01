package http

import (
	"net/http"
	"net/url"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenantDetail_StatusCardIsOfferedOnlyForOtherTenantsToTheAdministrativeSession(t *testing.T) {
	t.Run("another tenant, administrative session", func(t *testing.T) {
		f := newPagesFixture(t)
		acme := testTenant("Acme", "acme.example.com")
		f.stubTenantPage(acme, model.TenantUsage{})
		body := f.do(http.MethodGet, tenantPath(acme), nil, nil).Body.String()
		assert.Contains(t, body, `hx-put="`+tenantPath(acme)+`/status"`)
		assert.Contains(t, body, `href="#section-status"`)
	})
	t.Run("the administrative tenant itself", func(t *testing.T) {
		f := newPagesFixture(t)
		system := testTenant("Platform", "admin.example.com")
		system.IsSystem = true
		f.stubTenantPage(system, model.TenantUsage{})
		assert.NotContains(t, f.do(http.MethodGet, tenantPath(system), nil, nil).Body.String(), `id="section-status"`)
	})
	t.Run("the tenant you are signed in to", func(t *testing.T) {
		f := newPagesFixture(t)
		own := *f.tenant
		own.IsSystem = false
		f.tenant.IsSystem = true
		f.stubTenantPage(own, model.TenantUsage{})
		assert.NotContains(t, f.do(http.MethodGet, tenantPath(own), nil, nil).Body.String(), `id="section-status"`, "switching yourself off would shut out the console")
	})
	t.Run("a customer session", func(t *testing.T) {
		f := newPagesFixture(t)
		f.tenant.IsSystem = false
		own := *f.tenant
		f.stubTenantPage(own, model.TenantUsage{})
		assert.NotContains(t, f.do(http.MethodGet, tenantPath(own), nil, nil).Body.String(), `id="section-status"`)
	})
}

func TestTenantDetail_AnInactiveTenantIsFlagged(t *testing.T) {
	f := newPagesFixture(t)
	off := testTenant("Off Co", "off.example.com")
	off.IsActive = false
	f.stubTenantPage(off, model.TenantUsage{})

	body := f.do(http.MethodGet, tenantPath(off), nil, nil).Body.String()
	assert.Contains(t, body, "This tenant is not active")
	assert.Contains(t, body, "Not active")
}

func TestTenantSection_StatusParsesTheCheckbox(t *testing.T) {
	f := newPagesFixture(t)
	acme := testTenant("Acme", "acme.example.com")
	f.stubTenantPage(acme, model.TenantUsage{})
	got := f.capturePatch()

	rec := f.do(http.MethodPut, tenantPath(acme)+"/status", url.Values{}, htmx())
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, port.TenantSectionStatus, got.Section)
	assert.False(t, got.Active, "an unchecked box deactivates")
	assert.Contains(t, rec.Body.String(), `id="section-status"`)

	f.do(http.MethodPut, tenantPath(acme)+"/status", url.Values{"active": {"true"}}, htmx())
	assert.True(t, got.Active)
}

func TestTenantSection_StatusRefusalsAreShownInTheCard(t *testing.T) {
	for _, refusal := range []error{port.ErrForbidden, port.ErrSystemManaged, port.ErrOwnAccount} {
		f := newPagesFixture(t)
		acme := testTenant("Acme", "acme.example.com")
		f.stubTenantPage(acme, model.TenantUsage{})
		f.tenants.PatchTenantMock.Return(refusal)

		rec := f.do(http.MethodPut, tenantPath(acme)+"/status", url.Values{}, htmx())

		assert.GreaterOrEqual(t, rec.Code, 400)
		assert.Contains(t, rec.Body.String(), refusal.Error())
	}
}

func TestTenantList_ShowsAndFiltersByStatus(t *testing.T) {
	f := newPagesFixture(t)
	on, off := testTenant("OnCo", "on.example.com"), testTenant("OffCo", "off.example.com")
	on.IsActive, off.IsActive = true, false
	f.tenants.ListTenantsMock.Return([]port.TenantDetail{{Tenant: on}, {Tenant: off}}, nil)

	all := f.do(http.MethodGet, "/admin/tenants", nil, htmx()).Body.String()
	assert.Contains(t, all, "Not active")

	inactive := f.do(http.MethodGet, "/admin/tenants?status=inactive", nil, htmx()).Body.String()
	assert.Contains(t, inactive, ">OffCo<")
	assert.NotContains(t, inactive, ">OnCo<")

	active := f.do(http.MethodGet, "/admin/tenants?status=active", nil, htmx()).Body.String()
	assert.Contains(t, active, ">OnCo<")
	assert.NotContains(t, active, ">OffCo<")
}

func TestAdminErrors_InactiveTenantIsForbidden(t *testing.T) {
	status, message := adminErrorStatus(port.ErrTenantInactive)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, port.ErrTenantInactive.Error(), message)
}
