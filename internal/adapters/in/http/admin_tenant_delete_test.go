package http

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/stretchr/testify/assert"
)

func TestTenantDelete_PassesTheTypedDomainAndTheActingSession(t *testing.T) {
	f := newPagesFixture(t)
	acme := testTenant("Acme", "acme.example.com")
	f.stubTenantPage(acme, model.TenantUsage{})
	var got port.DeleteTenantCommand
	f.tenants.DeleteTenantMock.Set(func(ctx context.Context, cmd port.DeleteTenantCommand) error {
		got = cmd
		v := port.NewValidationError()
		v.Add("confirmation", "type the tenant's domain name exactly to confirm deletion")
		return v
	})

	rec := f.do(http.MethodDelete, tenantPath(acme), url.Values{"confirmation": {"wrong"}}, htmx())

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), "type the tenant")
	assert.Equal(t, "wrong", got.Confirmation, "the typed text reaches the service, which decides")
	assert.Equal(t, acme.ID, got.TenantID)
	assert.Equal(t, f.tenantID, got.ActingTenantID)
	assert.Equal(t, f.userID.String(), got.ActingUserID, "the administrator is recorded in the final audit log line")
}

func TestTenantDelete_ConfirmedDeletionRedirectsToTheList(t *testing.T) {
	f := newPagesFixture(t)
	acme := testTenant("Acme", "acme.example.com")
	f.stubTenantPage(acme, model.TenantUsage{})
	f.tenants.DeleteTenantMock.Return(nil)

	rec := f.do(http.MethodDelete, tenantPath(acme), url.Values{"confirmation": {"acme.example.com"}}, htmx())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("HX-Redirect"), "/admin/tenants?msg=")
}

func TestTenantDelete_RefusalsAreShownInTheDangerZone(t *testing.T) {
	for _, refusal := range []error{port.ErrSystemManaged, port.ErrForbidden} {
		f := newPagesFixture(t)
		acme := testTenant("Acme", "acme.example.com")
		f.stubTenantPage(acme, model.TenantUsage{})
		f.tenants.DeleteTenantMock.Return(refusal)

		rec := f.do(http.MethodDelete, tenantPath(acme), url.Values{"confirmation": {"acme.example.com"}}, htmx())

		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
		assert.Contains(t, rec.Body.String(), refusal.Error())
	}
}

func TestTenantCreate_RedirectsToTheNewTenantPage(t *testing.T) {
	f := newPagesFixture(t)
	created := testTenant("New Co", "new.example.com")
	f.tenants.CreateTenantMock.Set(func(ctx context.Context, cmd port.CreateTenantFromConsoleCommand) (*model.Tenant, error) {
		assert.Equal(t, f.tenantID, cmd.ActingTenant)
		assert.Equal(t, "New Co", cmd.Name)
		return &created, nil
	})

	rec := f.do(http.MethodPost, "/admin/tenants", url.Values{"name": {"New Co"}, "domain": {"new.example.com"}}, htmx())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("HX-Redirect"), tenantPath(created))
}

func TestTenantCreate_ErrorsKeepTheInput(t *testing.T) {
	f := newPagesFixture(t)
	verr := port.NewValidationError()
	verr.Add("domain", "another tenant already uses this domain")
	f.tenants.CreateTenantMock.Return(nil, verr)

	rec := f.do(http.MethodPost, "/admin/tenants", url.Values{"name": {"New Co"}, "domain": {"acme.example.com"}}, htmx())

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "another tenant already uses this domain")
	assert.Contains(t, body, `value="New Co"`)
}
