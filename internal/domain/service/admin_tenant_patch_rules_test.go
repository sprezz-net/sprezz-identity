package service_test

import (
	"context"
	"testing"

	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPatchTenant_DomainMustBeFree(t *testing.T) {
	f := newTenantFixture(t)
	f.forbidSave(t)
	f.storage.ResolveTenantByDomainMock.Return(&f.globex, nil)

	err := f.svc.PatchTenant(context.Background(), port.PatchTenantCommand{
		TenantID: f.acme.ID, ActingTenant: f.acme.ID, Section: port.TenantSectionGeneral, Name: "Acme", Domain: "globex.example.com",
	})
	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr.Fields["domain"], "already uses")
}

func TestPatchTenant_NonSystemTenantsCannotEditOthers(t *testing.T) {
	f := newTenantFixture(t)
	f.forbidSave(t)

	err := f.svc.PatchTenant(context.Background(), port.PatchTenantCommand{
		TenantID: f.globex.ID, ActingTenant: f.acme.ID, Section: port.TenantSectionGeneral, Name: "Hijacked", Domain: "globex.example.com",
	})
	assert.ErrorIs(t, err, port.ErrForbidden)

	err = f.svc.PatchTenant(context.Background(), port.PatchTenantCommand{TenantID: uuid.New(), ActingTenant: f.acme.ID, Section: port.TenantSectionGeneral})
	assert.ErrorIs(t, err, port.ErrForbidden)
}

func TestPatchTenant_SystemTenantCanEditOthers(t *testing.T) {
	f := newTenantFixture(t)
	f.storage.ResolveTenantByDomainMock.Optional().Return(&f.globex, nil)
	saved := f.captureSave()

	require.NoError(t, f.svc.PatchTenant(context.Background(), port.PatchTenantCommand{
		TenantID: f.globex.ID, ActingTenant: f.system.ID, Section: port.TenantSectionGeneral, Name: "Globex Inc", Domain: "globex.example.com",
	}))
	assert.Equal(t, f.globex.ID, saved.ID)
	assert.Equal(t, "Globex Inc", saved.Name)
}

func TestPatchTenant_SystemTenantKeepsItsDomainAndAdminRedirects(t *testing.T) {
	f := newTenantFixture(t)
	f.forbidSave(t)
	f.system.Config.RedirectWhitelist = []string{"https://admin.example.com/admin", "https://admin.example.com/oauth/federation/callback"}

	err := f.svc.PatchTenant(context.Background(), port.PatchTenantCommand{
		TenantID: f.system.ID, ActingTenant: f.system.ID, Section: port.TenantSectionGeneral, Name: "Renamed", Domain: "other.example.com",
	})
	assert.ErrorIs(t, err, port.ErrSystemManaged, "the domain of the administrative tenant is fixed")

	err = f.svc.PatchTenant(context.Background(), port.PatchTenantCommand{
		TenantID: f.system.ID, ActingTenant: f.system.ID, Section: port.TenantSectionRedirects,
		RedirectWhitelist: []string{"https://admin.example.com/admin"},
	})
	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr.Fields["redirect_whitelist"], "must keep", "the console must not be able to lock itself out")
}

func TestPatchTenant_SystemTenantMayStillBeRenamed(t *testing.T) {
	f := newTenantFixture(t)
	saved := f.captureSave()

	require.NoError(t, f.svc.PatchTenant(context.Background(), port.PatchTenantCommand{
		TenantID: f.system.ID, ActingTenant: f.system.ID, Section: port.TenantSectionGeneral, Name: "Platform", Domain: "admin.example.com",
	}))
	assert.Equal(t, "Platform", saved.Name)
	assert.True(t, saved.IsSystem)
}

func TestPatchTenant_SignupDelegatesSoClosingKeepsItsSideEffect(t *testing.T) {
	f := newTenantFixture(t)
	f.forbidSave(t)
	f.tenants.ToggleSignupMock.Expect(context.Background(), f.acme.ID, false).Return(&f.acme, nil)

	require.NoError(t, f.svc.PatchTenant(context.Background(), port.PatchTenantCommand{
		TenantID: f.acme.ID, ActingTenant: f.acme.ID, Section: port.TenantSectionSignup, AllowSignup: false,
	}))
}
