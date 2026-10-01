package service_test

import (
	"context"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListTenants_SystemSeesEveryoneOthersSeeOnlyThemselves(t *testing.T) {
	f := newTenantFixture(t)
	f.admin.GetAllTenantsMock.Return(f.all(), nil)

	all, err := f.svc.ListTenants(context.Background(), f.system.ID)
	require.NoError(t, err)
	names := []string{}
	for _, d := range all {
		names = append(names, d.Tenant.Name)
	}
	assert.Equal(t, []string{"Acme", "Administrative Tenant", "Globex"}, names, "sorted by name")
	assert.Equal(t, 5, all[0].Usage.Users, "usage is attached to the right tenant")

	own, err := f.svc.ListTenants(context.Background(), f.acme.ID)
	require.NoError(t, err)
	require.Len(t, own, 1)
	assert.Equal(t, f.acme.ID, own[0].Tenant.ID)
}

func TestGetTenant_NonSystemTenantsCannotReadOthers(t *testing.T) {
	f := newTenantFixture(t)

	_, err := f.svc.GetTenant(context.Background(), f.acme.ID, f.globex.ID)
	assert.ErrorIs(t, err, port.ErrForbidden)

	_, err = f.svc.GetTenant(context.Background(), f.acme.ID, uuid.New())
	assert.ErrorIs(t, err, port.ErrForbidden, "an unknown ID looks the same as a foreign one, so IDs cannot be probed")

	own, err := f.svc.GetTenant(context.Background(), f.acme.ID, f.acme.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, own.Usage.Applications)

	other, err := f.svc.GetTenant(context.Background(), f.system.ID, f.globex.ID)
	require.NoError(t, err)
	assert.Equal(t, "Globex", other.Tenant.Name)

	_, err = f.svc.GetTenant(context.Background(), f.system.ID, uuid.New())
	assert.ErrorIs(t, err, port.ErrTenantNotFound, "the system tenant gets an honest not-found")
}

func TestDeleteTenant_OnlyTheSystemTenantMayDelete(t *testing.T) {
	f := newTenantFixture(t)
	f.tenants.DeleteTenantMock.Optional().Set(func(ctx context.Context, cmd port.DeleteTenantCommand) error {
		assert.Equal(t, f.system.ID, cmd.ActingTenantID)
		return nil
	})

	err := f.svc.DeleteTenant(context.Background(), port.DeleteTenantCommand{TenantID: f.globex.ID, ActingTenantID: f.acme.ID, Confirmation: f.globex.Domain})
	assert.ErrorIs(t, err, port.ErrForbidden, "a customer tenant cannot delete another tenant")

	require.NoError(t, f.svc.DeleteTenant(context.Background(), port.DeleteTenantCommand{TenantID: f.globex.ID, ActingTenantID: f.system.ID, Confirmation: f.globex.Domain}))
}

func TestCreateTenant_OnlyTheSystemTenantMayCreate(t *testing.T) {
	f := newTenantFixture(t)
	f.storage.ResolveTenantByDomainMock.Return(nil, port.ErrTenantNotFound)
	var got port.CreateTenantCommand
	f.tenants.CreateTenantMock.Set(func(ctx context.Context, cmd port.CreateTenantCommand) (*model.Tenant, error) {
		got = cmd
		return &model.Tenant{ID: uuid.New(), Name: cmd.TenantName, Domain: cmd.DomainName, IsActive: true}, nil
	})

	_, err := f.svc.CreateTenant(context.Background(), port.CreateTenantFromConsoleCommand{ActingTenant: f.acme.ID, Name: "Evil", Domain: "evil.example.com"})
	assert.ErrorIs(t, err, port.ErrForbidden)

	_, err = f.svc.CreateTenant(context.Background(), port.CreateTenantFromConsoleCommand{ActingTenant: f.system.ID, Name: " New Co ", Domain: " NEW.Example.com "})
	require.NoError(t, err)
	assert.Equal(t, "New Co", got.TenantName, "input is trimmed")
	assert.Equal(t, "new.example.com", got.DomainName, "the domain is normalized to lower case")
}

func TestCreateTenant_ValidationAndDuplicateDomain(t *testing.T) {
	f := newTenantFixture(t)
	f.tenants.CreateTenantMock.Optional().Set(func(ctx context.Context, cmd port.CreateTenantCommand) (*model.Tenant, error) {
		t.Error("an invalid tenant must not be created")
		return nil, nil
	})

	_, err := f.svc.CreateTenant(context.Background(), port.CreateTenantFromConsoleCommand{ActingTenant: f.system.ID, Name: "", Domain: "https://x.example.com"})
	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr.Fields, "name")
	assert.Contains(t, verr.Fields, "domain")

	f.storage.ResolveTenantByDomainMock.Return(&f.acme, nil)
	_, err = f.svc.CreateTenant(context.Background(), port.CreateTenantFromConsoleCommand{ActingTenant: f.system.ID, Name: "Dup", Domain: "acme.example.com"})
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr.Fields["domain"], "already uses")
}
