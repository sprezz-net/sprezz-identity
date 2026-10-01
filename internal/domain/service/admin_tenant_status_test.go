package service_test

import (
	"context"
	"errors"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (f *tenantFixture) status(target model.Tenant, acting model.Tenant, active bool) error {
	return f.svc.PatchTenant(context.Background(), port.PatchTenantCommand{
		TenantID: target.ID, ActingTenant: acting.ID, Section: port.TenantSectionStatus, Active: active,
	})
}

func TestStatus_DeactivationSavesAndEndsEverySession(t *testing.T) {
	f := newTenantFixture(t)
	saved := f.captureSave()
	var purged uuid.UUID
	f.storage.PurgeTenantSessionsAndTokensMock.Set(func(ctx context.Context, id uuid.UUID) error {
		purged = id
		return nil
	})

	require.NoError(t, f.status(f.acme, f.system, false))

	assert.False(t, saved.IsActive)
	assert.Equal(t, f.acme.ID, saved.ID)
	assert.Equal(t, 2, saved.Config.DefaultAAL, "the rest of the tenant is carried over unchanged")
	assert.Equal(t, "sealed", saved.Config.EncryptedAdminSecret)
	assert.Equal(t, f.acme.ID, purged, "live sessions and refresh tokens end now, not when they expire")
}

func TestStatus_ReactivationRestoresNothing(t *testing.T) {
	f := newTenantFixture(t)
	f.acme.IsActive = false
	saved := f.captureSave()
	f.storage.PurgeTenantSessionsAndTokensMock.Optional().Set(func(ctx context.Context, id uuid.UUID) error {
		t.Error("reactivating must not purge anything")
		return nil
	})

	require.NoError(t, f.status(f.acme, f.system, true))
	assert.True(t, saved.IsActive)
}

func TestStatus_NoChangeIsANoOp(t *testing.T) {
	f := newTenantFixture(t)
	f.forbidSave(t)
	f.storage.PurgeTenantSessionsAndTokensMock.Optional().Set(func(ctx context.Context, id uuid.UUID) error {
		t.Error("nothing changed, so nothing is purged")
		return nil
	})

	require.NoError(t, f.status(f.acme, f.system, true), "already active")
}

func TestStatus_OnlyTheAdministrativeTenantMayChangeIt(t *testing.T) {
	f := newTenantFixture(t)
	f.forbidSave(t)

	assert.ErrorIs(t, f.status(f.acme, f.acme, false), port.ErrForbidden, "a tenant cannot switch itself off")
	assert.ErrorIs(t, f.status(f.globex, f.acme, false), port.ErrForbidden, "a customer cannot switch another tenant off")
}

func TestStatus_TheAdministrativeTenantCanNeverBeDeactivated(t *testing.T) {
	f := newTenantFixture(t)
	f.forbidSave(t)

	assert.ErrorIs(t, f.status(f.system, f.system, false), port.ErrSystemManaged)

	other := f.globex
	other.IsSystem = true
	f.globex = other
	assert.ErrorIs(t, f.status(f.globex, f.system, false), port.ErrSystemManaged, "no system tenant can be switched off")
}

func TestStatus_APurgeFailureIsReportedAfterTheTenantIsAlreadyOff(t *testing.T) {
	f := newTenantFixture(t)
	saved := f.captureSave()
	f.storage.PurgeTenantSessionsAndTokensMock.Return(errors.New("connection reset"))

	err := f.status(f.acme, f.system, false)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "ending its sessions failed")
	assert.False(t, saved.IsActive, "the gate is already closed; only the cleanup needs a retry")
}

func TestStatus_AnInactiveActingTenantHasNoConsole(t *testing.T) {
	f := newTenantFixture(t)
	f.system.IsActive = false
	f.forbidSave(t)

	assert.ErrorIs(t, f.status(f.acme, f.system, false), port.ErrTenantInactive)

	_, err := f.svc.ListTenants(context.Background(), f.system.ID)
	assert.ErrorIs(t, err, port.ErrTenantInactive)
}
