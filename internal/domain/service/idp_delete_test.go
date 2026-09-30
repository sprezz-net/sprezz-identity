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

func (f *idpFixture) stubUsage(id uuid.UUID, users int, groups ...string) {
	f.admin.GetIdentityProviderUsageMock.Return([]model.IdentityProviderUsage{
		{ProviderID: id, LinkedUsers: users, GroupNames: groups},
	}, nil)
}

func TestDeleteIdentityProvider_SystemProviderIsRefused(t *testing.T) {
	f := newIDPFixture(t)
	system := storedOIDC()
	system.IsSystem = true
	f.stubStored(system)
	f.admin.DeleteIdentityProviderMock.Optional().Set(func(ctx context.Context, tID, id uuid.UUID) error {
		t.Error("a system provider must never reach storage deletion")
		return nil
	})

	err := f.svc.DeleteIdentityProvider(context.Background(), f.tenantID, system.ID)
	assert.ErrorIs(t, err, port.ErrSystemManaged)
}

func TestDeleteIdentityProvider_ProviderUsedByGroupIsRefused(t *testing.T) {
	f := newIDPFixture(t)
	p := storedOIDC()
	f.stubStored(p)
	f.stubUsage(p.ID, 3, "Staff")
	f.admin.DeleteIdentityProviderMock.Optional().Set(func(ctx context.Context, tID, id uuid.UUID) error {
		t.Error("a provider allowed by a group must not be deleted")
		return nil
	})

	err := f.svc.DeleteIdentityProvider(context.Background(), f.tenantID, p.ID)
	assert.ErrorIs(t, err, port.ErrInUse)
}

func TestDeleteIdentityProvider_UnusedProviderIsDeleted(t *testing.T) {
	f := newIDPFixture(t)
	p := storedOIDC()
	f.stubStored(p)
	f.stubUsage(p.ID, 0)
	f.admin.DeleteIdentityProviderMock.Return(nil)

	require.NoError(t, f.svc.DeleteIdentityProvider(context.Background(), f.tenantID, p.ID))
}

func TestDeleteIdentityProvider_UnknownProvider(t *testing.T) {
	f := newIDPFixture(t)
	f.storage.GetIdentityProviderByUUIDMock.Return(nil, port.ErrIdentityProviderNotFound)

	err := f.svc.DeleteIdentityProvider(context.Background(), f.tenantID, uuid.New())
	assert.ErrorIs(t, err, port.ErrIdentityProviderNotFound)
}

func TestDescribeIdentityProviderDeletion_ReportsImpact(t *testing.T) {
	f := newIDPFixture(t)
	id := uuid.New()
	f.stubUsage(id, 12, "Staff", "Contractors")

	impact, err := f.svc.DescribeIdentityProviderDeletion(context.Background(), f.tenantID, id)
	require.NoError(t, err)
	assert.Equal(t, 12, impact.LinkedUsers, "users who would lose this sign-in method")
	assert.Equal(t, []string{"Staff", "Contractors"}, impact.GroupNames)
}
