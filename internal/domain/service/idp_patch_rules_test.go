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

func TestPatchIdentityProvider_InvalidContentIsNeverStored(t *testing.T) {
	f := newIDPFixture(t)
	before := storedOIDC()
	f.stubStored(before)
	f.admin.CreateIdentityProviderMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, p model.IdentityProvider) error {
		t.Error("an invalid provider must not be stored")
		return nil
	})

	err := f.svc.PatchIdentityProvider(context.Background(), port.PatchIdentityProviderCommand{
		TenantID: f.tenantID, ID: before.ID, Section: port.IDPSectionConnection,
		DiscoveryEndpoint: "http://insecure.example.com", Issuer: "https://idp.example.com", AuthenticationMethod: "client_secret_basic",
	})

	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr.Fields, "discovery_endpoint")
}

func TestPatchIdentityProvider_SystemProviderIsRefused(t *testing.T) {
	f := newIDPFixture(t)
	system := storedOIDC()
	system.IsSystem = true
	f.stubStored(system)

	err := f.svc.PatchIdentityProvider(context.Background(), port.PatchIdentityProviderCommand{
		TenantID: f.tenantID, ID: system.ID, Section: port.IDPSectionGeneral, Name: "x",
	})
	assert.ErrorIs(t, err, port.ErrSystemManaged)
}

func TestPatchIdentityProvider_UnknownSection(t *testing.T) {
	f := newIDPFixture(t)
	p := storedOIDC()
	f.stubStored(p)

	err := f.svc.PatchIdentityProvider(context.Background(), port.PatchIdentityProviderCommand{TenantID: f.tenantID, ID: p.ID, Section: "bogus"})

	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
}

func TestUpdateIdentityProvider_CannotChangeAliasTypeOrPartition(t *testing.T) {
	f := newIDPFixture(t)
	before := storedOIDC()
	f.stubStored(before)
	saved := f.captureSave()

	edited := before
	edited.Alias, edited.PartitionID, edited.IDPType = "hijack", 99, model.UsernamePasswordIDPType
	edited.IsSystem = true

	_, err := f.svc.UpdateIdentityProvider(context.Background(), f.tenantID, edited)
	require.NoError(t, err)
	assert.Equal(t, before.Alias, saved.Alias, "the conflict key is taken from the stored provider")
	assert.Equal(t, before.PartitionID, saved.PartitionID)
	assert.Equal(t, before.IDPType, saved.IDPType)
	assert.False(t, saved.IsSystem, "an update can never flag a provider as system-managed")
}

func TestCreateIdentityProvider_Rules(t *testing.T) {
	t.Run("a second local provider in a partition is refused", func(t *testing.T) {
		f := newIDPFixture(t)
		f.storage.GetIdentityProvidersMock.Return([]model.IdentityProvider{
			{ID: uuid.New(), IDPType: model.UsernamePasswordIDPType, PartitionID: 1, Alias: "username-password"},
		}, nil)
		f.admin.CreateIdentityProviderMock.Optional().Return(nil)

		_, err := f.svc.CreateIdentityProvider(context.Background(), f.tenantID, model.IdentityProvider{
			Name: "Local 2", Alias: "local-2", IDPType: model.UsernamePasswordIDPType, PartitionID: 1,
		})

		var verr *port.ValidationError
		require.ErrorAs(t, err, &verr)
		assert.Contains(t, verr.Fields, "idp_type")
	})

	t.Run("a duplicate alias is refused", func(t *testing.T) {
		f := newIDPFixture(t)
		existing := storedOIDC()
		f.storage.GetIdentityProvidersMock.Return([]model.IdentityProvider{existing}, nil)

		dup := storedOIDC()
		_, err := f.svc.CreateIdentityProvider(context.Background(), f.tenantID, dup)

		var verr *port.ValidationError
		require.ErrorAs(t, err, &verr)
		assert.Contains(t, verr.Fields, "alias")
	})

	t.Run("the admin use case can never create a system provider", func(t *testing.T) {
		f := newIDPFixture(t)
		f.storage.GetIdentityProvidersMock.Return(nil, nil)
		saved := f.captureSave()

		input := storedOIDC()
		input.IsSystem = true
		created, err := f.svc.CreateIdentityProvider(context.Background(), f.tenantID, input)
		require.NoError(t, err)
		assert.False(t, created.IsSystem)
		assert.False(t, saved.IsSystem)
		assert.NotEqual(t, input.ID, created.ID, "the ID is always generated")
	})

	t.Run("new local providers get secure defaults", func(t *testing.T) {
		f := newIDPFixture(t)
		f.storage.GetIdentityProvidersMock.Return(nil, nil)
		saved := f.captureSave()

		_, err := f.svc.CreateIdentityProvider(context.Background(), f.tenantID, model.IdentityProvider{
			Name: "Local", Alias: "username-password", IDPType: model.UsernamePasswordIDPType, PartitionID: 1,
		})
		require.NoError(t, err)
		assert.Equal(t, 5, saved.Config.MaxFailedVerificationCount)
		assert.Equal(t, 900, saved.Config.PasswordBlockedTime)
		assert.Equal(t, 1, saved.Config.AAL)
	})
}
