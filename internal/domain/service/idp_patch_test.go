package service_test

import (
	"context"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The bug this guards against: the old handler rebuilt the whole config from the posted form, so every save wiped
// the settings the form did not contain.
func TestPatchIdentityProvider_UnseenConfigurationSurvivesEverySection(t *testing.T) {
	sections := []port.PatchIdentityProviderCommand{
		{Section: port.IDPSectionGeneral, Name: "Renamed", Enabled: true},
		{Section: port.IDPSectionCredentials, ClientID: "sprezz"},
		{Section: port.IDPSectionAssurance, AAL: 2, IAL: 2, AcrToTuple: map[string]model.AcrTuple{"gold": {AAL: 3, IAL: 2}}},
	}

	for _, cmd := range sections {
		t.Run(string(cmd.Section), func(t *testing.T) {
			f := newIDPFixture(t)
			before := storedOIDC()
			f.stubStored(before)
			saved := f.captureSave()

			cmd.TenantID, cmd.ID = f.tenantID, before.ID
			require.NoError(t, f.svc.PatchIdentityProvider(context.Background(), cmd))

			assert.Equal(t, []string{"example.com"}, saved.Config.DomainAliases, "domain aliases are kept")
			assert.True(t, saved.Config.AutoProvisionUser)
			assert.True(t, saved.Config.AutoVerifyEmail)
			assert.True(t, saved.Config.AllowDecoupling)
			assert.True(t, saved.Config.PkceEnabled)
			assert.Equal(t, "sub", saved.Config.UserIdentifierClaim)
			assert.Equal(t, "https://idp.example.com", saved.Issuer)
			assert.Equal(t, before.Alias, saved.Alias, "the alias is never changed by a patch")
			assert.Equal(t, before.PartitionID, saved.PartitionID)
			assert.Equal(t, before.IDPType, saved.IDPType)
		})
	}
}

func TestPatchIdentityProvider_CredentialsSecretIsWriteOnly(t *testing.T) {
	f := newIDPFixture(t)
	before := storedOIDC()
	f.stubStored(before)
	saved := f.captureSave()

	t.Run("an empty secret keeps the stored one", func(t *testing.T) {
		require.NoError(t, f.svc.PatchIdentityProvider(context.Background(), port.PatchIdentityProviderCommand{
			TenantID: f.tenantID, ID: before.ID, Section: port.IDPSectionCredentials, ClientID: "new-client",
		}))
		assert.Equal(t, "new-client", saved.Config.ClientID)
		assert.Equal(t, "s3cret", saved.Config.ClientSecret)
	})

	t.Run("a new secret replaces it", func(t *testing.T) {
		require.NoError(t, f.svc.PatchIdentityProvider(context.Background(), port.PatchIdentityProviderCommand{
			TenantID: f.tenantID, ID: before.ID, Section: port.IDPSectionCredentials, ClientID: "sprezz", ClientSecret: "rotated",
		}))
		assert.Equal(t, "rotated", saved.Config.ClientSecret)
	})

	t.Run("clearing is refused while the client needs a secret", func(t *testing.T) {
		err := f.svc.PatchIdentityProvider(context.Background(), port.PatchIdentityProviderCommand{
			TenantID: f.tenantID, ID: before.ID, Section: port.IDPSectionCredentials, ClientID: "sprezz", ClearSecret: true,
		})
		var verr *port.ValidationError
		require.ErrorAs(t, err, &verr)
		assert.Contains(t, verr.Fields, "client_secret")
	})
}

func TestPatchIdentityProvider_SectionFieldsLandWhereExpected(t *testing.T) {
	f := newIDPFixture(t)
	before := storedOIDC()
	f.stubStored(before)
	saved := f.captureSave()

	require.NoError(t, f.svc.PatchIdentityProvider(context.Background(), port.PatchIdentityProviderCommand{
		TenantID: f.tenantID, ID: before.ID, Section: port.IDPSectionBehavior,
		Scopes: []string{"openid", "profile"}, UserIdentifierClaim: "email", DomainAliases: []string{"corp.example.com"},
		AutoProvisionUser: false, AutoVerifyEmail: true,
	}))
	assert.Equal(t, []string{"openid", "profile"}, saved.Config.Scopes)
	assert.Equal(t, "email", saved.Config.UserIdentifierClaim)
	assert.Equal(t, []string{"corp.example.com"}, saved.Config.DomainAliases)
	assert.False(t, saved.Config.AutoProvisionUser)
	assert.Equal(t, "s3cret", saved.Config.ClientSecret, "other sections are untouched")
}
