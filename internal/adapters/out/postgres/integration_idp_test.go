package postgres

import (
	"context"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_IdentityProviderDeleteHonoursGroupsSystemFlagAndLinks(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "idp.example.com", false)

	group := testGroupRow(tn.id, "staff", false, tn.ssoIDP)
	require.NoError(t, s.CreateApplicationGroup(ctx, tn.id, group))

	t.Run("a provider allowed by a group is reported as in use", func(t *testing.T) {
		assert.ErrorIs(t, s.DeleteIdentityProvider(ctx, tn.id, tn.ssoIDP), port.ErrInUse)
		_, err := s.GetIdentityProviderByUUID(ctx, tn.id, tn.ssoIDP)
		require.NoError(t, err, "the provider is still there")
	})

	t.Run("usage lists the allowing groups", func(t *testing.T) {
		usage, err := s.GetIdentityProviderUsage(ctx, tn.id)
		require.NoError(t, err)
		byID := map[uuid.UUID]model.IdentityProviderUsage{}
		for _, u := range usage {
			byID[u.ProviderID] = u
		}
		assert.Equal(t, []string{"staff"}, byID[tn.ssoIDP].GroupNames)
		assert.Empty(t, byID[tn.localIDP].GroupNames)
		assert.Equal(t, 0, byID[tn.localIDP].LinkedUsers)
		assert.Nil(t, byID[tn.localIDP].LastLoginAt)
	})

	t.Run("a provider that nothing uses is deleted, and deleting twice reports not found", func(t *testing.T) {
		require.NoError(t, s.DeleteIdentityProvider(ctx, tn.id, tn.localIDP))
		assert.ErrorIs(t, s.DeleteIdentityProvider(ctx, tn.id, tn.localIDP), port.ErrIdentityProviderNotFound)
	})
}

func TestIntegration_SystemIdentityProviderIsNeverDeletedBySQL(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "sys.example.com", false)

	system := model.IdentityProvider{
		ID: uuid.New(), TenantID: tn.id, IDPType: model.OpenIDConnectIDPType, Enabled: true, Alias: "admin-sso",
		Name: "Administrative SSO", PartitionID: tn.partition, Issuer: "https://sys.example.com", IsSystem: true,
	}
	require.NoError(t, s.CreateIdentityProvider(ctx, tn.id, system))

	assert.ErrorIs(t, s.DeleteIdentityProvider(ctx, tn.id, system.ID), port.ErrIdentityProviderNotFound)
	got, err := s.GetIdentityProviderByUUID(ctx, tn.id, system.ID)
	require.NoError(t, err)
	assert.True(t, got.IsSystem)

	t.Run("an upsert can never clear the flag", func(t *testing.T) {
		system.IsSystem = false
		system.Name = "Renamed"
		require.NoError(t, s.CreateIdentityProvider(ctx, tn.id, system))
		got, err := s.GetIdentityProviderByUUID(ctx, tn.id, system.ID)
		require.NoError(t, err)
		assert.True(t, got.IsSystem, "the flag is a one-way ratchet")
		assert.Equal(t, "Renamed", got.Name)
	})

	t.Run("the flag is returned by every read path", func(t *testing.T) {
		all, err := s.GetIdentityProviders(ctx, tn.id)
		require.NoError(t, err)
		flagged := 0
		for _, p := range all {
			if p.IsSystem {
				flagged++
			}
		}
		assert.Equal(t, 1, flagged)
	})
}

func TestIntegration_Migration00030FlagsExistingBootstrapProviders(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	admin := seedTenant(t, s, "admin.example.com", true)
	customer := seedTenant(t, s, "customer.example.com", false)

	// Rows written before the migration carry no flag; apply its UPDATE to them the way an upgrade does.
	_, err := s.pool.Exec(ctx, `UPDATE identity_providers SET is_system = FALSE`)
	require.NoError(t, err)
	_, err = s.pool.Exec(ctx, `
		UPDATE identity_providers SET is_system = TRUE
		WHERE (alias_name = 'admin-sso' AND idp_type = 'oidc')
		   OR (idp_type = 'username-password' AND tenant_id IN (SELECT id FROM tenants WHERE is_system))`)
	require.NoError(t, err)

	adminLocal, err := s.GetIdentityProviderByUUID(ctx, admin.id, admin.localIDP)
	require.NoError(t, err)
	assert.True(t, adminLocal.IsSystem, "the admin tenant's local provider is protected")

	customerLocal, err := s.GetIdentityProviderByUUID(ctx, customer.id, customer.localIDP)
	require.NoError(t, err)
	assert.False(t, customerLocal.IsSystem, "a customer tenant's local provider stays editable")

	customerSSO, err := s.GetIdentityProviderByUUID(ctx, customer.id, customer.ssoIDP)
	require.NoError(t, err)
	assert.False(t, customerSSO.IsSystem, "only admin-sso is protected, not other federated providers")
}
