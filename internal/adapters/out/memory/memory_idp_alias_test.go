package memory

import (
	"context"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func provider(tenantID uuid.UUID, alias, idpType string, partition int64) model.IdentityProvider {
	return model.IdentityProvider{ID: uuid.New(), TenantID: tenantID, Alias: alias, IDPType: idpType, PartitionID: partition, Enabled: true}
}

func TestGetIdentityProviderByAlias_FindsTheProviderOfTheTenant(t *testing.T) {
	s := NewStorage("production")
	ctx := context.Background()
	tenantID := uuid.New()
	admin := provider(tenantID, model.AdminSSOAliasName, model.OpenIDConnectIDPType, 3)
	require.NoError(t, s.CreateIdentityProvider(ctx, tenantID, admin))
	require.NoError(t, s.CreateIdentityProvider(ctx, tenantID, provider(tenantID, "corp", model.OpenIDConnectIDPType, 1)))

	got, err := s.GetIdentityProviderByAlias(ctx, tenantID, model.AdminSSOAliasName)

	require.NoError(t, err)
	assert.Equal(t, admin.ID, got.ID)
	assert.Equal(t, int64(3), got.PartitionID)
}

func TestGetIdentityProviderByAlias_AMissIsAnErrorNeverANilProvider(t *testing.T) {
	s := NewStorage("production")
	tenantID := uuid.New()

	got, err := s.GetIdentityProviderByAlias(context.Background(), tenantID, "nope")

	require.ErrorIs(t, err, port.ErrIdentityProviderNotFound)
	assert.Nil(t, got)
}

func TestGetIdentityProviderByAlias_NeverCrossesTenants(t *testing.T) {
	s := NewStorage("production")
	ctx := context.Background()
	a, b := uuid.New(), uuid.New()
	require.NoError(t, s.CreateIdentityProvider(ctx, a, provider(a, "shared-name", model.OpenIDConnectIDPType, 1)))

	_, err := s.GetIdentityProviderByAlias(ctx, b, "shared-name")

	require.ErrorIs(t, err, port.ErrIdentityProviderNotFound)
}

func TestGetIdentityProviderByAlias_ReturnsACopy(t *testing.T) {
	s := NewStorage("production")
	ctx := context.Background()
	tenantID := uuid.New()
	require.NoError(t, s.CreateIdentityProvider(ctx, tenantID, provider(tenantID, "corp", model.OpenIDConnectIDPType, 1)))

	first, _ := s.GetIdentityProviderByAlias(ctx, tenantID, "corp")
	first.Enabled = false
	second, _ := s.GetIdentityProviderByAlias(ctx, tenantID, "corp")

	assert.True(t, second.Enabled, "changing a result must not change the store")
}

// The store enforces the same tenant-wide alias key as the database.
func TestCreateIdentityProvider_AliasIsUniqueInTheTenant(t *testing.T) {
	s := NewStorage("production")
	ctx := context.Background()
	tenantID, other := uuid.New(), uuid.New()
	require.NoError(t, s.CreateIdentityProvider(ctx, tenantID, provider(tenantID, "corp", model.OpenIDConnectIDPType, 1)))

	for name, clash := range map[string]model.IdentityProvider{
		"another type":      provider(tenantID, "corp", model.UsernamePasswordIDPType, 1),
		"another partition": provider(tenantID, "corp", model.OpenIDConnectIDPType, 2),
		"both":              provider(tenantID, "corp", model.UsernamePasswordIDPType, 2),
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, s.CreateIdentityProvider(ctx, tenantID, clash), port.ErrAliasAlreadyExists)
		})
	}

	require.NoError(t, s.CreateIdentityProvider(ctx, other, provider(other, "corp", model.OpenIDConnectIDPType, 1)), "another tenant may use the alias")
}

func TestCreateIdentityProvider_SavingTheSameProviderAgainIsAnUpdate(t *testing.T) {
	s := NewStorage("production")
	ctx := context.Background()
	tenantID := uuid.New()
	p := provider(tenantID, "corp", model.OpenIDConnectIDPType, 1)
	require.NoError(t, s.CreateIdentityProvider(ctx, tenantID, p))

	p.Name = "Renamed"
	require.NoError(t, s.CreateIdentityProvider(ctx, tenantID, p), "the same id keeps its alias")

	// The SQL upsert resolves a provider by (tenant, partition, type, alias), so a new id for the same key replaces it.
	replacement := provider(tenantID, "corp", model.OpenIDConnectIDPType, 1)
	require.NoError(t, s.CreateIdentityProvider(ctx, tenantID, replacement))
}
