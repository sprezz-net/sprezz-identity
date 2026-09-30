package postgres

import (
	"context"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seedApplication(t *testing.T, s *PostgresStorage, tenantID uuid.UUID, clientID string, profileID, groupID uuid.UUID, system bool) {
	t.Helper()
	require.NoError(t, s.CreateApplication(context.Background(), tenantID, model.Application{
		ID: uuid.New(), TenantID: tenantID, ProfileID: profileID, GroupID: groupID,
		ApplicationName: clientID, ClientID: clientID, IsSystem: system,
	}))
}

func TestIntegration_DeleteGroupAndProfileHonourUsageAndSystemFlag(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "b.example.com", false)

	group := testGroupRow(tn.id, "g", false, tn.localIDP)
	profile := testProfileRow(tn.id, "p", false)
	require.NoError(t, s.CreateApplicationGroup(ctx, tn.id, group))
	require.NoError(t, s.CreateApplicationProfile(ctx, tn.id, profile))
	seedApplication(t, s, tn.id, "shop", profile.ID, group.ID, false)

	t.Run("usage listings", func(t *testing.T) {
		byGroup, err := s.GetApplicationsByGroup(ctx, tn.id, group.ID)
		require.NoError(t, err)
		require.Len(t, byGroup, 1)
		assert.Equal(t, "shop", byGroup[0].ClientID)
		assert.Equal(t, "g", byGroup[0].GroupName)
		assert.Equal(t, "p", byGroup[0].ProfileName)

		byProfile, err := s.GetApplicationsByProfile(ctx, tn.id, profile.ID)
		require.NoError(t, err)
		assert.Len(t, byProfile, 1)
	})

	t.Run("in use is reported as ErrInUse by the foreign key", func(t *testing.T) {
		assert.ErrorIs(t, s.DeleteApplicationGroup(ctx, tn.id, group.ID), port.ErrInUse)
		assert.ErrorIs(t, s.DeleteApplicationProfile(ctx, tn.id, profile.ID), port.ErrInUse)
	})

	t.Run("free objects are deleted", func(t *testing.T) {
		require.NoError(t, s.DeleteApplication(ctx, tn.id, "shop"))
		require.NoError(t, s.DeleteApplicationGroup(ctx, tn.id, group.ID))
		require.NoError(t, s.DeleteApplicationProfile(ctx, tn.id, profile.ID))

		_, err := s.GetApplicationGroupByID(ctx, tn.id, group.ID)
		assert.ErrorIs(t, err, port.ErrGroupNotFound)
		assert.ErrorIs(t, s.DeleteApplicationGroup(ctx, tn.id, group.ID), port.ErrGroupNotFound, "deleting twice reports not found")
	})

	t.Run("system objects are never deleted by SQL", func(t *testing.T) {
		sysGroup := testGroupRow(tn.id, "sys-g", true, tn.localIDP)
		sysProfile := testProfileRow(tn.id, "sys-p", true)
		require.NoError(t, s.CreateApplicationGroup(ctx, tn.id, sysGroup))
		require.NoError(t, s.CreateApplicationProfile(ctx, tn.id, sysProfile))

		assert.ErrorIs(t, s.DeleteApplicationGroup(ctx, tn.id, sysGroup.ID), port.ErrGroupNotFound)
		assert.ErrorIs(t, s.DeleteApplicationProfile(ctx, tn.id, sysProfile.ID), port.ErrProfileNotFound)

		got, err := s.GetApplicationGroupByID(ctx, tn.id, sysGroup.ID)
		require.NoError(t, err)
		assert.True(t, got.IsSystem)
	})
}

func TestIntegration_TenantIsolation(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	a := seedTenant(t, s, "iso-a.example.com", false)
	b := seedTenant(t, s, "iso-b.example.com", false)

	group := testGroupRow(a.id, "only-a", false, a.localIDP)
	require.NoError(t, s.CreateApplicationGroup(ctx, a.id, group))

	_, err := s.GetApplicationGroupByID(ctx, b.id, group.ID)
	assert.ErrorIs(t, err, port.ErrGroupNotFound, "another tenant cannot read the group")
	assert.ErrorIs(t, s.DeleteApplicationGroup(ctx, b.id, group.ID), port.ErrGroupNotFound, "another tenant cannot delete it")

	list, err := s.GetApplicationGroups(ctx, b.id)
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestIntegration_TenantDeleteNeverRemovesASystemTenant(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	system := seedTenant(t, s, "root.example.com", true)
	normal := seedTenant(t, s, "normal.example.com", false)

	assert.ErrorIs(t, s.DeleteTenant(ctx, system.id), port.ErrTenantNotFound, "the SQL guard refuses a system tenant")
	got, err := s.ResolveTenantByUUID(ctx, system.id)
	require.NoError(t, err)
	assert.True(t, got.IsSystem, "the flag round-trips through the tenant queries")

	require.NoError(t, s.DeleteTenant(ctx, normal.id))
	_, err = s.ResolveTenantByUUID(ctx, normal.id)
	assert.ErrorIs(t, err, port.ErrTenantNotFound)
}

func TestIntegration_TenantUpsertCanSetButNeverClearTheSystemFlag(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "ratchet.example.com", true)

	cleared := model.Tenant{
		ID: tn.id, Name: "renamed", Domain: "ratchet.example.com", IsActive: true, IsSystem: false, CreatedAt: time.Now(),
		Config: model.TenantConfig{PredefinedScopes: []string{}, PredefinedAudiences: []string{}, RedirectWhitelist: []string{}},
	}
	require.NoError(t, s.CreateTenant(ctx, cleared))

	got, err := s.ResolveTenantByUUID(ctx, tn.id)
	require.NoError(t, err)
	assert.Equal(t, "renamed", got.Name, "other fields are updated")
	assert.True(t, got.IsSystem, "an upsert cannot turn a system tenant into a normal one")
}
