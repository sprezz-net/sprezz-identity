package postgres

import (
	"context"
	"testing"

	"sprezz-identity/internal/domain/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func usageOf(t *testing.T, s *PostgresStorage, id string) model.TenantUsage {
	t.Helper()
	all, err := s.GetAllTenantUsage(context.Background())
	require.NoError(t, err)
	for _, u := range all {
		if u.TenantID.String() == id {
			return u
		}
	}
	t.Fatalf("no usage row for tenant %s", id)
	return model.TenantUsage{}
}

// The deletion dialog promises exact numbers, so they are checked against rows that really exist, per tenant.
func TestIntegration_TenantUsageCountsOnlyTheTenantsOwnRows(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	a := seedTenant(t, s, "a.usage.example.com", false)
	b := seedTenant(t, s, "b.usage.example.com", false)

	seedUser(t, s, a, "alice")
	seedUser(t, s, a, "bob")
	seedUser(t, s, b, "carol")
	require.NoError(t, s.CreateApplicationProfile(ctx, a.id, testProfileRow(a.id, "p1", false)))
	require.NoError(t, s.CreateApplicationGroup(ctx, a.id, testGroupRow(a.id, "g1", false, a.localIDP)))
	require.NoError(t, s.CreateApplicationGroup(ctx, a.id, testGroupRow(a.id, "g2", false, a.localIDP)))

	ua := usageOf(t, s, a.id.String())
	assert.Equal(t, 2, ua.Users)
	assert.Equal(t, 2, ua.Groups)
	assert.Equal(t, 1, ua.Profiles)
	assert.Equal(t, 2, ua.Providers, "the seeded local and federated providers")
	assert.Equal(t, 1, ua.Partitions, "the automatically created default partition")
	assert.Equal(t, 0, ua.Applications)

	ub := usageOf(t, s, b.id.String())
	assert.Equal(t, 1, ub.Users, "another tenant's rows are never counted")
	assert.Equal(t, 0, ub.Groups)
}

func TestIntegration_TenantUsageDropsToNothingAfterDeletion(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	a := seedTenant(t, s, "gone.usage.example.com", false)
	seedUser(t, s, a, "alice")

	require.NoError(t, s.DeleteTenant(ctx, a.id))

	all, err := s.GetAllTenantUsage(ctx)
	require.NoError(t, err)
	for _, u := range all {
		assert.NotEqual(t, a.id, u.TenantID, "a deleted tenant no longer appears")
	}
}

// Renaming through the console writes the whole tenant through the upsert, so the settings and the system flag the
// page never shows must come through it unchanged.
func TestIntegration_TenantSaveKeepsConfigAndSystemFlag(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "keep.example.com", false)

	loaded, err := s.ResolveTenantByUUID(ctx, tn.id)
	require.NoError(t, err)
	loaded.Config.DefaultAAL = 3
	loaded.Config.ACREssential = true
	loaded.Config.ACRToLevels = map[string]model.Levels{"gold": {AAL: 3}}
	require.NoError(t, s.CreateTenant(ctx, *loaded))

	loaded.Name = "Renamed"
	require.NoError(t, s.CreateTenant(ctx, *loaded))

	again, err := s.ResolveTenantByUUID(ctx, tn.id)
	require.NoError(t, err)
	assert.Equal(t, "Renamed", again.Name)
	assert.Equal(t, 3, again.Config.DefaultAAL)
	assert.True(t, again.Config.ACREssential)
	assert.Equal(t, map[string]model.Levels{"gold": {AAL: 3}}, again.Config.ACRToLevels)
}
