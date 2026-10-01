package postgres

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The domain, not storage, decides that an inactive tenant is refused. Storage must therefore keep returning it, or
// the console could neither list the tenant nor switch it back on.
func TestIntegration_InactiveTenantIsStillReadableAndTheFlagRoundTrips(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "toggle.example.com", false)

	loaded, err := s.ResolveTenantByUUID(ctx, tn.id)
	require.NoError(t, err)
	assert.True(t, loaded.IsActive)

	loaded.IsActive = false
	require.NoError(t, s.CreateTenant(ctx, *loaded))

	byID, err := s.ResolveTenantByUUID(ctx, tn.id)
	require.NoError(t, err, "an inactive tenant can still be loaded by ID")
	assert.False(t, byID.IsActive)

	byDomain, err := s.ResolveTenantByDomain(ctx, "toggle.example.com")
	require.NoError(t, err, "and by domain, so the middleware can tell the tenant exists but is switched off")
	assert.False(t, byDomain.IsActive)

	all, err := s.GetAllTenants(ctx)
	require.NoError(t, err)
	found := false
	for _, tenant := range all {
		if tenant.ID == tn.id {
			found = true
			assert.False(t, tenant.IsActive)
		}
	}
	assert.True(t, found, "the console lists inactive tenants")

	loaded.IsActive = true
	require.NoError(t, s.CreateTenant(ctx, *loaded))
	again, err := s.ResolveTenantByUUID(ctx, tn.id)
	require.NoError(t, err)
	assert.True(t, again.IsActive, "reactivation round-trips")
}

func TestIntegration_PurgeEndsTheSessionsOfOnlyTheDeactivatedTenant(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	a := seedTenant(t, s, "a.purge.example.com", false)
	b := seedTenant(t, s, "b.purge.example.com", false)

	require.NoError(t, s.PurgeTenantSessionsAndTokens(ctx, a.id))
	require.NoError(t, s.PurgeTenantSessionsAndTokens(ctx, b.id), "purging an empty tenant is not an error")

	_, err := s.ResolveTenantByUUID(ctx, a.id)
	require.NoError(t, err, "purging sessions never removes the tenant")
}
