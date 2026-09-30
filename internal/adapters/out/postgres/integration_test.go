package postgres

import (
	"context"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newIntegrationStorage connects to the database named by SPREZZ_TEST_DATABASE_URL, applies every migration to a
// fresh schema and returns a storage on it. The test is skipped when the variable is not set, so the normal
// `make test` needs no database.
//
//	docker run -d --rm -e POSTGRES_USER=it -e POSTGRES_PASSWORD=it -e POSTGRES_DB=it -p 55432:5432 postgres:18-alpine
//	SPREZZ_TEST_DATABASE_URL=postgres://it:it@localhost:55432/it make test
func newIntegrationStorage(t *testing.T) *PostgresStorage {
	t.Helper()
	ctx := context.Background()
	pool, cleanup := newSchemaPool(t, ctx, integrationURL(t))
	t.Cleanup(cleanup)

	require.NoError(t, RunDatabaseMigrations(ctx, pool))
	return NewPostgresStorage(pool, "unittest")
}

type seededTenant struct {
	id        uuid.UUID
	partition int64
	localIDP  uuid.UUID
	ssoIDP    uuid.UUID
}

// seedTenant creates a tenant with its default partition, a local provider and one federated provider.
func seedTenant(t *testing.T, s *PostgresStorage, domain string, system bool) seededTenant {
	t.Helper()
	ctx := context.Background()
	tenant := model.Tenant{
		ID: uuid.New(), Name: domain, Domain: domain, IsActive: true, IsSystem: system, CreatedAt: time.Now(),
		Config: model.TenantConfig{PredefinedScopes: []string{"openid"}, PredefinedAudiences: []string{}, RedirectWhitelist: []string{}},
	}
	require.NoError(t, s.CreateTenant(ctx, tenant))

	parts, err := s.GetPartitions(ctx, tenant.ID)
	require.NoError(t, err)
	require.NotEmpty(t, parts)

	local := model.IdentityProvider{ID: uuid.New(), TenantID: tenant.ID, IDPType: model.UsernamePasswordIDPType, Enabled: true, Alias: "username-password", Name: "Local", PartitionID: parts[0].ID}
	sso := model.IdentityProvider{ID: uuid.New(), TenantID: tenant.ID, IDPType: model.OpenIDConnectIDPType, Enabled: true, Alias: "corp", Name: "Corp", PartitionID: parts[0].ID, Issuer: "https://" + domain + "/idp"}
	require.NoError(t, s.CreateIdentityProvider(ctx, tenant.ID, local))
	require.NoError(t, s.CreateIdentityProvider(ctx, tenant.ID, sso))
	return seededTenant{id: tenant.ID, partition: parts[0].ID, localIDP: local.ID, ssoIDP: sso.ID}
}

func testProfileRow(tenantID uuid.UUID, name string, system bool) model.ApplicationProfile {
	return model.ApplicationProfile{
		ID: uuid.New(), TenantID: tenantID, ProfileName: name, IsEnabled: true, IsSystem: system,
		TokenEndpointAuthMethod: model.AuthMethodClientSecretPost, SigningAlgorithm: model.AlgRS256,
		GrantTypes: []model.GrantType{model.GrantTypeAuthorizationCode}, ResponseTypes: []model.ResponseType{model.ResponseTypeCode},
		AccessTokenLifetime: 15 * time.Minute, IDTokenLifetime: 15 * time.Minute, RefreshTokenLifetime: 24 * time.Hour,
	}
}

func testGroupRow(tenantID uuid.UUID, name string, system bool, idps ...uuid.UUID) model.ApplicationGroup {
	return model.ApplicationGroup{
		ID: uuid.New(), TenantID: tenantID, GroupName: name, IsEnabled: true, IsSystem: system,
		RedirectURI: "https://a.example.com/cb", RedirectURIs: []string{"https://a.example.com/cb"},
		PostLogoutRedirectURIs: []string{"https://a.example.com/bye"},
		FrontChannelLogoutURI:  "https://a.example.com/front", BackChannelLogoutURI: "https://a.example.com/back",
		AllowedScopes: []string{"openid", "email"}, DefaultScopes: []string{"openid"}, AllowedAudiences: []string{},
		AllowedIDPIDs: idps, DefaultIDPID: &idps[0],
	}
}

func TestIntegration_GroupRoundTripKeepsEveryField(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "a.example.com", false)

	want := testGroupRow(tn.id, "partners", false, tn.localIDP, tn.ssoIDP)
	require.NoError(t, s.CreateApplicationGroup(ctx, tn.id, want))

	got, err := s.GetApplicationGroupByID(ctx, tn.id, want.ID)
	require.NoError(t, err)
	assert.Equal(t, want.RedirectURI, got.RedirectURI, "the default redirect URI is persisted")
	assert.Equal(t, want.RedirectURIs, got.RedirectURIs)
	assert.Equal(t, want.FrontChannelLogoutURI, got.FrontChannelLogoutURI)
	assert.Equal(t, want.BackChannelLogoutURI, got.BackChannelLogoutURI)
	assert.ElementsMatch(t, want.AllowedIDPIDs, got.AllowedIDPIDs, "the local provider is stored as a real UUID")
	assert.False(t, got.IsSystem)

	want.GroupName = "renamed"
	want.RedirectURI = "https://b.example.com/cb"
	want.RedirectURIs = []string{"https://b.example.com/cb"}
	want.BackChannelLogoutURI = ""
	want.AllowedIDPIDs = []uuid.UUID{tn.ssoIDP}
	require.NoError(t, s.UpdateApplicationGroup(ctx, tn.id, want))

	got, err = s.GetApplicationGroupByID(ctx, tn.id, want.ID)
	require.NoError(t, err)
	assert.Equal(t, "renamed", got.GroupName)
	assert.Equal(t, "https://b.example.com/cb", got.RedirectURI)
	assert.Empty(t, got.BackChannelLogoutURI, "a cleared field is persisted as cleared")
	assert.Equal(t, []uuid.UUID{tn.ssoIDP}, got.AllowedIDPIDs)

	list, err := s.GetApplicationGroups(ctx, tn.id)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "https://b.example.com/cb", list[0].RedirectURI, "the list query returns the same fields")
}
