package postgres

import (
	"context"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
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

func newAliasProvider(tn seededTenant, alias, idpType string, partition int64) model.IdentityProvider {
	return model.IdentityProvider{
		ID: uuid.New(), TenantID: tn.id, IDPType: idpType, Enabled: true, Alias: alias, Name: alias, PartitionID: partition,
		// Unique per provider (tenant, partition and issuer are a key of their own), so only the alias can clash.
		Issuer: "https://" + uuid.NewString() + ".example.com",
	}
}

// idp_hint, the login page and the console resolve a provider by alias alone, so the database keeps the alias
// unique in the whole tenant, whatever the type or the partition.
func TestIntegration_ProviderAliasIsUniqueInTheWholeTenant(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "alias.example.com", false) // providers "username-password" and "corp" in the default partition
	other := seedTenant(t, s, "other.alias.example.com", false)

	extraPartition, err := s.CreatePartition(ctx, tn.id, "Second", "second")
	require.NoError(t, err)

	for name, clash := range map[string]model.IdentityProvider{
		"same type and partition":      newAliasProvider(tn, "corp", model.OpenIDConnectIDPType, tn.partition),
		"same type, another partition": newAliasProvider(tn, "corp", model.OpenIDConnectIDPType, extraPartition.ID),
		"another type, same partition": newAliasProvider(tn, "corp", model.UsernamePasswordIDPType, tn.partition),
		"another type and partition":   newAliasProvider(tn, "corp", model.UsernamePasswordIDPType, extraPartition.ID),
	} {
		t.Run(name, func(t *testing.T) {
			clash.ID = uuid.New()
			// The first case is the upsert of the very same row (same tenant, partition, type and alias), which stays an update.
			err := s.CreateIdentityProvider(ctx, tn.id, clash)
			if name == "same type and partition" {
				require.NoError(t, err, "the upsert key is unchanged: saving a provider again updates it")
				return
			}
			require.ErrorIs(t, err, port.ErrAliasAlreadyExists)
		})
	}

	require.NoError(t, s.CreateIdentityProvider(ctx, other.id, newAliasProvider(other, "shared", model.OpenIDConnectIDPType, other.partition)))
	require.NoError(t, s.CreateIdentityProvider(ctx, tn.id, newAliasProvider(tn, "shared", model.OpenIDConnectIDPType, tn.partition)), "another tenant may use the same alias")
}

func TestIntegration_GetIdentityProviderByAlias(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "byalias.example.com", false)
	other := seedTenant(t, s, "other.byalias.example.com", false)

	got, err := s.GetIdentityProviderByAlias(ctx, tn.id, "corp")
	require.NoError(t, err)
	assert.Equal(t, tn.ssoIDP, got.ID)
	assert.Equal(t, tn.partition, got.PartitionID)

	_, err = s.GetIdentityProviderByAlias(ctx, tn.id, "nope")
	require.ErrorIs(t, err, port.ErrIdentityProviderNotFound)

	other2, err := s.GetIdentityProviderByAlias(ctx, other.id, "corp")
	require.NoError(t, err)
	assert.Equal(t, other.ssoIDP, other2.ID, "each tenant resolves its own provider")
}

// Migration 00033 refuses to run on data that already breaks the rule, and says which tenant and alias.
func TestIntegration_Migration00033RefusesExistingDuplicateAliases(t *testing.T) {
	url := integrationURL(t)
	ctx := context.Background()
	pool, cleanup := newSchemaPool(t, ctx, url)
	defer cleanup()

	db := stdlib.OpenDBFromPool(pool)
	goose.SetBaseFS(embedMigrations)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpToContext(ctx, db, "migrations", 32))

	_, err := pool.Exec(ctx, `INSERT INTO tenants (name, domain_name) VALUES ('Dup', 'dup.example.com')`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO partitions (tenant_id, name, alias_name) SELECT id, 'One', 'one' FROM tenants WHERE domain_name = 'dup.example.com'`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO partitions (tenant_id, name, alias_name) SELECT id, 'Two', 'two' FROM tenants WHERE domain_name = 'dup.example.com'`)
	require.NoError(t, err)
	for _, partition := range []string{"one", "two"} {
		_, err = pool.Exec(ctx, `
			INSERT INTO identity_providers (tenant_id, idp_type, alias_name, name, partition_id, config, enabled)
			SELECT t.id, 'oidc', 'clash', 'Clash', p.id, '{}'::jsonb, TRUE
			FROM tenants t JOIN partitions p ON p.tenant_id = t.id WHERE t.domain_name = 'dup.example.com' AND p.alias_name = $1`, partition)
		require.NoError(t, err)
	}

	err = goose.UpContext(ctx, db, "migrations")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "dup.example.com")
	assert.Contains(t, err.Error(), "clash")
	assert.Contains(t, err.Error(), "rename all but one")
}

func TestIntegration_Migration00033AppliesToCleanDataAndRollsBack(t *testing.T) {
	url := integrationURL(t)
	ctx := context.Background()
	pool, cleanup := newSchemaPool(t, ctx, url)
	defer cleanup()

	db := stdlib.OpenDBFromPool(pool)
	goose.SetBaseFS(embedMigrations)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpContext(ctx, db, "migrations"))

	var constraints int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conname = 'uq_identity_providers_tenant_alias'`).Scan(&constraints))
	assert.Equal(t, 1, constraints)

	require.NoError(t, goose.DownToContext(ctx, db, "migrations", 32))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conname = 'uq_identity_providers_tenant_alias'`).Scan(&constraints))
	assert.Equal(t, 0, constraints, "the rollback removes the tenant-wide key")
}
