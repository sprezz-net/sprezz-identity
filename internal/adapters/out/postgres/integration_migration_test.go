package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Migration 00029 has a data step that flags the bootstrap rows of an installation created before the flag
// existed. This test builds such an installation (schema at 00028), seeds an admin tenant and a customer tenant,
// migrates forward and checks which rows were flagged.
func TestIntegration_Migration00029FlagsExistingBootstrapRows(t *testing.T) {
	url := integrationURL(t)
	ctx := context.Background()
	pool, cleanup := newSchemaPool(t, ctx, url)
	defer cleanup()

	db := stdlib.OpenDBFromPool(pool)
	goose.SetBaseFS(embedMigrations)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpToContext(ctx, db, "migrations", 28))

	seedLegacyInstallation(t, ctx, pool)
	require.NoError(t, goose.UpContext(ctx, db, "migrations"))

	flagged := func(query string) []string {
		rows, err := pool.Query(ctx, query)
		require.NoError(t, err)
		defer rows.Close()
		var out []string
		for rows.Next() {
			var name string
			require.NoError(t, rows.Scan(&name))
			out = append(out, name)
		}
		return out
	}

	assert.Equal(t, []string{"admin.example.com"}, flagged(`SELECT domain_name FROM tenants WHERE is_system ORDER BY 1`))
	assert.Equal(t, []string{"admin_ui"}, flagged(`SELECT client_id FROM applications WHERE is_system ORDER BY 1`))
	assert.Equal(t, []string{"sprezz_admin_ui_profile"}, flagged(`SELECT profile_name FROM application_profiles WHERE is_system ORDER BY 1`))
	assert.ElementsMatch(t, []string{"sprezz_admin_ui_group", "sprezz_local_admin_group"},
		flagged(`SELECT group_name FROM application_groups WHERE is_system`))
	assert.Equal(t, []string{"customer-app"}, flagged(`SELECT client_id FROM applications WHERE NOT is_system ORDER BY 1`),
		"customer objects stay unflagged")
	assert.Equal(t, []string{"customer-group"}, flagged(`SELECT group_name FROM application_groups WHERE NOT is_system`))
}
