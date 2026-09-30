package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// integrationURL returns the test database URL or skips the test.
func integrationURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("SPREZZ_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("SPREZZ_TEST_DATABASE_URL is not set")
	}
	return url
}

// newSchemaPool creates an empty, uniquely named schema and returns a pool whose search_path points at it.
// The cleanup function drops the schema again.
func newSchemaPool(t *testing.T, ctx context.Context, url string) (*pgxpool.Pool, func()) {
	t.Helper()
	schema := "it_" + uuid.NewString()[:8]

	admin, err := pgxpool.New(ctx, url)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)

	cfg, err := pgxpool.ParseConfig(url)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)

	return pool, func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	}
}

// seedLegacyInstallation inserts data the way a pre-00029 installation holds it: an admin tenant with the
// bootstrap objects and a customer tenant with its own objects. Raw SQL is used because the application code
// already targets the newer schema.
func seedLegacyInstallation(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	statements := []string{
		`INSERT INTO tenants (name, domain_name) VALUES ('Administrative Tenant', 'admin.example.com'), ('Customer', 'customer.example.com')`,
		`INSERT INTO application_profiles (tenant_id, profile_name, grant_types, response_types, access_token_lifetime, refresh_token_lifetime, id_token_lifetime)
		 SELECT id, 'sprezz_admin_ui_profile', '{authorization_code}', '{code}', '15 minutes', '1 day', '15 minutes' FROM tenants WHERE domain_name = 'admin.example.com'`,
		`INSERT INTO application_profiles (tenant_id, profile_name, grant_types, response_types, access_token_lifetime, refresh_token_lifetime, id_token_lifetime)
		 SELECT id, 'customer-profile', '{authorization_code}', '{code}', '15 minutes', '1 day', '15 minutes' FROM tenants WHERE domain_name = 'customer.example.com'`,
		`INSERT INTO application_groups (tenant_id, group_name, allowed_audiences)
		 SELECT id, 'sprezz_admin_ui_group', '{}' FROM tenants WHERE domain_name = 'admin.example.com'`,
		`INSERT INTO application_groups (tenant_id, group_name, allowed_audiences)
		 SELECT id, 'sprezz_local_admin_group', '{}' FROM tenants WHERE domain_name = 'admin.example.com'`,
		`INSERT INTO application_groups (tenant_id, group_name, allowed_audiences)
		 SELECT id, 'customer-group', '{}' FROM tenants WHERE domain_name = 'customer.example.com'`,
		`INSERT INTO applications (tenant_id, profile_id, group_id, application_name, client_id)
		 SELECT t.id, p.id, g.id, 'Admin Interface', 'admin_ui'
		 FROM tenants t
		 JOIN application_profiles p ON p.tenant_id = t.id AND p.profile_name = 'sprezz_admin_ui_profile'
		 JOIN application_groups g ON g.tenant_id = t.id AND g.group_name = 'sprezz_admin_ui_group'
		 WHERE t.domain_name = 'admin.example.com'`,
		`INSERT INTO applications (tenant_id, profile_id, group_id, application_name, client_id)
		 SELECT t.id, p.id, g.id, 'Customer App', 'customer-app'
		 FROM tenants t
		 JOIN application_profiles p ON p.tenant_id = t.id AND p.profile_name = 'customer-profile'
		 JOIN application_groups g ON g.tenant_id = t.id AND g.group_name = 'customer-group'
		 WHERE t.domain_name = 'customer.example.com'`,
	}
	for _, stmt := range statements {
		_, err := pool.Exec(ctx, stmt)
		require.NoError(t, err, stmt)
	}
}
