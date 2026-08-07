package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	sqlcdb "sprezz-identity/internal/adapters/out/postgres/db"
	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStorage struct {
	pool    *pgxpool.Pool
	queries *sqlcdb.Queries
}

func NewPostgresStorage(pool *pgxpool.Pool) *PostgresStorage {
	return &PostgresStorage{
		pool:    pool,
		queries: sqlcdb.New(pool),
	}
}

func (s *PostgresStorage) SaveClient(ctx context.Context, client model.ClientApplication) error {
	clientUUID, err := uuid.Parse(client.ID)
	if err != nil {
		return fmt.Errorf("save client: parse client UUID: %w", err)
	}

	clientType := client.ClientType
	if clientType == "" {
		clientType = model.ClientTypeConfidential
	}

	commandTag, err := s.queries.SaveClient(ctx, sqlcdb.SaveClientParams{
		TenantUuid:             toPGUUID(client.TenantID),
		ID:                     toPGUUID(clientUUID),
		ClientID:               client.ClientID,
		ClientSecretHash:       client.ClientSecret,
		ClientName:             client.ClientName,
		RedirectUri:            client.RedirectURI,
		RedirectUris:           client.RedirectURIs,
		PostLogoutRedirectUris: client.PostLogoutRedirectURIs,
		FrontChannelLogoutUri:  stringPtr(client.FrontChannelLogoutURI),
		BackChannelLogoutUri:   stringPtr(client.BackChannelLogoutURI),
		GrantTypes:             client.GrantTypes,
		ResponseTypes:          client.ResponseTypes,
		IdpSigningAlgorithm:    string(client.Algorithm),
		AccessTokenLifetime:    toPGInterval(client.AccessTokenLifetime),
		RefreshTokenLifetime:   toPGInterval(client.RefreshTokenLifetime),
		IDTokenLifetime:        toPGInterval(client.IDTokenLifetime),
		AllowedScopes:          client.AllowedScopes,
		DefaultScopes:          client.DefaultScopes,
		AllowedIdps:            client.AllowedIDPs,
		DefaultIdp:             stringPtr(client.DefaultIDP),
		AllowedAudiences:       client.AllowedAudiences,
		ClientType:             clientType,
		EnforceRtr:             client.EnforceRTR,
	})
	if err != nil {
		return fmt.Errorf("save client: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		return fmt.Errorf("save client: expected 1 row to be inserted, affected %d", commandTag.RowsAffected())
	}
	return nil
}

func (s *PostgresStorage) GetClient(ctx context.Context, tenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
	row, err := s.queries.GetClient(ctx, sqlcdb.GetClientParams{
		TenantUuid: toPGUUID(tenantID),
		ClientID:   clientID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("client %s for tenant %s: %w", clientID, tenantID, port.ErrClientNotFound)
		}
		return nil, fmt.Errorf("get client: %w", err)
	}

	id, err := pgUUIDToUUID(row.ID)
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}
	accessLifetime, err := pgIntervalToDuration(row.AccessTokenLifetime)
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}
	refreshLifetime, err := pgIntervalToDuration(row.RefreshTokenLifetime)
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}
	idTokenLifetime, err := pgIntervalToDuration(row.IDTokenLifetime)
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}

	createdAt, err := pgTimestamptzToTime(row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get client: parse created_at: %w", err)
	}
	updatedAt, err := pgTimestamptzToTime(row.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get client: parse updated_at: %w", err)
	}

	return &model.ClientApplication{
		ID:                     id.String(),
		TenantID:               tenantID,
		ClientID:               row.ClientID,
		ClientSecret:           row.ClientSecretHash,
		ClientName:             row.ClientName,
		RedirectURI:            row.RedirectUri,
		RedirectURIs:           row.RedirectUris,
		PostLogoutRedirectURIs: row.PostLogoutRedirectUris,
		FrontChannelLogoutURI:  valueOrEmpty(row.FrontChannelLogoutUri),
		BackChannelLogoutURI:   valueOrEmpty(row.BackChannelLogoutUri),
		GrantTypes:             row.GrantTypes,
		ResponseTypes:          row.ResponseTypes,
		Algorithm:              model.SignatureAlgorithm(row.IdpSigningAlgorithm),
		AccessTokenLifetime:    accessLifetime,
		RefreshTokenLifetime:   refreshLifetime,
		IDTokenLifetime:        idTokenLifetime,
		AllowedScopes:          row.AllowedScopes,
		DefaultScopes:          row.DefaultScopes,
		AllowedIDPs:            row.AllowedIdps,
		DefaultIDP:             valueOrEmpty(row.DefaultIdp),
		AllowedAudiences:       row.AllowedAudiences,
		ClientType:             row.ClientType,
		EnforceRTR:             row.EnforceRtr,
		CreatedAt:              createdAt,
		UpdatedAt:              updatedAt,
	}, nil
}

func scanClientRow(row pgx.Row, tenantID uuid.UUID) (model.ClientApplication, error) {
	var id pgtype.UUID
	var clientID string
	var clientSecret *string
	var clientName string
	var redirectURI string
	var redirectURIs []string
	var postLogoutRedirectURIs []string
	var frontChannelLogoutURI *string
	var backChannelLogoutURI *string
	var grantTypes []string
	var responseTypes []string
	var algorithm string
	var accessLifetime pgtype.Interval
	var refreshLifetime pgtype.Interval
	var idTokenLifetime pgtype.Interval
	var allowedScopes []string
	var defaultScopes []string
	var allowedIdps []string
	var defaultIdp *string
	var allowedAudiences []string
	var clientType string
	var enforceRTR bool
	var createdAt pgtype.Timestamptz
	var updatedAt pgtype.Timestamptz

	err := row.Scan(
		&id,
		&clientID,
		&clientSecret,
		&clientName,
		&redirectURI,
		&redirectURIs,
		&postLogoutRedirectURIs,
		&frontChannelLogoutURI,
		&backChannelLogoutURI,
		&grantTypes,
		&responseTypes,
		&algorithm,
		&accessLifetime,
		&refreshLifetime,
		&idTokenLifetime,
		&allowedScopes,
		&defaultScopes,
		&allowedIdps,
		&defaultIdp,
		&allowedAudiences,
		&clientType,
		&enforceRTR,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return model.ClientApplication{}, fmt.Errorf("scan client application: %w", err)
	}

	parsedID, err := pgUUIDToUUID(id)
	if err != nil {
		return model.ClientApplication{}, fmt.Errorf("parse client UUID: %w", err)
	}
	parsedAccess, err := pgIntervalToDuration(accessLifetime)
	if err != nil {
		return model.ClientApplication{}, fmt.Errorf("parse access lifetime: %w", err)
	}
	parsedRefresh, err := pgIntervalToDuration(refreshLifetime)
	if err != nil {
		return model.ClientApplication{}, fmt.Errorf("parse refresh lifetime: %w", err)
	}
	parsedIDToken, err := pgIntervalToDuration(idTokenLifetime)
	if err != nil {
		return model.ClientApplication{}, fmt.Errorf("parse id token lifetime: %w", err)
	}
	parsedCreatedAt, err := pgTimestamptzToTime(createdAt)
	if err != nil {
		return model.ClientApplication{}, fmt.Errorf("parse created_at: %w", err)
	}
	parsedUpdatedAt, err := pgTimestamptzToTime(updatedAt)
	if err != nil {
		return model.ClientApplication{}, fmt.Errorf("parse updated_at: %w", err)
	}

	return model.ClientApplication{
		ID:                     parsedID.String(),
		TenantID:               tenantID,
		ClientID:               clientID,
		ClientSecret:           clientSecret,
		ClientName:             clientName,
		RedirectURI:            redirectURI,
		RedirectURIs:           redirectURIs,
		PostLogoutRedirectURIs: postLogoutRedirectURIs,
		FrontChannelLogoutURI:  valueOrEmpty(frontChannelLogoutURI),
		BackChannelLogoutURI:   valueOrEmpty(backChannelLogoutURI),
		GrantTypes:             grantTypes,
		ResponseTypes:          responseTypes,
		Algorithm:              model.SignatureAlgorithm(algorithm),
		AccessTokenLifetime:    parsedAccess,
		RefreshTokenLifetime:   parsedRefresh,
		IDTokenLifetime:        parsedIDToken,
		AllowedScopes:          allowedScopes,
		DefaultScopes:          defaultScopes,
		AllowedIDPs:            allowedIdps,
		DefaultIDP:             valueOrEmpty(defaultIdp),
		AllowedAudiences:       allowedAudiences,
		ClientType:             clientType,
		EnforceRTR:             enforceRTR,
		CreatedAt:              parsedCreatedAt,
		UpdatedAt:              parsedUpdatedAt,
	}, nil
}

func (s *PostgresStorage) GetClientsByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.ClientApplication, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			a.id,
			a.client_id,
			a.client_secret_hash,
			a.client_name,
			a.redirect_uri,
			a.redirect_uris,
			a.post_logout_redirect_uris,
			a.front_channel_logout_uri,
			a.back_channel_logout_uri,
			a.grant_types,
			a.response_types,
			a.idp_signing_algorithm,
			a.access_token_lifetime,
			a.refresh_token_lifetime,
			a.id_token_lifetime,
			a.allowed_scopes,
			a.default_scopes,
			a.allowed_idps,
			a.default_idp,
			a.allowed_audiences,
			a.client_type,
			a.enforce_rtr,
			a.created_at,
			a.updated_at
		FROM applications AS a
		JOIN tenants AS t ON t.id = a.tenant_id
		WHERE t.tenant_uuid = $1::uuid
	`, toPGUUID(tenantID))
	if err != nil {
		return nil, fmt.Errorf("get clients by tenant: %w", err)
	}
	defer rows.Close()

	var clients []model.ClientApplication
	for rows.Next() {
		client, err := scanClientRow(rows, tenantID)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate client applications: %w", err)
	}

	return clients, nil
}

func (s *PostgresStorage) SaveAuthSession(ctx context.Context, session model.AuthorizationCodeSession) error {
	tenantUUID, err := uuid.Parse(session.TenantID)
	if err != nil {
		return fmt.Errorf("save auth session: parse tenant UUID: %w", err)
	}

	commandTag, err := s.queries.SaveAuthSession(ctx, sqlcdb.SaveAuthSessionParams{
		TenantUuid:      toPGUUID(tenantUUID),
		Code:            session.Code,
		ClientID:        session.ClientID,
		Subject:         session.Subject,
		CodeChallenge:   session.CodeChallenge,
		ChallengeMethod: session.ChallengeMethod,
		RedirectUri:     session.RedirectURI,
		Scopes:          session.Scopes,
		ExpiresAt:       toPGTimestamptz(session.ExpiresAt),
		SessionID:       session.SessionID,
		State:           session.State,
		Nonce:           session.Nonce,
		AcrValues:       session.ACRValues,
	})
	if err != nil {
		return fmt.Errorf("save auth session: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		return fmt.Errorf("save auth session: expected 1 row to be inserted, affected %d", commandTag.RowsAffected())
	}
	return nil
}

func (s *PostgresStorage) GetAndConsumeAuthSession(ctx context.Context, tenantID uuid.UUID, code string) (*model.AuthorizationCodeSession, error) {
	row, err := s.queries.ConsumeAuthSession(ctx, sqlcdb.ConsumeAuthSessionParams{
		TenantUuid: toPGUUID(tenantID),
		Code:       code,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("session %s for tenant %s: %w", code, tenantID, port.ErrSessionNotFound)
		}
		return nil, fmt.Errorf("consume auth session: %w", err)
	}

	expiresAt, err := pgTimestamptzToTime(row.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("consume auth session: %w", err)
	}

	return &model.AuthorizationCodeSession{
		Code:            row.Code,
		TenantID:        tenantID.String(),
		ClientID:        row.ClientID,
		Subject:         row.Subject,
		CodeChallenge:   row.CodeChallenge,
		ChallengeMethod: row.ChallengeMethod,
		RedirectURI:     row.RedirectUri,
		Scopes:          row.Scopes,
		ExpiresAt:       expiresAt,
		SessionID:       row.SessionID,
		State:           row.State,
		Nonce:           row.Nonce,
		ACRValues:       row.AcrValues,
	}, nil
}

func (s *PostgresStorage) ResolveTenantByDomain(ctx context.Context, domain string) (*model.Tenant, error) {
	row, err := s.queries.ResolveTenantByDomain(ctx, domain)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, port.ErrTenantNotFound
		}
		return nil, fmt.Errorf("resolve tenant by domain: %w", err)
	}

	tenantID, err := pgUUIDToUUID(row.TenantUuid)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant by domain: %w", err)
	}

	createdAt, err := pgTimestamptzToTime(row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant by domain: %w", err)
	}

	updatedAt, err := pgTimestamptzToTime(row.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant by domain: %w", err)
	}

	var cfg model.TenantConfig
	if len(row.Config) > 0 {
		if err := json.Unmarshal(row.Config, &cfg); err != nil {
			return nil, fmt.Errorf("resolve tenant by domain: unmarshal config: %w", err)
		}
	}

	return &model.Tenant{
		ID:               tenantID,
		Name:             row.Name,
		Domain:           row.DomainName,
		IsActive:         row.IsActive,
		CreatedAt:        createdAt,
		Config:           cfg,
		DefaultPartition: row.DefaultPartition,
		UpdatedAt:        updatedAt,
	}, nil
}

func (s *PostgresStorage) ResolveTenantByID(ctx context.Context, tenantID uuid.UUID) (*model.Tenant, error) {
	row, err := s.queries.ResolveTenantByUUID(ctx, toPGUUID(tenantID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, port.ErrTenantNotFound
		}
		return nil, fmt.Errorf("resolve tenant by ID: %w", err)
	}

	resolvedID, err := pgUUIDToUUID(row.TenantUuid)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant by ID: %w", err)
	}

	createdAt, err := pgTimestamptzToTime(row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant by ID: %w", err)
	}

	updatedAt, err := pgTimestamptzToTime(row.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant by ID: %w", err)
	}

	var cfg model.TenantConfig
	if len(row.Config) > 0 {
		if err := json.Unmarshal(row.Config, &cfg); err != nil {
			return nil, fmt.Errorf("resolve tenant by ID: unmarshal config: %w", err)
		}
	}

	return &model.Tenant{
		ID:               resolvedID,
		Name:             row.Name,
		Domain:           row.DomainName,
		IsActive:         row.IsActive,
		CreatedAt:        createdAt,
		Config:           cfg,
		DefaultPartition: row.DefaultPartition,
		UpdatedAt:        updatedAt,
	}, nil
}

func scanTenantRow(row pgx.Row) (model.Tenant, error) {
	var tenantUUID pgtype.UUID
	var name string
	var domainName string
	var isActive bool
	var createdAt pgtype.Timestamptz
	var configJSON []byte
	var defaultPartition *int64
	var updatedAt pgtype.Timestamptz

	err := row.Scan(&tenantUUID, &name, &domainName, &isActive, &createdAt, &configJSON, &defaultPartition, &updatedAt)
	if err != nil {
		return model.Tenant{}, fmt.Errorf("scan tenant: %w", err)
	}

	parsedID, err := pgUUIDToUUID(tenantUUID)
	if err != nil {
		return model.Tenant{}, fmt.Errorf("parse tenant UUID: %w", err)
	}

	parsedCreatedAt, err := pgTimestamptzToTime(createdAt)
	if err != nil {
		return model.Tenant{}, fmt.Errorf("parse created_at: %w", err)
	}

	parsedUpdatedAt, err := pgTimestamptzToTime(updatedAt)
	if err != nil {
		return model.Tenant{}, fmt.Errorf("parse updated_at: %w", err)
	}

	var cfg model.TenantConfig
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return model.Tenant{}, fmt.Errorf("unmarshal config: %w", err)
		}
	}

	return model.Tenant{
		ID:               parsedID,
		Name:             name,
		Domain:           domainName,
		IsActive:         isActive,
		CreatedAt:        parsedCreatedAt,
		Config:           cfg,
		DefaultPartition: defaultPartition,
		UpdatedAt:        parsedUpdatedAt,
	}, nil
}

func (s *PostgresStorage) GetAllTenants(ctx context.Context) ([]model.Tenant, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT tenant_uuid, name, domain_name, is_active, created_at, config, default_partition, updated_at
		FROM tenants
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("get all tenants: %w", err)
	}
	defer rows.Close()

	var tenants []model.Tenant
	for rows.Next() {
		tenant, err := scanTenantRow(rows)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, tenant)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenants: %w", err)
	}

	return tenants, nil
}

func (s *PostgresStorage) CreateTenant(ctx context.Context, tenant model.Tenant) error {
	configJSON, err := json.Marshal(tenant.Config)
	if err != nil {
		return fmt.Errorf("create tenant: marshal config: %w", err)
	}

	commandTag, err := s.queries.CreateTenant(ctx, sqlcdb.CreateTenantParams{
		TenantUuid:       toPGUUID(tenant.ID),
		Name:             tenant.Name,
		DomainName:       tenant.Domain,
		IsActive:         tenant.IsActive,
		CreatedAt:        toPGTimestamptz(tenant.CreatedAt),
		Config:           configJSON,
		DefaultPartition: tenant.DefaultPartition,
	})
	if err != nil {
		return fmt.Errorf("create tenant: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		return fmt.Errorf("create tenant: expected 1 row to be inserted, affected %d", commandTag.RowsAffected())
	}

	return nil
}

func (s *PostgresStorage) CreateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) error {
	configJSON, err := json.Marshal(provider.Config)
	if err != nil {
		return fmt.Errorf("marshal provider config: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO identity_providers (id, tenant_id, idp_type, enabled, alias_name, config, name, partition_id)
		SELECT $1::uuid, t.id, $2, $3, $4, $5::jsonb, $7, $8
		FROM tenants t
		WHERE t.tenant_uuid = $6::uuid
		ON CONFLICT (tenant_id, partition_id, idp_type, alias_name) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			config = EXCLUDED.config,
			name = EXCLUDED.name
	`, toPGUUID(provider.ID), provider.IDPType, provider.Enabled, provider.Alias, string(configJSON), toPGUUID(tenantID), provider.Name, provider.PartitionID)
	if err != nil {
		return fmt.Errorf("create identity provider: %w", err)
	}
	return nil
}

func (s *PostgresStorage) GetIdentityProviderByType(ctx context.Context, tenantID uuid.UUID, idpType string) (*model.IdentityProvider, error) {
	var providerID pgtype.UUID
	var enabled bool
	var alias string
	var configJSON []byte
	var name string
	var partitionID int64
	var createdAt, updatedAt pgtype.Timestamptz

	err := s.pool.QueryRow(ctx, `
		SELECT ip.id, ip.enabled, ip.alias_name, ip.config, ip.name, ip.partition_id, ip.created_at, ip.updated_at
		FROM identity_providers ip
		JOIN tenants t ON t.id = ip.tenant_id
		WHERE t.tenant_uuid = $1::uuid AND ip.idp_type = $2 AND ip.enabled = TRUE
	`, toPGUUID(tenantID), idpType).Scan(&providerID, &enabled, &alias, &configJSON, &name, &partitionID, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("identity provider not found: %w", port.ErrIdentityProviderNotFound)
		}
		return nil, fmt.Errorf("get identity provider by type: %w", err)
	}

	providerUUID, err := pgUUIDToUUID(providerID)
	if err != nil {
		return nil, fmt.Errorf("parse provider UUID: %w", err)
	}

	parsedCreatedAt, err := pgTimestamptzToTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	parsedUpdatedAt, err := pgTimestamptzToTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at: %w", err)
	}

	providerCfg := model.IdentityProviderConfig{}
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &providerCfg); err != nil {
			return nil, fmt.Errorf("unmarshal provider config: %w", err)
		}
	}

	return &model.IdentityProvider{
		ID:          providerUUID,
		TenantID:    tenantID,
		IDPType:     idpType,
		Enabled:     enabled,
		Alias:       alias,
		Name:        name,
		PartitionID: partitionID,
		IssuerURL:   providerCfg.Issuer,
		Config:      providerCfg,
		CreatedAt:   parsedCreatedAt,
		UpdatedAt:   parsedUpdatedAt,
	}, nil
}

func (s *PostgresStorage) SaveUserProfile(ctx context.Context, tenantID uuid.UUID, profile model.UserProfile) error {
	// Check collision first
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM user_profiles
			WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1::uuid)
			  AND partition_id = $4
			  AND (preferred_username = $2 OR email = $3)
		)
	`, toPGUUID(tenantID), profile.PreferredUsername, profile.Email, profile.PartitionID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("collision check user profile: %w", err)
	}
	if exists {
		// Specific error mapping can be refined inside transaction, but we check specifically:
		var count int
		_ = s.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM user_profiles
			WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1::uuid)
			  AND partition_id = $3
			  AND preferred_username = $2
		`, toPGUUID(tenantID), profile.PreferredUsername, profile.PartitionID).Scan(&count)
		if count > 0 {
			return port.ErrUsernameAlreadyExists
		}
		return port.ErrEmailAlreadyExists
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO user_profiles (id, tenant_id, preferred_username, name, email, email_verified, partition_id)
		SELECT $1::uuid, t.id, $2, $3, $4, $5, $7
		FROM tenants t
		WHERE t.tenant_uuid = $6::uuid
	`, toPGUUID(profile.ID), profile.PreferredUsername, profile.Name, profile.Email, profile.EmailVerified, toPGUUID(tenantID), profile.PartitionID)
	if err != nil {
		return fmt.Errorf("insert user profile: %w", err)
	}
	return nil
}

func (s *PostgresStorage) SavePasswordCredential(ctx context.Context, credential model.PasswordCredential) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO passwords (user_profile_id, identity_provider_id, password_hash)
		VALUES ($1::uuid, $2::uuid, $3)
		ON CONFLICT (user_profile_id, identity_provider_id) DO UPDATE SET
			password_hash = EXCLUDED.password_hash
	`, toPGUUID(credential.UserProfileID), toPGUUID(credential.IdentityProviderID), credential.Argon2Hash)
	if err != nil {
		return fmt.Errorf("insert/update password credential: %w", err)
	}
	return nil
}

func scanIdentityProviderRow(row pgx.Row, tenantID uuid.UUID) (model.IdentityProvider, error) {
	var providerID pgtype.UUID
	var idpType string
	var enabled bool
	var alias string
	var configJSON []byte
	var name string
	var partitionID int64
	var createdAt pgtype.Timestamptz
	var updatedAt pgtype.Timestamptz

	if err := row.Scan(&providerID, &idpType, &enabled, &alias, &configJSON, &name, &partitionID, &createdAt, &updatedAt); err != nil {
		return model.IdentityProvider{}, fmt.Errorf("scan identity provider: %w", err)
	}

	providerUUID, err := pgUUIDToUUID(providerID)
	if err != nil {
		return model.IdentityProvider{}, fmt.Errorf("parse provider UUID: %w", err)
	}

	parsedCreatedAt, err := pgTimestamptzToTime(createdAt)
	if err != nil {
		return model.IdentityProvider{}, fmt.Errorf("parse created_at: %w", err)
	}

	parsedUpdatedAt, err := pgTimestamptzToTime(updatedAt)
	if err != nil {
		return model.IdentityProvider{}, fmt.Errorf("parse updated_at: %w", err)
	}

	providerCfg := model.IdentityProviderConfig{}
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &providerCfg); err != nil {
			return model.IdentityProvider{}, fmt.Errorf("unmarshal provider config: %w", err)
		}
	}

	return model.IdentityProvider{
		ID:          providerUUID,
		TenantID:    tenantID,
		IDPType:     idpType,
		Enabled:     enabled,
		Alias:       alias,
		Name:        name,
		PartitionID: partitionID,
		IssuerURL:   providerCfg.Issuer,
		Config:      providerCfg,
		CreatedAt:   parsedCreatedAt,
		UpdatedAt:   parsedUpdatedAt,
	}, nil
}

func (s *PostgresStorage) GetEnabledIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ip.id, ip.idp_type, ip.enabled, ip.alias_name, ip.config, ip.name, ip.partition_id, ip.created_at, ip.updated_at
		FROM identity_providers ip
		JOIN tenants t ON t.id = ip.tenant_id
		WHERE t.tenant_uuid = $1::uuid AND ip.enabled = TRUE
		ORDER BY ip.alias_name ASC
	`, toPGUUID(tenantID))
	if err != nil {
		return nil, fmt.Errorf("get enabled identity providers: %w", err)
	}
	defer rows.Close()

	providers := make([]model.IdentityProvider, 0)
	for rows.Next() {
		p, err := scanIdentityProviderRow(rows, tenantID)
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identity providers: %w", err)
	}
	return providers, nil
}

func (s *PostgresStorage) getUsernameField(ctx context.Context, tenantID uuid.UUID, providerID uuid.UUID) (string, error) {
	var configJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT ip.config
		FROM identity_providers ip
		JOIN tenants t ON t.id = ip.tenant_id
		WHERE t.tenant_uuid = $1::uuid AND ip.id = $2::uuid
	`, toPGUUID(tenantID), toPGUUID(providerID)).Scan(&configJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", port.ErrIdentityProviderNotFound
		}
		return "", fmt.Errorf("get identity provider config: %w", err)
	}

	var providerCfg model.IdentityProviderConfig
	if len(configJSON) > 0 {
		_ = json.Unmarshal(configJSON, &providerCfg)
	}
	if providerCfg.UsernameField != "" {
		return providerCfg.UsernameField, nil
	}
	return "preferredUsername", nil
}

func (s *PostgresStorage) GetUserProfileByIdentifier(ctx context.Context, tenantID uuid.UUID, partitionID int64, providerID uuid.UUID, identifier string) (*model.UserProfile, error) {
	usernameField, err := s.getUsernameField(ctx, tenantID, providerID)
	if err != nil {
		return nil, err
	}

	var query string
	if usernameField == "email" {
		query = `
			SELECT id, preferred_username, name, email, email_verified, partition_id, created_at, updated_at
			FROM user_profiles
			WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1::uuid)
			  AND partition_id = $3
			  AND email = $2
		`
	} else {
		query = `
			SELECT id, preferred_username, name, email, email_verified, partition_id, created_at, updated_at
			FROM user_profiles
			WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1::uuid)
			  AND partition_id = $3
			  AND preferred_username = $2
		`
	}

	row := s.pool.QueryRow(ctx, query, toPGUUID(tenantID), identifier, partitionID)
	profile, err := scanUserProfileRow(row, tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user profile not found for identifier %s: %w", identifier, port.ErrUserProfileNotFound)
		}
		return nil, fmt.Errorf("lookup user profile: %w", err)
	}

	return &profile, nil
}

func (s *PostgresStorage) GetUserProfileByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.UserProfile, error) {
	var preferredUsername string
	var name string
	var email string
	var emailVerified bool
	var partitionID int64
	var createdAt, updatedAt pgtype.Timestamptz

	err := s.pool.QueryRow(ctx, `
		SELECT preferred_username, name, email, email_verified, partition_id, created_at, updated_at
		FROM user_profiles
		WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1::uuid)
		  AND id = $2::uuid
	`, toPGUUID(tenantID), toPGUUID(id)).Scan(&preferredUsername, &name, &email, &emailVerified, &partitionID, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, port.ErrUserProfileNotFound
		}
		return nil, fmt.Errorf("get user profile by ID: %w", err)
	}

	parsedCreatedAt, err := pgTimestamptzToTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}

	parsedUpdatedAt, err := pgTimestamptzToTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at: %w", err)
	}

	return &model.UserProfile{
		ID:                id,
		TenantID:          tenantID,
		PartitionID:       partitionID,
		PreferredUsername: preferredUsername,
		Name:              name,
		Email:             email,
		EmailVerified:     emailVerified,
		CreatedAt:         parsedCreatedAt,
		UpdatedAt:         parsedUpdatedAt,
	}, nil
}

func (s *PostgresStorage) GetPasswordCredential(ctx context.Context, userProfileID uuid.UUID, providerID uuid.UUID) (*model.PasswordCredential, error) {
	var hash string
	var createdAt, updatedAt pgtype.Timestamptz
	err := s.pool.QueryRow(ctx, `
		SELECT password_hash, created_at, updated_at
		FROM passwords
		WHERE user_profile_id = $1::uuid AND identity_provider_id = $2::uuid
	`, toPGUUID(userProfileID), toPGUUID(providerID)).Scan(&hash, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("password credential not found: %w", port.ErrPasswordCredentialNotFound)
		}
		return nil, fmt.Errorf("get password credential: %w", err)
	}
	parsedCreatedAt, err := pgTimestamptzToTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	parsedUpdatedAt, err := pgTimestamptzToTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at: %w", err)
	}
	return &model.PasswordCredential{
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		Argon2Hash:         hash,
		CreatedAt:          parsedCreatedAt,
		UpdatedAt:          parsedUpdatedAt,
	}, nil
}

func (s *PostgresStorage) GetIdentityByProfileAndProvider(ctx context.Context, userProfileID uuid.UUID, providerID uuid.UUID) (*model.UserIdentity, error) {
	var id pgtype.UUID
	var externalIdentityID string
	var loginCount int
	var lastLoginAt pgtype.Timestamptz
	var lastVerificationAttempt pgtype.Timestamptz
	var failedVerificationCount int
	var blocked bool
	var coupledAt pgtype.Timestamptz

	err := s.pool.QueryRow(ctx, `
		SELECT id, external_identity_id, login_count, last_login_at, last_verification_attempt, failed_verification_count, blocked, coupled_at
		FROM identities
		WHERE user_profile_id = $1::uuid AND identity_provider_id = $2::uuid
	`, toPGUUID(userProfileID), toPGUUID(providerID)).Scan(&id, &externalIdentityID, &loginCount, &lastLoginAt, &lastVerificationAttempt, &failedVerificationCount, &blocked, &coupledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("identity not found: %w", port.ErrIdentityNotFound)
		}
		return nil, fmt.Errorf("get identity by profile and provider: %w", err)
	}

	identityUUID, err := pgUUIDToUUID(id)
	if err != nil {
		return nil, fmt.Errorf("parse identity UUID: %w", err)
	}
	lastLoginTime, err := pgTimestamptzToTime(lastLoginAt)
	if err != nil {
		return nil, fmt.Errorf("parse last login time: %w", err)
	}
	coupledTime, err := pgTimestamptzToTime(coupledAt)
	if err != nil {
		return nil, fmt.Errorf("parse coupled time: %w", err)
	}
	var parsedAttempt time.Time
	if lastVerificationAttempt.Valid {
		parsedAttempt, _ = pgTimestamptzToTime(lastVerificationAttempt)
	}

	return &model.UserIdentity{
		ID:                        identityUUID,
		UserProfileID:             userProfileID,
		IdentityProviderID:        providerID,
		ExternalIdentityID:        externalIdentityID,
		LoginCount:                loginCount,
		LastLoginAt:               lastLoginTime,
		LastVerificationAttemptAt: parsedAttempt,
		FailedVerificationCount:   failedVerificationCount,
		Blocked:                   blocked,
		CoupledAt:                 coupledTime,
	}, nil
}

func (s *PostgresStorage) GetIdentityByProviderAndExternalID(ctx context.Context, providerID uuid.UUID, externalID string) (*model.UserIdentity, error) {
	var id, userProfileID pgtype.UUID
	var externalIdentityID string
	var loginCount int
	var lastLoginAt pgtype.Timestamptz
	var lastVerificationAttempt pgtype.Timestamptz
	var failedVerificationCount int
	var blocked bool
	var coupledAt pgtype.Timestamptz

	err := s.pool.QueryRow(ctx, `
		SELECT id, user_profile_id, external_identity_id, login_count, last_login_at, last_verification_attempt, failed_verification_count, blocked, coupled_at
		FROM identities
		WHERE identity_provider_id = $1::uuid AND external_identity_id = $2
	`, toPGUUID(providerID), externalID).Scan(&id, &userProfileID, &externalIdentityID, &loginCount, &lastLoginAt, &lastVerificationAttempt, &failedVerificationCount, &blocked, &coupledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("identity not found for external id %s: %w", externalID, port.ErrIdentityNotFound)
		}
		return nil, fmt.Errorf("get identity by provider and external id: %w", err)
	}

	identityUUID, err := pgUUIDToUUID(id)
	if err != nil {
		return nil, fmt.Errorf("parse identity UUID: %w", err)
	}
	upUUID, err := pgUUIDToUUID(userProfileID)
	if err != nil {
		return nil, fmt.Errorf("parse user profile UUID: %w", err)
	}
	lastLoginTime, err := pgTimestamptzToTime(lastLoginAt)
	if err != nil {
		return nil, fmt.Errorf("parse last login time: %w", err)
	}
	coupledTime, err := pgTimestamptzToTime(coupledAt)
	if err != nil {
		return nil, fmt.Errorf("parse coupled time: %w", err)
	}
	var parsedAttempt time.Time
	if lastVerificationAttempt.Valid {
		parsedAttempt, _ = pgTimestamptzToTime(lastVerificationAttempt)
	}

	return &model.UserIdentity{
		ID:                        identityUUID,
		UserProfileID:             upUUID,
		IdentityProviderID:        providerID,
		ExternalIdentityID:        externalIdentityID,
		LoginCount:                loginCount,
		LastLoginAt:               lastLoginTime,
		LastVerificationAttemptAt: parsedAttempt,
		FailedVerificationCount:   failedVerificationCount,
		Blocked:                   blocked,
		CoupledAt:                 coupledTime,
	}, nil
}

func (s *PostgresStorage) FindProfileByEmail(ctx context.Context, partitionID int64, email string) (*model.UserProfile, error) {
	query := `
		SELECT id, tenant_id, preferred_username, name, email, email_verified, partition_id, created_at, updated_at
		FROM user_profiles
		WHERE partition_id = $1 AND email = $2
	`
	var id, tenantID pgtype.UUID
	var preferredUsername string
	var name string
	var emailVal string
	var emailVerified bool
	var partID int64
	var createdAt, updatedAt pgtype.Timestamptz

	err := s.pool.QueryRow(ctx, query, partitionID, email).Scan(&id, &tenantID, &preferredUsername, &name, &emailVal, &emailVerified, &partID, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user profile not found for email %s: %w", email, port.ErrUserProfileNotFound)
		}
		return nil, fmt.Errorf("find user profile by email: %w", err)
	}

	parsedID, err := pgUUIDToUUID(id)
	if err != nil {
		return nil, err
	}
	parsedTenantID, err := pgUUIDToUUID(tenantID)
	if err != nil {
		return nil, err
	}
	parsedCreatedAt, err := pgTimestamptzToTime(createdAt)
	if err != nil {
		return nil, err
	}
	parsedUpdatedAt, err := pgTimestamptzToTime(updatedAt)
	if err != nil {
		return nil, err
	}

	return &model.UserProfile{
		ID:                parsedID,
		TenantID:          parsedTenantID,
		PreferredUsername: preferredUsername,
		Name:              name,
		Email:             emailVal,
		EmailVerified:     emailVerified,
		PartitionID:       partID,
		CreatedAt:         parsedCreatedAt,
		UpdatedAt:         parsedUpdatedAt,
	}, nil
}

func (s *PostgresStorage) UpsertIdentity(ctx context.Context, identity model.UserIdentity) error {
	var attempt pgtype.Timestamptz
	if !identity.LastVerificationAttemptAt.IsZero() {
		attempt = toPGTimestamptz(identity.LastVerificationAttemptAt)
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO identities (id, user_profile_id, identity_provider_id, external_identity_id, login_count, last_login_at, last_verification_attempt, failed_verification_count, blocked, coupled_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6::timestamptz, $7::timestamptz, $8, $9, $10::timestamptz)
		ON CONFLICT (user_profile_id, identity_provider_id) DO UPDATE SET
			external_identity_id = EXCLUDED.external_identity_id,
			login_count = EXCLUDED.login_count,
			last_login_at = EXCLUDED.last_login_at,
			last_verification_attempt = EXCLUDED.last_verification_attempt,
			failed_verification_count = EXCLUDED.failed_verification_count,
			blocked = EXCLUDED.blocked,
			coupled_at = EXCLUDED.coupled_at
	`, toPGUUID(identity.ID), toPGUUID(identity.UserProfileID), toPGUUID(identity.IdentityProviderID), identity.ExternalIdentityID, identity.LoginCount, toPGTimestamptz(identity.LastLoginAt), attempt, identity.FailedVerificationCount, identity.Blocked, toPGTimestamptz(identity.CoupledAt))
	if err != nil {
		return fmt.Errorf("upsert identity: %w", err)
	}
	return nil
}

func (s *PostgresStorage) RevokeSession(ctx context.Context, tenantID uuid.UUID, subject string, clientID string) error {
	return nil
}

func (s *PostgresStorage) SaveInteractionSession(ctx context.Context, session model.InteractionSession) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO interaction_sessions (id, tenant_id, client_id, redirect_uri, code_challenge, code_challenge_method, idp_hint, expires_at, state, nonce, acr_values)
		SELECT $1::uuid, t.id, $2, $3, $4, $5, $6, $7::timestamptz, $9, $10, $11
		FROM tenants t
		WHERE t.tenant_uuid = $8::uuid
	`, toPGUUID(session.ID), session.ClientID, session.RedirectURI, session.CodeChallenge, session.ChallengeMethod, stringPtr(session.IDPHint), toPGTimestamptz(session.ExpiresAt), toPGUUID(session.TenantID), session.State, session.Nonce, session.ACRValues)
	if err != nil {
		return fmt.Errorf("save interaction session: %w", err)
	}
	return nil
}

func (s *PostgresStorage) GetAndConsumeInteractionSession(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.InteractionSession, error) {
	var clientID string
	var redirectURI string
	var codeChallenge string
	var codeChallengeMethod string
	var idpHint *string
	var expiresAt pgtype.Timestamptz
	var tenantUUID pgtype.UUID
	var state string
	var nonce string
	var acrValues string

	err := s.pool.QueryRow(ctx, `
		DELETE FROM interaction_sessions
		WHERE id = $1::uuid AND tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $2::uuid)
		RETURNING client_id, redirect_uri, code_challenge, code_challenge_method, idp_hint, expires_at, state, nonce, acr_values,
		          (SELECT tenant_uuid FROM tenants WHERE id = tenant_id)
	`, toPGUUID(id), toPGUUID(tenantID)).Scan(&clientID, &redirectURI, &codeChallenge, &codeChallengeMethod, &idpHint, &expiresAt, &state, &nonce, &acrValues, &tenantUUID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("interaction session %s not found: %w", id, port.ErrInteractionSessionNotFound)
		}
		return nil, fmt.Errorf("get and consume interaction session: %w", err)
	}

	parsedTenantID, err := pgUUIDToUUID(tenantUUID)
	if err != nil {
		return nil, fmt.Errorf("parse tenant UUID: %w", err)
	}
	parsedExpiresAt, err := pgTimestamptzToTime(expiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}

	return &model.InteractionSession{
		ID:              id,
		TenantID:        parsedTenantID,
		ClientID:        clientID,
		RedirectURI:     redirectURI,
		CodeChallenge:   codeChallenge,
		ChallengeMethod: codeChallengeMethod,
		IDPHint:         valueOrEmpty(idpHint),
		ExpiresAt:       parsedExpiresAt,
		State:           state,
		Nonce:           nonce,
		ACRValues:       acrValues,
	}, nil
}

func (s *PostgresStorage) GetInteractionSession(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.InteractionSession, error) {
	var clientID string
	var redirectURI string
	var codeChallenge string
	var codeChallengeMethod string
	var idpHint *string
	var expiresAt pgtype.Timestamptz
	var tenantUUID pgtype.UUID
	var state string
	var nonce string
	var acrValues string

	err := s.pool.QueryRow(ctx, `
		SELECT client_id, redirect_uri, code_challenge, code_challenge_method, idp_hint, expires_at, state, nonce, acr_values,
		       (SELECT tenant_uuid FROM tenants WHERE id = tenant_id)
		FROM interaction_sessions
		WHERE id = $1::uuid AND tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $2::uuid)
	`, toPGUUID(id), toPGUUID(tenantID)).Scan(&clientID, &redirectURI, &codeChallenge, &codeChallengeMethod, &idpHint, &expiresAt, &state, &nonce, &acrValues, &tenantUUID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("interaction session %s not found: %w", id, port.ErrInteractionSessionNotFound)
		}
		return nil, fmt.Errorf("get interaction session: %w", err)
	}

	parsedTenantID, err := pgUUIDToUUID(tenantUUID)
	if err != nil {
		return nil, fmt.Errorf("parse tenant UUID: %w", err)
	}
	parsedExpiresAt, err := pgTimestamptzToTime(expiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}

	return &model.InteractionSession{
		ID:              id,
		TenantID:        parsedTenantID,
		ClientID:        clientID,
		RedirectURI:     redirectURI,
		CodeChallenge:   codeChallenge,
		ChallengeMethod: codeChallengeMethod,
		IDPHint:         valueOrEmpty(idpHint),
		ExpiresAt:       parsedExpiresAt,
		State:           state,
		Nonce:           nonce,
		ACRValues:       acrValues,
	}, nil
}

func (s *PostgresStorage) RevokeToken(ctx context.Context, tokenID string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO revoked_tokens (token_id, expires_at)
		VALUES ($1, $2::timestamptz)
		ON CONFLICT (token_id) DO NOTHING
	`, tokenID, toPGTimestamptz(expiresAt))
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	return nil
}

func (s *PostgresStorage) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM revoked_tokens
			WHERE token_id = $1 AND expires_at > NOW()
		)
	`, tokenID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check token revocation: %w", err)
	}
	return exists, nil
}

func (s *PostgresStorage) PruneExpiredTokens(ctx context.Context) error {
	// 1. Prune expired revoked tokens
	_, err := s.pool.Exec(ctx, "DELETE FROM revoked_tokens WHERE expires_at <= NOW()")
	if err != nil {
		return fmt.Errorf("prune expired tokens: %w", err)
	}

	// 2. Prune stale authorization sessions
	_, err = s.pool.Exec(ctx, "DELETE FROM auth_sessions WHERE expires_at <= NOW()")
	if err != nil {
		return fmt.Errorf("prune stale auth sessions: %w", err)
	}

	// 3. Prune expired interaction sessions
	_, err = s.pool.Exec(ctx, "DELETE FROM interaction_sessions WHERE expires_at <= NOW()")
	if err != nil {
		return fmt.Errorf("prune expired interaction sessions: %w", err)
	}

	// 4. Prune expired PAR sessions
	_, err = s.pool.Exec(ctx, "DELETE FROM pushed_authorization_requests WHERE expires_at <= NOW()")
	if err != nil {
		return fmt.Errorf("prune expired pushed auth requests: %w", err)
	}

	// 5. Prune expired DPoP proofs
	_, err = s.pool.Exec(ctx, "DELETE FROM dpop_proofs WHERE expires_at <= NOW()")
	if err != nil {
		return fmt.Errorf("prune expired dpop proofs: %w", err)
	}

	return nil
}

func (s *PostgresStorage) SavePAR(ctx context.Context, req model.PushedAuthorizationRequest) error {
	_, err := s.queries.SavePAR(ctx, sqlcdb.SavePARParams{
		TenantUuid:          toPGUUID(req.TenantID),
		RequestUri:          req.RequestURI,
		ClientID:            req.ClientID,
		RedirectUri:         req.RedirectURI,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.ChallengeMethod,
		Scopes:              req.Scopes,
		State:               req.State,
		Nonce:               req.Nonce,
		IdpHint:             req.IDPHint,
		AcrValues:           req.ACRValues,
		ExpiresAt:           toPGTimestamptz(req.ExpiresAt),
	})
	if err != nil {
		return fmt.Errorf("save pushed authorization request: %w", err)
	}
	return nil
}

func (s *PostgresStorage) GetAndConsumePAR(ctx context.Context, tenantID uuid.UUID, requestURI string) (*model.PushedAuthorizationRequest, error) {
	row, err := s.queries.ConsumePAR(ctx, sqlcdb.ConsumePARParams{
		TenantUuid: toPGUUID(tenantID),
		RequestUri: requestURI,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("pushed authorization request %s not found: %w", requestURI, port.ErrSessionNotFound)
		}
		return nil, fmt.Errorf("get and consume pushed authorization request: %w", err)
	}

	expiresAt, err := pgTimestamptzToTime(row.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse PAR expires_at: %w", err)
	}

	return &model.PushedAuthorizationRequest{
		RequestURI:      row.RequestUri,
		TenantID:        tenantID,
		ClientID:        row.ClientID,
		RedirectURI:     row.RedirectUri,
		CodeChallenge:   row.CodeChallenge,
		ChallengeMethod: row.CodeChallengeMethod,
		Scopes:          row.Scopes,
		State:           row.State,
		Nonce:           row.Nonce,
		IDPHint:         row.IdpHint,
		ACRValues:       row.AcrValues,
		ExpiresAt:       expiresAt,
	}, nil
}

func (s *PostgresStorage) IsDPoPProofUsed(ctx context.Context, jti string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM dpop_proofs
			WHERE jti = $1 AND expires_at > NOW()
		)
	`, jti).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check DPoP proof replay: %w", err)
	}
	return exists, nil
}

func (s *PostgresStorage) SaveDPoPProof(ctx context.Context, jti string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO dpop_proofs (jti, expires_at)
		VALUES ($1, $2::timestamptz)
		ON CONFLICT (jti) DO NOTHING
	`, jti, toPGTimestamptz(expiresAt))
	if err != nil {
		return fmt.Errorf("save DPoP proof: %w", err)
	}
	return nil
}

func toPGUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func toPGInterval(duration time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: int64(duration / time.Microsecond), Valid: true}
}

func pgIntervalToDuration(interval pgtype.Interval) (time.Duration, error) {
	if !interval.Valid {
		return 0, errors.New("invalid interval value")
	}
	return time.Duration(interval.Microseconds) * time.Microsecond, nil
}

func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func pgUUIDToUUID(pgUUID pgtype.UUID) (uuid.UUID, error) {
	if !pgUUID.Valid {
		return uuid.Nil, errors.New("invalid UUID value")
	}
	return uuid.UUID(pgUUID.Bytes), nil
}

func toPGTimestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func pgTimestamptzToTime(pgTime pgtype.Timestamptz) (time.Time, error) {
	if !pgTime.Valid {
		return time.Time{}, errors.New("invalid timestamptz value")
	}
	return pgTime.Time, nil
}

func pgTimestamptzToTimeOrZero(pgTime pgtype.Timestamptz) time.Time {
	if !pgTime.Valid {
		return time.Time{}
	}
	return pgTime.Time
}

func (s *PostgresStorage) DeleteClient(ctx context.Context, tenantID uuid.UUID, clientID string) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM applications
		WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1::uuid) AND client_id = $2
	`, toPGUUID(tenantID), clientID)
	return err
}

func (s *PostgresStorage) GetIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ip.id, ip.idp_type, ip.enabled, ip.alias_name, ip.config, ip.name, ip.partition_id, ip.created_at, ip.updated_at
		FROM identity_providers ip
		JOIN tenants t ON t.id = ip.tenant_id
		WHERE t.tenant_uuid = $1::uuid
		ORDER BY ip.alias_name ASC
	`, toPGUUID(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []model.IdentityProvider
	for rows.Next() {
		p, err := scanIdentityProviderRow(rows, tenantID)
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	return providers, nil
}

func (s *PostgresStorage) DeleteIdentityProvider(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM identity_providers
		WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1::uuid) AND id = $2::uuid
	`, toPGUUID(tenantID), toPGUUID(idpID))
	return err
}

func scanUserProfileRow(row pgx.Row, tenantID uuid.UUID) (model.UserProfile, error) {
	var id pgtype.UUID
	var preferredUsername string
	var name string
	var email string
	var emailVerified bool
	var partitionID int64
	var createdAt, updatedAt pgtype.Timestamptz

	if err := row.Scan(&id, &preferredUsername, &name, &email, &emailVerified, &partitionID, &createdAt, &updatedAt); err != nil {
		return model.UserProfile{}, err
	}

	parsedID, err := pgUUIDToUUID(id)
	if err != nil {
		return model.UserProfile{}, err
	}

	parsedCreatedAt, err := pgTimestamptzToTime(createdAt)
	if err != nil {
		return model.UserProfile{}, err
	}

	parsedUpdatedAt, err := pgTimestamptzToTime(updatedAt)
	if err != nil {
		return model.UserProfile{}, err
	}

	return model.UserProfile{
		ID:                parsedID,
		TenantID:          tenantID,
		PreferredUsername: preferredUsername,
		Name:              name,
		Email:             email,
		EmailVerified:     emailVerified,
		PartitionID:       partitionID,
		CreatedAt:         parsedCreatedAt,
		UpdatedAt:         parsedUpdatedAt,
	}, nil
}

func (s *PostgresStorage) GetUserProfilesByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.UserProfile, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT up.id, up.preferred_username, up.name, up.email, up.email_verified, up.partition_id, up.created_at, up.updated_at
		FROM user_profiles up
		JOIN tenants t ON t.id = up.tenant_id
		WHERE t.tenant_uuid = $1::uuid
		ORDER BY up.preferred_username ASC
	`, toPGUUID(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var profiles []model.UserProfile
	for rows.Next() {
		profile, err := scanUserProfileRow(rows, tenantID)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return profiles, nil
}

func (s *PostgresStorage) DeleteUserProfile(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM user_profiles
		WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1::uuid) AND id = $2::uuid
	`, toPGUUID(tenantID), toPGUUID(userID))
	return err
}

func (s *PostgresStorage) UpdateUserProfile(ctx context.Context, tenantID uuid.UUID, profile model.UserProfile) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE user_profiles
		SET preferred_username = $1, name = $2, email = $3, email_verified = $4, partition_id = $5
		WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $6::uuid) AND id = $7::uuid
	`, profile.PreferredUsername, profile.Name, profile.Email, profile.EmailVerified, profile.PartitionID, toPGUUID(tenantID), toPGUUID(profile.ID))
	return err
}

func (s *PostgresStorage) GetUserIdentities(ctx context.Context, userProfileID uuid.UUID) ([]model.UserIdentity, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_profile_id, identity_provider_id, external_identity_id, login_count, last_login_at, last_verification_attempt, failed_verification_count, blocked, coupled_at
		FROM identities
		WHERE user_profile_id = $1::uuid
	`, toPGUUID(userProfileID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var identities []model.UserIdentity
	for rows.Next() {
		var id, upID, idpID pgtype.UUID
		var extID string
		var loginCount int
		var lastLogin, lastAttempt pgtype.Timestamptz
		var failedVerificationCount int
		var blocked bool
		var coupled pgtype.Timestamptz
		if err := rows.Scan(&id, &upID, &idpID, &extID, &loginCount, &lastLogin, &lastAttempt, &failedVerificationCount, &blocked, &coupled); err != nil {
			return nil, err
		}
		parsedID, _ := pgUUIDToUUID(id)
		parsedUP, _ := pgUUIDToUUID(upID)
		parsedIDP, _ := pgUUIDToUUID(idpID)
		identities = append(identities, model.UserIdentity{
			ID:                        parsedID,
			UserProfileID:             parsedUP,
			IdentityProviderID:        parsedIDP,
			ExternalIdentityID:        extID,
			LoginCount:                loginCount,
			LastLoginAt:               pgTimestamptzToTimeOrZero(lastLogin),
			LastVerificationAttemptAt: pgTimestamptzToTimeOrZero(lastAttempt),
			FailedVerificationCount:   failedVerificationCount,
			Blocked:                   blocked,
			CoupledAt:                 pgTimestamptzToTimeOrZero(coupled),
		})
	}
	return identities, nil
}

func (s *PostgresStorage) DecoupleIdentity(ctx context.Context, userProfileID uuid.UUID, identityProviderID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM identities
		WHERE user_profile_id = $1::uuid AND identity_provider_id = $2::uuid
	`, toPGUUID(userProfileID), toPGUUID(identityProviderID))
	return err
}

func (s *PostgresStorage) SaveRefreshToken(ctx context.Context, token model.RefreshToken) error {
	_, err := s.queries.SaveRefreshToken(ctx, sqlcdb.SaveRefreshTokenParams{
		TenantUuid:    toPGUUID(token.TenantID),
		TokenID:       token.TokenID,
		ClientID:      token.ClientID,
		Subject:       token.Subject,
		Scopes:        token.Scopes,
		TokenFamilyID: token.TokenFamilyID,
		IsUsed:        token.IsUsed,
		ExpiresAt:     toPGTimestamptz(token.ExpiresAt),
	})
	if err != nil {
		return fmt.Errorf("save refresh token: %w", err)
	}
	return nil
}

func (s *PostgresStorage) GetRefreshToken(ctx context.Context, tokenID string) (*model.RefreshToken, error) {
	row, err := s.queries.GetRefreshToken(ctx, tokenID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("refresh token %s: %w", tokenID, port.ErrSessionNotFound)
		}
		return nil, fmt.Errorf("get refresh token: %w", err)
	}

	tenantUUID, err := pgUUIDToUUID(row.TenantUuid)
	if err != nil {
		return nil, fmt.Errorf("get refresh token: parse tenant UUID: %w", err)
	}

	expiresAt, err := pgTimestamptzToTime(row.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("get refresh token: parse expires_at: %w", err)
	}

	createdAt, err := pgTimestamptzToTime(row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get refresh token: parse created_at: %w", err)
	}

	return &model.RefreshToken{
		TokenID:       row.TokenID,
		TenantID:      tenantUUID,
		ClientID:      row.ClientID,
		Subject:       row.Subject,
		Scopes:        row.Scopes,
		TokenFamilyID: row.TokenFamilyID,
		IsUsed:        row.IsUsed,
		ExpiresAt:     expiresAt,
		CreatedAt:     createdAt,
	}, nil
}

func (s *PostgresStorage) MarkRefreshTokenUsed(ctx context.Context, tokenID string) error {
	_, err := s.queries.MarkRefreshTokenUsed(ctx, tokenID)
	if err != nil {
		return fmt.Errorf("mark refresh token used: %w", err)
	}
	return nil
}

func (s *PostgresStorage) RevokeRefreshTokenFamily(ctx context.Context, tokenFamilyID string) error {
	_, err := s.queries.RevokeRefreshTokenFamily(ctx, tokenFamilyID)
	if err != nil {
		return fmt.Errorf("revoke refresh token family: %w", err)
	}
	return nil
}

func (s *PostgresStorage) PurgeTenantSessionsAndTokens(ctx context.Context, tenantID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		DELETE FROM auth_sessions
		WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1::uuid)
	`, toPGUUID(tenantID))
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		DELETE FROM refresh_tokens
		WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1::uuid)
	`, toPGUUID(tenantID))
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *PostgresStorage) GetPartitions(ctx context.Context, tenantID uuid.UUID) ([]model.Partition, error) {
	rows, err := s.queries.GetPartitions(ctx, toPGUUID(tenantID))
	if err != nil {
		return nil, fmt.Errorf("get partitions: %w", err)
	}

	partitions := make([]model.Partition, len(rows))
	for i, r := range rows {
		partitions[i] = model.Partition{
			ID:        r.ID,
			TenantID:  tenantID,
			Name:      r.Name,
			AliasName: r.AliasName,
		}
	}
	return partitions, nil
}

func (s *PostgresStorage) GetPartitionByAlias(ctx context.Context, tenantID uuid.UUID, alias string) (*model.Partition, error) {
	row, err := s.queries.GetPartitionByAlias(ctx, sqlcdb.GetPartitionByAliasParams{
		Column1:   toPGUUID(tenantID),
		AliasName: alias,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("get partition by alias: %w", port.ErrPartitionNotFound)
		}
		return nil, fmt.Errorf("get partition by alias: %w", err)
	}

	return &model.Partition{
		ID:        row.ID,
		TenantID:  tenantID,
		Name:      row.Name,
		AliasName: row.AliasName,
	}, nil
}

func (s *PostgresStorage) CreatePartition(ctx context.Context, tenantID uuid.UUID, name, aliasName string) (*model.Partition, error) {
	row, err := s.queries.CreatePartition(ctx, sqlcdb.CreatePartitionParams{
		Column1:   toPGUUID(tenantID),
		Name:      name,
		AliasName: aliasName,
	})
	if err != nil {
		return nil, fmt.Errorf("create partition: %w", err)
	}

	return &model.Partition{
		ID:        row.ID,
		TenantID:  tenantID,
		Name:      row.Name,
		AliasName: row.AliasName,
	}, nil
}

func (s *PostgresStorage) GetPartitionByID(ctx context.Context, id int64) (*model.Partition, error) {
	row, err := s.queries.GetPartitionByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("get partition by ID: %w", port.ErrPartitionNotFound)
		}
		return nil, fmt.Errorf("get partition by ID: %w", err)
	}

	var tenantUUID pgtype.UUID
	err = s.pool.QueryRow(ctx, "SELECT tenant_uuid FROM tenants WHERE id = $1", row.TenantID).Scan(&tenantUUID)
	if err != nil {
		return nil, fmt.Errorf("get partition tenant: %w", err)
	}
	tID, err := pgUUIDToUUID(tenantUUID)
	if err != nil {
		return nil, fmt.Errorf("parse partition tenant uuid: %w", err)
	}

	return &model.Partition{
		ID:        row.ID,
		TenantID:  tID,
		Name:      row.Name,
		AliasName: row.AliasName,
	}, nil
}
