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

	commandTag, err := s.queries.SaveClient(ctx, sqlcdb.SaveClientParams{
		TenantUuid:             toPGUUID(client.TenantID),
		ID:                     toPGUUID(clientUUID),
		ClientID:               client.ClientID,
		ClientSecretHash:       client.ClientSecret,
		ClientName:             client.ClientName,
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

	return &model.ClientApplication{
		ID:                     id.String(),
		TenantID:               tenantID,
		ClientID:               row.ClientID,
		ClientSecret:           row.ClientSecretHash,
		ClientName:             row.ClientName,
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
	}, nil
}

func (s *PostgresStorage) GetClientsByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.ClientApplication, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			a.id,
			a.client_id,
			a.client_secret_hash,
			a.client_name,
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
			a.allowed_audiences
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
		var id pgtype.UUID
		var clientID string
		var clientSecret *string
		var clientName string
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

		err = rows.Scan(
			&id,
			&clientID,
			&clientSecret,
			&clientName,
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
		)
		if err != nil {
			return nil, fmt.Errorf("scan client application: %w", err)
		}

		parsedID, err := pgUUIDToUUID(id)
		if err != nil {
			return nil, fmt.Errorf("parse client UUID: %w", err)
		}
		parsedAccess, err := pgIntervalToDuration(accessLifetime)
		if err != nil {
			return nil, fmt.Errorf("parse access lifetime: %w", err)
		}
		parsedRefresh, err := pgIntervalToDuration(refreshLifetime)
		if err != nil {
			return nil, fmt.Errorf("parse refresh lifetime: %w", err)
		}
		parsedIDToken, err := pgIntervalToDuration(idTokenLifetime)
		if err != nil {
			return nil, fmt.Errorf("parse id token lifetime: %w", err)
		}

		clients = append(clients, model.ClientApplication{
			ID:                     parsedID.String(),
			TenantID:               tenantID,
			ClientID:               clientID,
			ClientSecret:           clientSecret,
			ClientName:             clientName,
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
		})
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

	return &model.Tenant{
		ID:                  tenantID,
		Name:                row.Name,
		Domain:              row.DomainName,
		IsActive:            row.IsActive,
		CreatedAt:           createdAt,
		PredefinedScopes:    row.PredefinedScopes,
		PredefinedAudiences: row.PredefinedAudiences,
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

	return &model.Tenant{
		ID:                  resolvedID,
		Name:                row.Name,
		Domain:              row.DomainName,
		IsActive:            row.IsActive,
		CreatedAt:           createdAt,
		PredefinedScopes:    row.PredefinedScopes,
		PredefinedAudiences: row.PredefinedAudiences,
	}, nil
}

func (s *PostgresStorage) CreateTenant(ctx context.Context, tenant model.Tenant) error {
	commandTag, err := s.queries.CreateTenant(ctx, sqlcdb.CreateTenantParams{
		TenantUuid:          toPGUUID(tenant.ID),
		Name:                tenant.Name,
		DomainName:          tenant.Domain,
		IsActive:            tenant.IsActive,
		CreatedAt:           toPGTimestamptz(tenant.CreatedAt),
		PredefinedScopes:    tenant.PredefinedScopes,
		PredefinedAudiences: tenant.PredefinedAudiences,
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
		INSERT INTO identity_providers (id, tenant_id, idp_type, enabled, alias_name, config)
		SELECT $1::uuid, t.id, $2, $3, $4, $5::jsonb
		FROM tenants t
		WHERE t.tenant_uuid = $6::uuid
		ON CONFLICT (id) DO UPDATE SET
			idp_type = EXCLUDED.idp_type,
			enabled = EXCLUDED.enabled,
			alias_name = EXCLUDED.alias_name,
			config = EXCLUDED.config
	`, toPGUUID(provider.ID), provider.IDPType, provider.Enabled, provider.Alias, string(configJSON), toPGUUID(tenantID))
	if err != nil {
		return fmt.Errorf("create identity provider: %w", err)
	}
	return nil
}

func (s *PostgresStorage) GetEnabledIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ip.id, ip.idp_type, ip.enabled, ip.alias_name, ip.config
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
		var providerID pgtype.UUID
		var idpType string
		var enabled bool
		var alias string
		var configJSON []byte
		if err := rows.Scan(&providerID, &idpType, &enabled, &alias, &configJSON); err != nil {
			return nil, fmt.Errorf("scan identity provider: %w", err)
		}
		providerUUID, err := pgUUIDToUUID(providerID)
		if err != nil {
			return nil, fmt.Errorf("parse provider UUID: %w", err)
		}
		providerCfg := model.IdentityProviderConfig{}
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &providerCfg); err != nil {
				return nil, fmt.Errorf("unmarshal provider config: %w", err)
			}
		}
		providers = append(providers, model.IdentityProvider{
			ID:       providerUUID,
			TenantID: tenantID,
			IDPType:  idpType,
			Enabled:  enabled,
			Alias:    alias,
			Config:   providerCfg,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identity providers: %w", err)
	}
	return providers, nil
}

func (s *PostgresStorage) GetUserProfileByIdentifier(ctx context.Context, tenantID uuid.UUID, providerID uuid.UUID, identifier string) (*model.UserProfile, error) {
	var configJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT config
		FROM identity_providers ip
		JOIN tenants t ON t.id = ip.tenant_id
		WHERE t.tenant_uuid = $1::uuid AND ip.id = $2::uuid
	`, toPGUUID(tenantID), toPGUUID(providerID)).Scan(&configJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("identity provider not found: %w", port.ErrIdentityProviderNotFound)
		}
		return nil, fmt.Errorf("get identity provider config: %w", err)
	}

	var providerCfg model.IdentityProviderConfig
	if len(configJSON) > 0 {
		_ = json.Unmarshal(configJSON, &providerCfg)
	}
	usernameField := "preferredUsername"
	if providerCfg.UsernameField != "" {
		usernameField = providerCfg.UsernameField
	}

	var id pgtype.UUID
	var preferredUsername string
	var name string
	var email string
	var emailVerified bool

	var query string
	if usernameField == "email" {
		query = `
			SELECT id, preferred_username, name, email, email_verified
			FROM user_profiles
			WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1::uuid)
			  AND email = $2
		`
	} else {
		query = `
			SELECT id, preferred_username, name, email, email_verified
			FROM user_profiles
			WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1::uuid)
			  AND preferred_username = $2
		`
	}

	err = s.pool.QueryRow(ctx, query, toPGUUID(tenantID), identifier).Scan(&id, &preferredUsername, &name, &email, &emailVerified)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user profile not found for identifier %s: %w", identifier, port.ErrUserProfileNotFound)
		}
		return nil, fmt.Errorf("lookup user profile: %w", err)
	}

	profileID, err := pgUUIDToUUID(id)
	if err != nil {
		return nil, fmt.Errorf("parse profile UUID: %w", err)
	}

	return &model.UserProfile{
		ID:                profileID,
		PreferredUsername: preferredUsername,
		Name:              name,
		Email:             email,
		EmailVerified:     emailVerified,
	}, nil
}

func (s *PostgresStorage) GetPasswordCredential(ctx context.Context, userProfileID uuid.UUID, providerID uuid.UUID) (*model.PasswordCredential, error) {
	var hash string
	err := s.pool.QueryRow(ctx, `
		SELECT password_hash
		FROM passwords
		WHERE user_profile_id = $1::uuid AND identity_provider_id = $2::uuid
	`, toPGUUID(userProfileID), toPGUUID(providerID)).Scan(&hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("password credential not found: %w", port.ErrPasswordCredentialNotFound)
		}
		return nil, fmt.Errorf("get password credential: %w", err)
	}
	return &model.PasswordCredential{
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		Argon2Hash:         hash,
	}, nil
}

func (s *PostgresStorage) GetIdentityByProfileAndProvider(ctx context.Context, userProfileID uuid.UUID, providerID uuid.UUID) (*model.UserIdentity, error) {
	var id pgtype.UUID
	var externalIdentityID string
	var loginCount int
	var lastLoginAt pgtype.Timestamptz
	var lastLoginAttempt pgtype.Timestamptz
	var blocked bool
	var coupledAt pgtype.Timestamptz

	err := s.pool.QueryRow(ctx, `
		SELECT id, external_identity_id, login_count, last_login_at, last_login_attempt, blocked, coupled_at
		FROM identities
		WHERE user_profile_id = $1::uuid AND identity_provider_id = $2::uuid
	`, toPGUUID(userProfileID), toPGUUID(providerID)).Scan(&id, &externalIdentityID, &loginCount, &lastLoginAt, &lastLoginAttempt, &blocked, &coupledAt)
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
	if lastLoginAttempt.Valid {
		parsedAttempt, _ = pgTimestamptzToTime(lastLoginAttempt)
	}

	return &model.UserIdentity{
		ID:                 identityUUID,
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		ExternalIdentityID: externalIdentityID,
		LoginCount:         loginCount,
		LastLoginAt:        lastLoginTime,
		LastLoginAttemptAt: parsedAttempt,
		Blocked:            blocked,
		CoupledAt:          coupledTime,
	}, nil
}

func (s *PostgresStorage) UpsertIdentity(ctx context.Context, identity model.UserIdentity) error {
	var attempt pgtype.Timestamptz
	if !identity.LastLoginAttemptAt.IsZero() {
		attempt = toPGTimestamptz(identity.LastLoginAttemptAt)
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO identities (id, user_profile_id, identity_provider_id, external_identity_id, login_count, last_login_at, last_login_attempt, blocked, coupled_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6::timestamptz, $7::timestamptz, $8, $9::timestamptz)
		ON CONFLICT (user_profile_id, identity_provider_id) DO UPDATE SET
			external_identity_id = EXCLUDED.external_identity_id,
			login_count = EXCLUDED.login_count,
			last_login_at = EXCLUDED.last_login_at,
			last_login_attempt = EXCLUDED.last_login_attempt,
			blocked = EXCLUDED.blocked,
			coupled_at = EXCLUDED.coupled_at
	`, toPGUUID(identity.ID), toPGUUID(identity.UserProfileID), toPGUUID(identity.IdentityProviderID), identity.ExternalIdentityID, identity.LoginCount, toPGTimestamptz(identity.LastLoginAt), attempt, identity.Blocked, toPGTimestamptz(identity.CoupledAt))
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
		INSERT INTO interaction_sessions (id, tenant_id, client_id, redirect_uri, code_challenge, code_challenge_method, idp_hint, expires_at)
		SELECT $1::uuid, t.id, $2, $3, $4, $5, $6, $7::timestamptz
		FROM tenants t
		WHERE t.tenant_uuid = $8::uuid
	`, toPGUUID(session.ID), session.ClientID, session.RedirectURI, session.CodeChallenge, session.ChallengeMethod, stringPtr(session.IDPHint), toPGTimestamptz(session.ExpiresAt), toPGUUID(session.TenantID))
	if err != nil {
		return fmt.Errorf("save interaction session: %w", err)
	}
	return nil
}

func (s *PostgresStorage) GetAndConsumeInteractionSession(ctx context.Context, id uuid.UUID) (*model.InteractionSession, error) {
	var clientID string
	var redirectURI string
	var codeChallenge string
	var codeChallengeMethod string
	var idpHint *string
	var expiresAt pgtype.Timestamptz
	var tenantUUID pgtype.UUID

	err := s.pool.QueryRow(ctx, `
		DELETE FROM interaction_sessions
		WHERE id = $1::uuid
		RETURNING client_id, redirect_uri, code_challenge, code_challenge_method, idp_hint, expires_at,
		          (SELECT tenant_uuid FROM tenants WHERE id = tenant_id)
	`, toPGUUID(id)).Scan(&clientID, &redirectURI, &codeChallenge, &codeChallengeMethod, &idpHint, &expiresAt, &tenantUUID)
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
	_, err := s.pool.Exec(ctx, "DELETE FROM revoked_tokens WHERE expires_at <= NOW()")
	if err != nil {
		return fmt.Errorf("prune expired tokens: %w", err)
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
