package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	appEnv  string
}

// Compile-time type assertions to guarantee strict structural compliance.
var _ port.Storage = (*PostgresStorage)(nil)
var _ port.CryptoStorage = (*PostgresStorage)(nil)
var _ port.AdminStorage = (*PostgresStorage)(nil)

func NewPostgresStorage(pool *pgxpool.Pool, appEnv string) *PostgresStorage {
	return &PostgresStorage{
		pool:    pool,
		queries: sqlcdb.New(pool),
		appEnv:  appEnv,
	}
}

// TODO There's lots of storage functions using inline SQL queries. Assess which can be moved to query files.

// =========================================================================
// DATA TYPE CONVERSION HELPERS
// =========================================================================

func toPGUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func pgUUIDToUUID(pgUUID pgtype.UUID) (uuid.UUID, error) {
	if !pgUUID.Valid {
		return uuid.Nil, errors.New("invalid UUID value")
	}
	return uuid.UUID(pgUUID.Bytes), nil
}

func pgIntervalToDuration(interval pgtype.Interval) (time.Duration, error) {
	if !interval.Valid {
		return 0, errors.New("invalid interval value")
	}
	return time.Duration(interval.Microseconds) * time.Microsecond, nil
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

func toPGTimestamptzPtr(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{Valid: false}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

func pgTimestamptzToTimePtr(pgTime pgtype.Timestamptz) *time.Time {
	if !pgTime.Valid {
		return nil
	}
	t := pgTime.Time
	return &t
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

// =========================================================================
// PORT.STORAGE INTERFACE IMPLEMENTATION (RUNTIME HOT-PATHS)
// =========================================================================

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

	scheme := model.SchemeHttps
	if s.appEnv == "local" {
		scheme = model.SchemeHttp
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
		Scheme:           scheme,
	}, nil
}

func (s *PostgresStorage) ResolveTenantByUUID(ctx context.Context, tenantID uuid.UUID) (*model.Tenant, error) {
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

	scheme := model.SchemeHttps
	if s.appEnv == "local" {
		scheme = model.SchemeHttp
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
		Scheme:           scheme,
	}, nil
}

// RegisterApplication persists a lightweight dynamic or static application row to the database.
// It relies on a high-performance CTE to map the domain tenant UUID to the internal database integer transparently.
func (s *PostgresStorage) RegisterApplication(ctx context.Context, app model.Application) error {
	_, err := s.queries.RegisterApplication(ctx, sqlcdb.RegisterApplicationParams{
		ID:               toPGUUID(app.ID),
		TenantUuid:       toPGUUID(app.TenantID), // CTE automatically resolves this to internal DB integer
		ProfileID:        toPGUUID(app.ProfileID),
		GroupID:          toPGUUID(app.GroupID),
		ApplicationName:  app.ApplicationName,
		ClientID:         app.ClientID,
		ClientSecretHash: app.ClientSecretHash,
		IsDynamic:        app.IsDynamic,
		IsEnabled:        app.IsEnabled,
		CreatedAt:        toPGTimestamptz(app.CreatedAt),
		UpdatedAt:        toPGTimestamptz(app.UpdatedAt),
		LastUsedAt:       toPGTimestamptz(app.LastUsedAt),
	})
	if err != nil {
		return fmt.Errorf("insert application instance: %w", err)
	}
	return nil
}

// GetApplicationByClientID pulls your lightweight identity row joined across its shared profiles and groups.
// It tracks clean, independent timestamp metrics directly from each underlying database layer.
func (s *PostgresStorage) GetApplicationByClientID(ctx context.Context, tenantUUID uuid.UUID, clientID string) (*model.Application, *model.ApplicationProfile, *model.ApplicationGroup, error) {
	row, err := s.queries.GetApplicationByClientID(ctx, sqlcdb.GetApplicationByClientIDParams{
		ClientID:   clientID,
		TenantUuid: toPGUUID(tenantUUID), // Materialized CTE join scans this key in constant O(1) time
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, nil, fmt.Errorf("application %s for tenant %s: %w", clientID, tenantUUID, port.ErrApplicationNotFound)
		}
		return nil, nil, nil, fmt.Errorf("get application by client id: %w", err)
	}

	appID, err := pgUUIDToUUID(row.AppID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse application UUID: %w", err)
	}
	profileID, err := pgUUIDToUUID(row.ProfileID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse profile UUID: %w", err)
	}
	groupID, err := pgUUIDToUUID(row.GroupID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse group UUID: %w", err)
	}

	appCreatedAt, err := pgTimestamptzToTime(row.AppCreatedAt)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse app created_at: %w", err)
	}
	appUpdatedAt, err := pgTimestamptzToTime(row.AppUpdatedAt)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse app updated_at: %w", err)
	}
	appLastUsedAt, err := pgTimestamptzToTime(row.LastUsedAt)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse app last_used_at: %w", err)
	}

	app := &model.Application{
		ID:               appID,
		TenantID:         tenantUUID,
		ProfileID:        profileID,
		GroupID:          groupID,
		ApplicationName:  row.ApplicationName,
		ClientID:         row.ClientID,
		ClientSecretHash: row.ClientSecretHash,
		IsEnabled:        row.AppEnabled,
		IsDynamic:        row.IsDynamic,
		CreatedAt:        appCreatedAt,
		UpdatedAt:        appUpdatedAt,
		LastUsedAt:       appLastUsedAt,
	}

	profileAccessLifetime, err := pgIntervalToDuration(row.AccessTokenLifetime)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse profile access lifetime: %w", err)
	}
	profileRefreshLifetime, err := pgIntervalToDuration(row.RefreshTokenLifetime)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse profile refresh lifetime: %w", err)
	}
	profileIDTokenLifetime, err := pgIntervalToDuration(row.IDTokenLifetime)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse profile id token lifetime: %w", err)
	}
	profileUpdatedAt, err := pgTimestamptzToTime(row.ProfileUpdatedAt)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse profile updated_at: %w", err)
	}

	// Convert row.GrantTypes string slice to []model.GrantType slice
	profileGrantTypes := make([]model.GrantType, len(row.GrantTypes))
	for i, gt := range row.GrantTypes {
		profileGrantTypes[i] = model.GrantType(gt)
	}

	// Convert row.ResponseTypes string slice to []model.ResponseType slice
	profileResponseTypes := make([]model.ResponseType, len(row.ResponseTypes))
	for i, rt := range row.ResponseTypes {
		profileResponseTypes[i] = model.ResponseType(rt)
	}

	profile := &model.ApplicationProfile{
		ID:                      profileID,
		TenantID:                tenantUUID,
		ProfileName:             row.ProfileName,
		IsEnabled:               row.ProfileEnabled,
		TokenEndpointAuthMethod: model.TokenEndpointAuthMethod(row.TokenEndpointAuthMethod),
		GrantTypes:              profileGrantTypes,
		ResponseTypes:           profileResponseTypes,
		AccessTokenLifetime:     profileAccessLifetime,
		RefreshTokenLifetime:    profileRefreshLifetime,
		IDTokenLifetime:         profileIDTokenLifetime,
		EnforceRTR:              row.EnforceRtr,
		SigningAlgorithm:        model.SignatureAlgorithm(row.SigningAlgorithm),
		UpdatedAt:               profileUpdatedAt,
	}

	groupUpdatedAt, err := pgTimestamptzToTime(row.GroupUpdatedAt) // Maps raw group update metric
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse group updated_at: %w", err)
	}

	// Clean conversion mapping of aggregated pgtype.UUID arrays down to Go uuid.UUID slices
	allowedIDPIDs := make([]uuid.UUID, len(row.AllowedIdpIds))
	for i, pgID := range row.AllowedIdpIds {
		allowedIDPIDs[i], _ = pgUUIDToUUID(pgID)
	}

	var defaultIDPID *uuid.UUID
	if row.DefaultIdpID.Valid {
		parsed, _ := pgUUIDToUUID(row.DefaultIdpID)
		defaultIDPID = &parsed
	}

	group := &model.ApplicationGroup{
		ID:                     groupID,
		TenantID:               tenantUUID,
		GroupName:              row.GroupName,
		IsEnabled:              row.GroupEnabled,
		RedirectURI:            row.RedirectUri,
		RedirectURIs:           row.RedirectUris,
		PostLogoutRedirectURIs: row.PostLogoutRedirectUris,
		FrontChannelLogoutURI:  valueOrEmpty(row.FrontChannelLogoutUri),
		BackChannelLogoutURI:   valueOrEmpty(row.BackChannelLogoutUri),
		AllowedScopes:          row.AllowedScopes,
		DefaultScopes:          row.DefaultScopes,
		AllowedAudiences:       row.AllowedAudiences,
		AllowedIDPIDs:          allowedIDPIDs,
		DefaultIDPID:           defaultIDPID,
		UpdatedAt:              groupUpdatedAt,
	}

	return app, profile, group, nil
}

// GetProfileByName resolves a shared protocol specification capability row using its template handle.
func (s *PostgresStorage) GetProfileByName(ctx context.Context, tenantUUID uuid.UUID, name string) (*model.ApplicationProfile, error) {
	row, err := s.queries.GetProfileByName(ctx, sqlcdb.GetProfileByNameParams{
		ProfileName: name,
		TenantUuid:  toPGUUID(tenantUUID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("application profile '%s' not found for tenant %s: %w", name, tenantUUID, port.ErrProfileNotFound)
		}
		return nil, fmt.Errorf("get profile by name: %w", err)
	}

	profileID, err := pgUUIDToUUID(row.ID)
	if err != nil {
		return nil, fmt.Errorf("parse profile UUID: %w", err)
	}
	accessLifetime, err := pgIntervalToDuration(row.AccessTokenLifetime)
	if err != nil {
		return nil, fmt.Errorf("parse profile access interval: %w", err)
	}
	refreshLifetime, err := pgIntervalToDuration(row.RefreshTokenLifetime)
	if err != nil {
		return nil, fmt.Errorf("parse profile refresh interval: %w", err)
	}
	idTokenLifetime, err := pgIntervalToDuration(row.IDTokenLifetime)
	if err != nil {
		return nil, fmt.Errorf("parse profile id token interval: %w", err)
	}
	createdAt, err := pgTimestamptzToTime(row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse profile created_at: %w", err)
	}
	updatedAt, err := pgTimestamptzToTime(row.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse profile updated_at: %w", err)
	}

	// Convert row.GrantTypes string slice to []model.GrantType slice
	profileGrantTypes := make([]model.GrantType, len(row.GrantTypes))
	for i, gt := range row.GrantTypes {
		profileGrantTypes[i] = model.GrantType(gt)
	}

	// Convert row.ResponseTypes string slice to []model.ResponseType slice
	profileResponseTypes := make([]model.ResponseType, len(row.ResponseTypes))
	for i, rt := range row.ResponseTypes {
		profileResponseTypes[i] = model.ResponseType(rt)
	}

	return &model.ApplicationProfile{
		ID:                      profileID,
		TenantID:                tenantUUID,
		ProfileName:             row.ProfileName,
		IsEnabled:               row.IsEnabled,
		TokenEndpointAuthMethod: model.TokenEndpointAuthMethod(row.TokenEndpointAuthMethod),
		GrantTypes:              profileGrantTypes,
		ResponseTypes:           profileResponseTypes,
		AccessTokenLifetime:     accessLifetime,
		RefreshTokenLifetime:    refreshLifetime,
		IDTokenLifetime:         idTokenLifetime,
		EnforceRTR:              row.EnforceRtr,
		SigningAlgorithm:        model.SignatureAlgorithm(row.SigningAlgorithm),
		CreatedAt:               createdAt,
		UpdatedAt:               updatedAt,
	}, nil
}

// GetGroupByName resolves a shared network routing configuration matrix row using its software blueprint handle.
func (s *PostgresStorage) GetGroupByName(ctx context.Context, tenantUUID uuid.UUID, name string) (*model.ApplicationGroup, error) {
	row, err := s.queries.GetGroupByName(ctx, sqlcdb.GetGroupByNameParams{
		GroupName:  name,
		TenantUuid: toPGUUID(tenantUUID), // Correctly converts domain uuid.UUID to pgtype.UUID
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("application group '%s' not found for tenant %s: %w", name, tenantUUID, port.ErrGroupNotFound)
		}
		return nil, fmt.Errorf("get group by name: %w", err)
	}

	groupID, err := pgUUIDToUUID(row.ID) // Converts pgtype.UUID back to domain uuid.UUID
	if err != nil {
		return nil, fmt.Errorf("parse group UUID: %w", err)
	}
	createdAt, err := pgTimestamptzToTime(row.CreatedAt) // Safe pgtype.Timestamptz parsing
	if err != nil {
		return nil, fmt.Errorf("parse group created_at: %w", err)
	}
	updatedAt, err := pgTimestamptzToTime(row.UpdatedAt) // Safe pgtype.Timestamptz parsing
	if err != nil {
		return nil, fmt.Errorf("parse group updated_at: %w", err)
	}

	allowedIDPIDs := make([]uuid.UUID, len(row.AllowedIdpIds))
	for i, pgID := range row.AllowedIdpIds {
		allowedIDPIDs[i], _ = pgUUIDToUUID(pgID)
	}

	var defaultIDPID *uuid.UUID
	if row.DefaultIdpID.Valid {
		parsed, _ := pgUUIDToUUID(row.DefaultIdpID)
		defaultIDPID = &parsed
	}

	return &model.ApplicationGroup{
		ID:                     groupID,
		TenantID:               tenantUUID,
		GroupName:              row.GroupName,
		IsEnabled:              row.IsEnabled,
		RedirectURI:            row.RedirectUri,
		RedirectURIs:           row.RedirectUris,
		PostLogoutRedirectURIs: row.PostLogoutRedirectUris,
		FrontChannelLogoutURI:  valueOrEmpty(row.FrontChannelLogoutUri),
		BackChannelLogoutURI:   valueOrEmpty(row.BackChannelLogoutUri),
		AllowedScopes:          row.AllowedScopes,
		DefaultScopes:          row.DefaultScopes,
		AllowedAudiences:       row.AllowedAudiences,
		AllowedIDPIDs:          allowedIDPIDs,
		DefaultIDPID:           defaultIDPID,
		CreatedAt:              createdAt,
		UpdatedAt:              updatedAt,
	}, nil
}

// =========================================================================
// PORT.STORAGE INTERFACE IMPLEMENTATION (SESSION, IDENTITY & CORE AUTH HANDLERS)
// =========================================================================

// SaveAuthSession registers transient authorization states using type-safe queries.
func (s *PostgresStorage) SaveAuthSession(ctx context.Context, session model.AuthorizationCodeSession) error {
	var parsedIDPUUID pgtype.UUID
	if session.IdentityProviderID != uuid.Nil {
		parsedIDPUUID = toPGUUID(session.IdentityProviderID)
	}

	err := s.queries.SaveAuthSession(ctx, sqlcdb.SaveAuthSessionParams{
		Code:                  session.Code,
		ClientID:              session.ClientID,
		Subject:               session.Subject,
		CodeChallenge:         session.CodeChallenge,
		ChallengeMethod:       session.ChallengeMethod,
		RedirectUri:           session.RedirectURI,
		Scopes:                session.Scopes,
		ExpiresAt:             toPGTimestamptz(session.ExpiresAt),
		SessionID:             session.SessionID,
		State:                 session.State,
		Nonce:                 session.Nonce,
		AcrValues:             session.ACRValues,
		IdentityProviderID:    parsedIDPUUID,
		IdentityProviderAlias: stringPtr(session.IdentityProviderAlias),
		TenantUuid:            toPGUUID(session.TenantID),
	})
	if err != nil {
		return fmt.Errorf("save auth session: %w", err)
	}
	return nil
}

// GetAndConsumeAuthSession executes an atomic single-trip read-and-delete operation.
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

	var localIDPUUID uuid.UUID
	var partitionID int64
	if row.IdentityProviderID.Valid {
		localIDPUUID, _ = pgUUIDToUUID(row.IdentityProviderID)
		if idp, err := s.queries.GetIdentityProviderByUUID(ctx, sqlcdb.GetIdentityProviderByUUIDParams{
			TenantUuid: toPGUUID(tenantID),
			IdpUuid:    row.IdentityProviderID,
		}); err == nil {
			partitionID = idp.PartitionID
		}
	}

	return &model.AuthorizationCodeSession{
		Code:                  row.Code,
		TenantID:              tenantID,
		PartitionID:           partitionID,
		ClientID:              row.ClientID,
		Subject:               row.Subject,
		CodeChallenge:         row.CodeChallenge,
		ChallengeMethod:       row.ChallengeMethod,
		RedirectURI:           row.RedirectUri,
		Scopes:                row.Scopes,
		ExpiresAt:             expiresAt,
		SessionID:             row.SessionID,
		State:                 row.State,
		Nonce:                 row.Nonce,
		ACRValues:             row.AcrValues,
		IdentityProviderID:    localIDPUUID,
		IdentityProviderAlias: valueOrEmpty(row.IdentityProviderAlias),
	}, nil
}

func (s *PostgresStorage) SaveInteractionSession(ctx context.Context, session model.InteractionSession) error {
	err := s.queries.SaveInteractionSession(ctx, sqlcdb.SaveInteractionSessionParams{
		TenantUuid:          toPGUUID(session.TenantID), // $1: Automatically typed by sqlc!
		ID:                  toPGUUID(session.ID),       // $2: Maps safely to pgtype.UUID
		ClientID:            session.ClientID,
		RedirectUri:         session.RedirectURI,
		CodeChallenge:       session.CodeChallenge,
		CodeChallengeMethod: session.ChallengeMethod,
		IdpHint:             stringPtr(session.IDPHint),
		ExpiresAt:           toPGTimestamptz(session.ExpiresAt),
		State:               session.State,
		Nonce:               session.Nonce,
		AcrValues:           session.ACRValues,
	})
	if err != nil {
		return fmt.Errorf("save interaction session: %w", err)
	}
	return nil
}

func (s *PostgresStorage) GetAndConsumeInteractionSession(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.InteractionSession, error) {
	// FIXED: Single-trip atomic consumption mapping
	row, err := s.queries.ConsumeInteractionSession(ctx, sqlcdb.ConsumeInteractionSessionParams{
		TenantUuid: toPGUUID(tenantID),
		ID:         toPGUUID(id),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("interaction session %s not found: %w", id, port.ErrInteractionSessionNotFound)
		}
		return nil, fmt.Errorf("get and consume interaction session: %w", err)
	}

	parsedTenantID, err := pgUUIDToUUID(row.TenantUuid)
	if err != nil {
		return nil, fmt.Errorf("parse tenant UUID: %w", err)
	}
	parsedExpiresAt, err := pgTimestamptzToTime(row.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}
	parsedID, err := pgUUIDToUUID(row.ID)
	if err != nil {
		return nil, fmt.Errorf("parse interaction session UUID: %w", err)
	}

	return &model.InteractionSession{
		ID:              parsedID,
		TenantID:        parsedTenantID,
		ClientID:        row.ClientID,
		RedirectURI:     row.RedirectUri,
		CodeChallenge:   row.CodeChallenge,
		ChallengeMethod: row.CodeChallengeMethod,
		IDPHint:         valueOrEmpty(row.IdpHint),
		ExpiresAt:       parsedExpiresAt,
		State:           row.State,
		Nonce:           row.Nonce,
		ACRValues:       row.AcrValues,
	}, nil
}

func (s *PostgresStorage) GetInteractionSession(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.InteractionSession, error) {
	// FIXED: Type-safe read path
	row, err := s.queries.GetInteractionSession(ctx, sqlcdb.GetInteractionSessionParams{
		TenantUuid: toPGUUID(tenantID),
		ID:         toPGUUID(id),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("interaction session %s not found: %w", id, port.ErrInteractionSessionNotFound)
		}
		return nil, fmt.Errorf("get interaction session: %w", err)
	}

	parsedTenantID, err := pgUUIDToUUID(row.TenantUuid)
	if err != nil {
		return nil, fmt.Errorf("parse tenant UUID: %w", err)
	}
	parsedExpiresAt, err := pgTimestamptzToTime(row.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}
	parsedID, err := pgUUIDToUUID(row.ID)
	if err != nil {
		return nil, fmt.Errorf("parse interaction session UUID: %w", err)
	}

	return &model.InteractionSession{
		ID:              parsedID,
		TenantID:        parsedTenantID,
		ClientID:        row.ClientID,
		RedirectURI:     row.RedirectUri,
		CodeChallenge:   row.CodeChallenge,
		ChallengeMethod: row.CodeChallengeMethod,
		IDPHint:         valueOrEmpty(row.IdpHint),
		ExpiresAt:       parsedExpiresAt,
		State:           row.State,
		Nonce:           row.Nonce,
		ACRValues:       row.AcrValues,
	}, nil
}

// RevokeToken registers an access or refresh token identifier in the central blacklist ledger.
// It accepts the authoritative expiration timestamp directly from the domain use case layer.
func (s *PostgresStorage) RevokeToken(ctx context.Context, tokenID string, expiresAt time.Time) error {
	err := s.queries.RevokeToken(ctx, sqlcdb.RevokeTokenParams{
		TokenID:   tokenID,
		ExpiresAt: toPGTimestamptz(expiresAt.UTC()), // Normalize to UTC at the infrastructure perimeter boundary
	})
	if err != nil {
		return fmt.Errorf("storage: failed to blacklist token identifier: %w", err)
	}

	return nil
}

// IsTokenRevoked interrogates the relational data blacklist to verify if an
// incoming cryptographic access or refresh handle has been administratively canceled.
func (s *PostgresStorage) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	isRevoked, err := s.queries.IsTokenRevoked(ctx, tokenID)
	if err != nil {
		return false, fmt.Errorf("storage: check token revocation failed: %w", err)
	}

	return isRevoked, nil
}

// RecordClientSessionLink appends an idempotent link record mapping an active browser single-sign-on
// session directly to an authorized client application footprint inside the database backend.
func (s *PostgresStorage) RecordClientSessionLink(ctx context.Context, tenantID uuid.UUID, sessionID string, clientID string, associatedAt time.Time) error {
	return s.queries.RecordClientSessionLink(ctx, sqlcdb.RecordClientSessionLinkParams{
		TenantID:     toPGUUID(tenantID),
		SessionID:    sessionID,
		ClientID:     clientID,
		AssociatedAt: toPGTimestamptz(associatedAt),
	})
}

// GetApplicationsLogoutContextBySession queries your relational database layout using an active session ID
// to extract only the target application nodes and logout destinations utilized during that specific browser lifecycle.
func (s *PostgresStorage) GetApplicationsLogoutContextBySession(ctx context.Context, tenantUUID uuid.UUID, sessionID string) ([]model.Application, error) {
	// 1. Fire the optimized CTE select query statement against the persistent table layout
	rows, err := s.queries.GetApplicationsLogoutContextBySession(ctx, sqlcdb.GetApplicationsLogoutContextBySessionParams{
		SessionID:  sessionID,
		TenantUuid: toPGUUID(tenantUUID),
	})
	if err != nil {
		return nil, err
	}

	// 2. Hydrate the driver row payloads back into standard, un-annotated pure domain model entity objects
	domainApplications := make([]model.Application, 0, len(rows))
	for _, row := range rows {
		// Parse structured raw byte string sequences back into google/uuid properties safely
		parsedAppUUID, err := uuid.Parse(row.ID.String())
		if err != nil {
			continue
		}

		parsedProfileUUID, err := uuid.Parse(row.ProfileID.String())
		if err != nil {
			continue
		}

		parsedGroupUUID, err := uuid.Parse(row.GroupID.String())
		if err != nil {
			continue
		}

		var frontChannelURI, backChannelURI string
		if row.FrontChannelLogoutUri != nil {
			frontChannelURI = *row.FrontChannelLogoutUri
		}
		if row.BackChannelLogoutUri != nil {
			backChannelURI = *row.BackChannelLogoutUri
		}

		app := model.Application{
			ID:                    parsedAppUUID,
			TenantID:              tenantUUID,
			ProfileID:             parsedProfileUUID,
			GroupID:               parsedGroupUUID,
			ApplicationName:       row.ApplicationName,
			IsEnabled:             row.IsEnabled,
			ClientID:              row.ClientID,
			ClientSecretHash:      row.ClientSecretHash,
			IsDynamic:             row.IsDynamic,
			CreatedAt:             row.CreatedAt.Time,
			UpdatedAt:             row.UpdatedAt.Time,
			LastUsedAt:            row.LastUsedAt.Time,
			FrontChannelLogoutURI: frontChannelURI, // Maps joined tracking values straight onto transient domain containers
			BackChannelLogoutURI:  backChannelURI,
			SigningAlgorithm:      model.SignatureAlgorithm(row.SigningAlgorithm),
		}

		domainApplications = append(domainApplications, app)
	}

	return domainApplications, nil
}

// PruneExpiredTokens clears out stale cache partitions across all operational session tables.
// Invoked dynamically by the centralized background worker on 15-minute ticks to maintain
// efficient index traversal speeds across hot token verification paths.
func (s *PostgresStorage) PruneExpiredTokens(ctx context.Context) error {
	// 1. Prune expired revoked tokens
	if err := s.queries.PruneExpiredRevokedTokens(ctx); err != nil {
		return fmt.Errorf("storage: failed to prune expired revoked tokens: %w", err)
	}

	// 2. Prune stale authorization sessions
	if err := s.queries.PruneExpiredAuthSessions(ctx); err != nil {
		return fmt.Errorf("storage: failed to prune stale auth sessions: %w", err)
	}

	// 3. Prune orphan client sessions records
	// Must run immediately after PruneExpiredAuthSessions so it can accurately calculate
	// which session_ids no longer exist within the live parent authorization session tables.
	if err := s.queries.PruneClientSessionsByExpiry(ctx); err != nil {
		return fmt.Errorf("storage: failed to prune orphaned client sessions links: %w", err)
	}

	// 4. Prune expired interaction sessions
	if err := s.queries.PruneExpiredInteractionSessions(ctx); err != nil {
		return fmt.Errorf("storage: failed to prune expired interaction sessions: %w", err)
	}

	// 5. Prune expired PAR sessions
	if err := s.queries.PruneExpiredPushedAuthRequests(ctx); err != nil {
		return fmt.Errorf("storage: failed to prune expired pushed auth requests: %w", err)
	}

	// 6. Prune expired DPoP proofs
	if err := s.queries.PruneExpiredDPoPProofs(ctx); err != nil {
		return fmt.Errorf("storage: failed to prune expired dpop proofs: %w", err)
	}

	return nil
}

func (s *PostgresStorage) SavePAR(ctx context.Context, req model.PushedAuthorizationRequest) error {
	// FIXED: Fully aligned with the sqlc v1.31.1 generated naming parameters struct
	err := s.queries.SavePAR(ctx, sqlcdb.SavePARParams{
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
		TenantUuid:          toPGUUID(req.TenantID), // Bound cleanly to the TenantUuid field slot
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

// IsDPoPProofUsed audits the database catalog to verify if a unique JTI has already been consumed.
func (s *PostgresStorage) IsDPoPProofUsed(ctx context.Context, jti string) (bool, error) {
	// Call your newly generated read validation query block smoothly
	isUsed, err := s.queries.IsDPoPProofUsed(ctx, jti)
	if err != nil {
		return false, fmt.Errorf("storage: failed to evaluate DPoP proof replay tracking status: %w", err)
	}
	return isUsed, nil
}

// SaveDPoPProof registers a high-entropy proof identifier signature into our persistent tracking grids.
func (s *PostgresStorage) SaveDPoPProof(ctx context.Context, jti string, expiresAt time.Time) error {
	// Call your newly generated named-parameter sqlc mutator loop safely
	err := s.queries.SaveDPoPProof(ctx, sqlcdb.SaveDPoPProofParams{
		Jti:       jti,
		ExpiresAt: toPGTimestamptz(expiresAt), // Encapsulates standard timestamptz conversion
	})
	if err != nil {
		return fmt.Errorf("storage: failed to execute DPoP proof ingestion block: %w", err)
	}
	return nil
}

// =========================================================================
// PORT.CRYPTOSTORAGE INTERFACE IMPLEMENTATION (KEY WRAPPERS)
// =========================================================================

// GetTenantDEK extracts the envelope encryption metadata directly from the tenants row.
func (s *PostgresStorage) GetTenantDEK(ctx context.Context, tenantUUID uuid.UUID) ([]byte, []byte, error) {
	row, err := s.queries.ResolveTenantByUUID(ctx, toPGUUID(tenantUUID)) // Wrapped with toPGUUID
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, fmt.Errorf("tenant metadata not found: %w", err)
		}
		return nil, nil, err
	}
	return row.EncryptedDek, row.DekNonce, nil
}

// InsertTenantDEK provisions the dynamic 32-byte key wrapper for an existing tenant record.
func (s *PostgresStorage) InsertTenantDEK(ctx context.Context, tenantUUID uuid.UUID, encryptedDEK, nonce []byte) error {
	return s.queries.UpdateTenantDEK(ctx, sqlcdb.UpdateTenantDEKParams{ // Swapped to sqlcdb.
		TenantUuid:   toPGUUID(tenantUUID),
		EncryptedDek: encryptedDEK,
		DekNonce:     nonce,
	})
}

// GetActiveSigningKeys loads all private keys currently required to sign tokens.
func (s *PostgresStorage) GetActiveSigningKeys(ctx context.Context, tenantUUID uuid.UUID) ([]model.SigningKey, error) {
	// 1. Query for the active signing keys for the tenant, returning a slice of sqlc-generated row structs
	rows, err := s.queries.GetActiveSigningKeys(ctx, toPGUUID(tenantUUID))
	if err != nil {
		return nil, fmt.Errorf("storage: failed loading active signing keys: %w", err)
	}

	// 2. Hydrate the driver row payloads back into standard, un-annotated pure domain model entity objects
	keys := make([]model.SigningKey, 0, len(rows))
	for _, row := range rows {
		var jwk map[string]any
		if len(row.PublicJwkJson) > 0 {
			if err := json.Unmarshal([]byte(row.PublicJwkJson), &jwk); err != nil {
				return nil, fmt.Errorf("storage: failed to parse stored public jwk: %w", err)
			}
		}

		keys = append(keys, model.SigningKey{
			Kid:                    row.Kid,
			Algorithm:              row.Algorithm,
			PublicJWK:              jwk,
			RawEncryptedPrivateKey: row.EncryptedPrivateKey,
			CryptoNonce:            row.Nonce,
		})
	}

	return keys, nil
}

// GetActiveVerificationKeys streams all valid verification public targets without decrypting anything.
func (s *PostgresStorage) GetActiveVerificationKeys(ctx context.Context, tenantUUID uuid.UUID) ([]model.SigningKey, error) {
	rows, err := s.queries.GetActiveVerificationKeys(ctx, toPGUUID(tenantUUID)) // Wrapped with toPGUUID
	if err != nil {
		return nil, err
	}

	var keys []model.SigningKey
	for _, row := range rows {
		var jwk map[string]any
		if err := json.Unmarshal([]byte(row.PublicJwkJson), &jwk); err != nil {
			return nil, fmt.Errorf("malformed public key array: %w", err)
		}

		keys = append(keys, model.SigningKey{
			Kid:       row.Kid,
			Algorithm: row.Algorithm,
			PublicJWK: jwk,
		})
	}
	return keys, nil
}

// InsertSigningKey commits a key asset to the database, capturing the generated UUIDv7.
func (s *PostgresStorage) InsertSigningKey(ctx context.Context, tenantUUID uuid.UUID, key model.SigningKey, encryptedPrivateKey, nonce []byte) (string, error) {
	jwkBytes, err := json.Marshal(key.PublicJWK)
	if err != nil {
		return "", err
	}

	// Insert the record. Postgres 18 automatically computes the UUIDv7 primary key.
	generatedID, err := s.queries.InsertSigningKey(ctx, sqlcdb.InsertSigningKeyParams{ // Swapped to sqlcdb.
		TenantUuid:           toPGUUID(tenantUUID),
		Kid:                  key.Kid,
		Algorithm:            key.Algorithm,
		EncryptedPrivateKey:  encryptedPrivateKey,
		PublicJwkJson:        string(jwkBytes),
		Nonce:                nonce,
		IsActiveSigning:      true,
		IsActiveVerification: true,
	})
	if err != nil {
		return "", err
	}

	return generatedID.String(), nil
}

// RotateSigningKeys demotes all active signing keys for the tenant to verification-only.
func (s *PostgresStorage) RotateSigningKeys(ctx context.Context, tenantUUID uuid.UUID) error {
	return s.queries.RotateSigningKeysTransaction(ctx, toPGUUID(tenantUUID))
}

// =========================================================================
// PORT.ADMINSTORAGE INTERFACE IMPLEMENTATION (DASHBOARD PATHWAYS)
// =========================================================================

// GetDynamicApplicationsSummary streams a performance-optimized list of dynamic applications
// populated with their active profile and group name tags for your Fleet Monitoring dashboard grid.
func (s *PostgresStorage) GetDynamicApplicationsSummary(ctx context.Context, tenantUUID uuid.UUID) ([]model.ApplicationSummary, error) {
	rows, err := s.queries.GetDynamicApplicationsSummary(ctx, toPGUUID(tenantUUID))
	if err != nil {
		return nil, fmt.Errorf("storage: failed to execute dynamic summary query: %w", err)
	}

	var summaries []model.ApplicationSummary
	for _, row := range rows {
		appID, err := pgUUIDToUUID(row.ID)
		if err != nil {
			return nil, fmt.Errorf("storage: decode dynamic app uuid: %w", err)
		}
		profileID, err := pgUUIDToUUID(row.ProfileID)
		if err != nil {
			return nil, fmt.Errorf("storage: decode dynamic profile uuid: %w", err)
		}
		groupID, err := pgUUIDToUUID(row.GroupID)
		if err != nil {
			return nil, fmt.Errorf("storage: decode dynamic group uuid: %w", err)
		}

		createdAt, err := pgTimestamptzToTime(row.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("storage: convert dynamic created_at: %w", err)
		}
		updatedAt, err := pgTimestamptzToTime(row.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("storage: convert dynamic updated_at: %w", err)
		}
		lastUsedAt := pgTimestamptzToTimeOrZero(row.LastUsedAt)

		summaries = append(summaries, model.ApplicationSummary{
			ID:              appID,
			ClientID:        row.ClientID,
			ApplicationName: row.ApplicationName,
			IsEnabled:       row.IsEnabled,
			IsDynamic:       true,
			CreatedAt:       createdAt,
			UpdatedAt:       updatedAt,
			LastUsedAt:      lastUsedAt,
			ProfileID:       profileID,
			ProfileName:     row.ProfileName,
			GroupID:         groupID,
			GroupName:       row.GroupName,
		})
	}

	return summaries, nil
}

// GetStaticApplicationsSummary streams an administrative list of permanent integration rows
// for your dedicated Dashboard Onboarding configuration view page.
func (s *PostgresStorage) GetStaticApplicationsSummary(ctx context.Context, tenantUUID uuid.UUID) ([]model.ApplicationSummary, error) {
	rows, err := s.queries.GetStaticApplicationsSummary(ctx, toPGUUID(tenantUUID))
	if err != nil {
		return nil, fmt.Errorf("storage: failed to execute static summary query: %w", err)
	}

	var summaries []model.ApplicationSummary
	for _, row := range rows {
		appID, err := pgUUIDToUUID(row.ID)
		if err != nil {
			return nil, fmt.Errorf("storage: decode static app uuid: %w", err)
		}
		profileID, err := pgUUIDToUUID(row.ProfileID)
		if err != nil {
			return nil, fmt.Errorf("storage: decode static profile uuid: %w", err)
		}
		groupID, err := pgUUIDToUUID(row.GroupID)
		if err != nil {
			return nil, fmt.Errorf("storage: decode static group uuid: %w", err)
		}

		createdAt, err := pgTimestamptzToTime(row.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("storage: convert static created_at: %w", err)
		}
		updatedAt, err := pgTimestamptzToTime(row.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("storage: convert static updated_at: %w", err)
		}
		lastUsedAt := pgTimestamptzToTimeOrZero(row.LastUsedAt)

		summaries = append(summaries, model.ApplicationSummary{
			ID:              appID,
			ClientID:        row.ClientID,
			ApplicationName: row.ApplicationName,
			IsEnabled:       row.IsEnabled,
			IsDynamic:       false,
			CreatedAt:       createdAt,
			UpdatedAt:       updatedAt,
			LastUsedAt:      lastUsedAt,
			ProfileID:       profileID,
			ProfileName:     row.ProfileName,
			GroupID:         groupID,
			GroupName:       row.GroupName,
		})
	}

	return summaries, nil
}

// UpdateApplicationProfile modifies execution token lifetimes and cryptographic settings.
func (s *PostgresStorage) UpdateApplicationProfile(ctx context.Context, tenantUUID uuid.UUID, profile model.ApplicationProfile) error {
	// Map Go slice enums into explicit string slices for the driver
	grantTypes := make([]string, len(profile.GrantTypes))
	for i, gt := range profile.GrantTypes {
		grantTypes[i] = string(gt)
	}

	responseTypes := make([]string, len(profile.ResponseTypes))
	for i, rt := range profile.ResponseTypes {
		responseTypes[i] = string(rt)
	}

	// Calculate granular lifespans down to seconds for integer storage compatibility
	accessTokenSeconds := int32(profile.AccessTokenLifetime / time.Second)
	refreshTokenSeconds := int32(profile.RefreshTokenLifetime / time.Second)
	idTokenSeconds := int32(profile.IDTokenLifetime / time.Second)

	err := s.queries.UpdateApplicationProfile(ctx, sqlcdb.UpdateApplicationProfileParams{
		ID:                      toPGUUID(profile.ID),
		ProfileName:             profile.ProfileName,
		IsEnabled:               profile.IsEnabled,
		TokenEndpointAuthMethod: string(profile.TokenEndpointAuthMethod),
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		AccessTokenLifetime:     accessTokenSeconds,
		RefreshTokenLifetime:    refreshTokenSeconds,
		IDTokenLifetime:         idTokenSeconds,
		EnforceRtr:              profile.EnforceRTR,
		SigningAlgorithm:        string(profile.SigningAlgorithm),
		TenantUuid:              toPGUUID(tenantUUID),
	})
	if err != nil {
		return fmt.Errorf("storage: failed to execute application profile update: %w", err)
	}

	return nil
}

// UpdateApplication updates the metadata layout properties of a pre-existing
// application instance within a strict tenant authorization perimeter.
func (s *PostgresStorage) UpdateApplication(ctx context.Context, tenantUUID uuid.UUID, clientID string, app model.Application) error {
	// Execute your compiled named-parameter update block safely
	err := s.queries.UpdateApplication(ctx, sqlcdb.UpdateApplicationParams{
		TenantUuid:      toPGUUID(tenantUUID), // Enforces structural tenant isolation walls
		ApplicationName: app.ApplicationName,
		IsEnabled:       app.IsEnabled,
		ProfileID:       toPGUUID(app.ProfileID),
		GroupID:         toPGUUID(app.GroupID),
		ClientID:        clientID,
	})
	if err != nil {
		return fmt.Errorf("storage: failed to update application metadata layout: %w", err)
	}

	return nil
}

// UpdateApplicationGroup modifies top-level group settings, flushes historical identity provider
// bindings, and re-streams the updated whitelists inside a single atomic database transaction.
func (s *PostgresStorage) UpdateApplicationGroup(ctx context.Context, tenantUUID uuid.UUID, group model.ApplicationGroup) error {
	// 1. Initialize a transaction context block to ensure strict relational safety
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("storage: failed to initiate group update transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Bind the transactional handle straight to your compiled query container
	txQueries := s.queries.WithTx(tx)

	var pgDefaultIDP pgtype.UUID
	if group.DefaultIDPID != nil {
		pgDefaultIDP = toPGUUID(*group.DefaultIDPID)
	}

	// 2. Mutate the base application group column row data using the true UPDATE query
	err = txQueries.UpdateApplicationGroup(ctx, sqlcdb.UpdateApplicationGroupParams{
		ID:                     toPGUUID(group.ID),
		GroupName:              group.GroupName,
		IsEnabled:              group.IsEnabled,
		AllowedScopes:          group.AllowedScopes,
		DefaultScopes:          group.DefaultScopes,
		AllowedAudiences:       group.AllowedAudiences,
		DefaultIdpID:           pgDefaultIDP,
		RedirectUris:           group.RedirectURIs,
		PostLogoutRedirectUris: group.PostLogoutRedirectURIs,
		TenantUuid:             toPGUUID(tenantUUID),
	})
	if err != nil {
		return fmt.Errorf("storage: failed to execute application group update query: %w", err)
	}

	// 3. Purge existing relationship matrix records to prevent unique key index conflicts
	pgGroupUUID := toPGUUID(group.ID)
	err = txQueries.ClearIdentityProvidersFromGroup(ctx, sqlcdb.ClearIdentityProvidersFromGroupParams{
		GroupID:    pgGroupUUID,
		TenantUuid: toPGUUID(tenantUUID),
	})
	if err != nil {
		return fmt.Errorf("storage: failed to clear historic group identity provider mappings: %w", err)
	}

	// 4. Batch Re-Inscription Phase: Stream the updated whitelist array into the join table
	if len(group.AllowedIDPIDs) > 0 {
		tenantID, err := txQueries.GetTenantIDByUUID(ctx, toPGUUID(tenantUUID))
		if err != nil {
			return fmt.Errorf("storage: failed to resolve tenant internal ID: %w", err)
		}

		batchEntries := make([]sqlcdb.BindIdentityProvidersToGroupParams, len(group.AllowedIDPIDs))
		for i, idpID := range group.AllowedIDPIDs {
			batchEntries[i] = sqlcdb.BindIdentityProvidersToGroupParams{
				GroupID:  pgGroupUUID,
				IdpID:    toPGUUID(idpID),
				TenantID: tenantID,
			}
		}

		// Stream structural join entries via the high-performance COPY pipeline
		_, err = txQueries.BindIdentityProvidersToGroup(ctx, batchEntries)
		if err != nil {
			return fmt.Errorf("storage: failed to re-stream updated identity provider bindings: %w", err)
		}
	}

	// 5. Commit all relational changes to disk atomically
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("storage: update transaction commit phase rejected: %w", err)
	}

	return nil
}

// =========================================================================
// FEDERATED SESSION INTERFACE IMPLEMENTATION
// =========================================================================

// SaveFederatedSession handles the secure persistence or mutation of an upstream session state securely [5.7]
func (s *PostgresStorage) SaveFederatedSession(ctx context.Context, session model.FederatedSession) error {
	err := s.queries.SaveFederatedSession(ctx, sqlcdb.SaveFederatedSessionParams{
		ID:                   toPGUUID(session.ID),
		PartitionID:          session.PartitionID,
		SessionID:            session.SessionID,
		IdentityProviderID:   toPGUUID(session.IdentityProviderID),
		UpstreamSubject:      session.UpstreamSubject,
		UpstreamAccessToken:  session.UpstreamAccessToken,
		UpstreamIDToken:      session.UpstreamIDToken,
		UpstreamRefreshToken: session.UpstreamRefreshToken,
		CreatedAt:            toPGTimestamptz(session.CreatedAt),
		ExpiresAt:            toPGTimestamptz(session.ExpiresAt),
		TenantUuid:           toPGUUID(session.TenantUUID),
	})
	if err != nil {
		return fmt.Errorf("storage: failed to execute sqlc save federated session: %w", err)
	}
	return nil
}

// GetFederatedSessionByLocalSessionID retrieves upstream tokens using our native tracking session reference [7.3]
func (s *PostgresStorage) GetFederatedSessionByLocalSessionID(
	ctx context.Context,
	tenantUUID uuid.UUID,
	partitionID int64,
	sessionID string,
) (*model.FederatedSession, error) {
	row, err := s.queries.GetFederatedSessionByLocalSessionID(ctx, sqlcdb.GetFederatedSessionByLocalSessionIDParams{
		PartitionID: partitionID,
		SessionID:   sessionID,
		TenantUuid:  toPGUUID(tenantUUID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("storage: federated tracking session not found: %w", port.ErrSessionNotFound)
		}
		return nil, fmt.Errorf("storage: lookup failed by local session identifier: %w", err)
	}

	return toDomainFederatedSession(row, tenantUUID), nil
}

// FindFederatedSessionByUpstreamSubject locates a mapping record for incoming upstream Back-Channel SLO webhooks [7.2]
func (s *PostgresStorage) FindFederatedSessionByUpstreamSubject(
	ctx context.Context,
	tenantUUID uuid.UUID,
	idpID uuid.UUID,
	upstreamSub string,
) (*model.FederatedSession, error) {
	row, err := s.queries.FindFederatedSessionByUpstreamSubject(ctx, sqlcdb.FindFederatedSessionByUpstreamSubjectParams{
		IdentityProviderID: toPGUUID(idpID),
		UpstreamSubject:    upstreamSub,
		TenantUuid:         toPGUUID(tenantUUID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("storage: federated tracking context unresolvable: %w", port.ErrSessionNotFound)
		}
		return nil, fmt.Errorf("storage: lookup failed by upstream provider criteria: %w", err)
	}

	return toDomainFederatedSession(row, tenantUUID), nil
}

// DeleteFederatedSession explicitly purges a single federated mapping layer during targeted single-logouts [7.1]
func (s *PostgresStorage) DeleteFederatedSession(
	ctx context.Context,
	tenantUUID uuid.UUID,
	partitionID int64,
	sessionID string,
) error {
	err := s.queries.DeleteFederatedSession(ctx, sqlcdb.DeleteFederatedSessionParams{
		PartitionID: partitionID,
		SessionID:   sessionID,
		TenantUuid:  toPGUUID(tenantUUID),
	})
	if err != nil {
		return fmt.Errorf("storage: failed to execute single logout row eviction: %w", err)
	}
	return nil
}

// PruneExpiredFederatedSessions sweeps old, obsolete upstream keys matching background cleaning intervals [6.3]
func (s *PostgresStorage) PruneExpiredFederatedSessions(ctx context.Context, now time.Time) (int64, error) {
	rowsAffected, err := s.queries.PruneExpiredFederatedSessions(ctx, toPGTimestamptz(now))
	if err != nil {
		return 0, fmt.Errorf("storage: clear task runtime failure on expired federated records: %w", err)
	}
	return rowsAffected, nil
}

// GetApplicationProfiles retrieves all standalone security policies for a tenant.
func (s *PostgresStorage) GetApplicationProfiles(ctx context.Context, tenantUUID uuid.UUID) ([]model.ApplicationProfile, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, profile_name, is_enabled, token_endpoint_auth_method, grant_types, response_types,
		       access_token_lifetime, refresh_token_lifetime, id_token_lifetime, enforce_rtr, signing_algorithm, updated_at
		FROM application_profiles
		WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1 LIMIT 1)
		ORDER BY profile_name ASC
	`, toPGUUID(tenantUUID))
	if err != nil {
		return nil, fmt.Errorf("storage: select application profiles: %w", err)
	}
	defer rows.Close()

	var list []model.ApplicationProfile
	for rows.Next() {
		var p model.ApplicationProfile
		var pgID pgtype.UUID
		var authMethod string
		var grantTypes, responseTypes []string
		var accessInterval, refreshInterval, idInterval pgtype.Interval
		var signingAlg string
		var updatedAt pgtype.Timestamptz

		if err := rows.Scan(&pgID, &p.ProfileName, &p.IsEnabled, &authMethod, &grantTypes, &responseTypes,
			&accessInterval, &refreshInterval, &idInterval, &p.EnforceRTR, &signingAlg, &updatedAt); err != nil {
			return nil, fmt.Errorf("storage: scan profile row: %w", err)
		}

		p.ID, _ = pgUUIDToUUID(pgID)
		p.TenantID = tenantUUID
		p.TokenEndpointAuthMethod = model.TokenEndpointAuthMethod(authMethod)
		p.AccessTokenLifetime, _ = pgIntervalToDuration(accessInterval)
		p.RefreshTokenLifetime, _ = pgIntervalToDuration(refreshInterval)
		p.IDTokenLifetime, _ = pgIntervalToDuration(idInterval)
		p.SigningAlgorithm = model.SignatureAlgorithm(signingAlg)
		p.UpdatedAt = pgTimestamptzToTimeOrZero(updatedAt)

		p.GrantTypes = make([]model.GrantType, len(grantTypes))
		for i, gt := range grantTypes {
			p.GrantTypes[i] = model.GrantType(gt)
		}
		p.ResponseTypes = make([]model.ResponseType, len(responseTypes))
		for i, rt := range responseTypes {
			p.ResponseTypes[i] = model.ResponseType(rt)
		}

		list = append(list, p)
	}
	return list, nil
}

// GetApplicationGroups retrieves all standalone routing / authorization groups for a tenant.
func (s *PostgresStorage) GetApplicationGroups(ctx context.Context, tenantUUID uuid.UUID) ([]model.ApplicationGroup, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, group_name, is_enabled, redirect_uris, post_logout_redirect_uris,
		       front_channel_logout_uri, back_channel_logout_uri, allowed_scopes, default_scopes, allowed_audiences, default_idp_id, updated_at
		FROM application_groups
		WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1 LIMIT 1)
		ORDER BY group_name ASC
	`, toPGUUID(tenantUUID))
	if err != nil {
		return nil, fmt.Errorf("storage: select application groups: %w", err)
	}
	defer rows.Close()

	var list []model.ApplicationGroup
	for rows.Next() {
		var g model.ApplicationGroup
		var pgID pgtype.UUID
		var defaultIdpID pgtype.UUID
		var updatedAt pgtype.Timestamptz

		if err := rows.Scan(&pgID, &g.GroupName, &g.IsEnabled, &g.RedirectURIs, &g.PostLogoutRedirectURIs,
			&g.FrontChannelLogoutURI, &g.BackChannelLogoutURI, &g.AllowedScopes, &g.DefaultScopes, &g.AllowedAudiences, &defaultIdpID, &updatedAt); err != nil {
			return nil, fmt.Errorf("storage: scan group row: %w", err)
		}

		g.ID, _ = pgUUIDToUUID(pgID)
		g.TenantID = tenantUUID
		g.UpdatedAt = pgTimestamptzToTimeOrZero(updatedAt)

		if defaultIdpID.Valid {
			parsed, _ := pgUUIDToUUID(defaultIdpID)
			g.DefaultIDPID = &parsed
		}

		// Load group IDP join relation array
		idpRows, err := s.pool.Query(ctx, "SELECT idp_id FROM application_group_idps WHERE group_id = $1", pgID)
		if err == nil {
			var idps []uuid.UUID
			for idpRows.Next() {
				var pgIDP pgtype.UUID
				if err := idpRows.Scan(&pgIDP); err == nil {
					parsed, _ := pgUUIDToUUID(pgIDP)
					idps = append(idps, parsed)
				}
			}
			idpRows.Close()
			g.AllowedIDPIDs = idps
		}

		list = append(list, g)
	}
	return list, nil
}

// GetApplicationProfileByID retrieves a single application profile policy.
func (s *PostgresStorage) GetApplicationProfileByID(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) (*model.ApplicationProfile, error) {
	var p model.ApplicationProfile
	var pgID pgtype.UUID
	var authMethod string
	var grantTypes, responseTypes []string
	var accessInterval, refreshInterval, idInterval pgtype.Interval
	var signingAlg string
	var updatedAt pgtype.Timestamptz

	err := s.pool.QueryRow(ctx, `
		SELECT id, profile_name, is_enabled, token_endpoint_auth_method, grant_types, response_types,
		       access_token_lifetime, refresh_token_lifetime, id_token_lifetime, enforce_rtr, signing_algorithm, updated_at
		FROM application_profiles
		WHERE id = $1 AND tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $2 LIMIT 1)
	`, toPGUUID(id), toPGUUID(tenantUUID)).Scan(&pgID, &p.ProfileName, &p.IsEnabled, &authMethod, &grantTypes, &responseTypes,
		&accessInterval, &refreshInterval, &idInterval, &p.EnforceRTR, &signingAlg, &updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("profile not found")
		}
		return nil, fmt.Errorf("storage: get profile by id: %w", err)
	}

	p.ID = id
	p.TenantID = tenantUUID
	p.TokenEndpointAuthMethod = model.TokenEndpointAuthMethod(authMethod)
	p.AccessTokenLifetime, _ = pgIntervalToDuration(accessInterval)
	p.RefreshTokenLifetime, _ = pgIntervalToDuration(refreshInterval)
	p.IDTokenLifetime, _ = pgIntervalToDuration(idInterval)
	p.SigningAlgorithm = model.SignatureAlgorithm(signingAlg)
	p.UpdatedAt = pgTimestamptzToTimeOrZero(updatedAt)

	p.GrantTypes = make([]model.GrantType, len(grantTypes))
	for i, gt := range grantTypes {
		p.GrantTypes[i] = model.GrantType(gt)
	}
	p.ResponseTypes = make([]model.ResponseType, len(responseTypes))
	for i, rt := range responseTypes {
		p.ResponseTypes[i] = model.ResponseType(rt)
	}

	return &p, nil
}

// GetApplicationGroupByID retrieves a single authorization group.
func (s *PostgresStorage) GetApplicationGroupByID(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) (*model.ApplicationGroup, error) {
	var g model.ApplicationGroup
	var pgID pgtype.UUID
	var defaultIdpID pgtype.UUID
	var updatedAt pgtype.Timestamptz

	err := s.pool.QueryRow(ctx, `
		SELECT id, group_name, is_enabled, redirect_uris, post_logout_redirect_uris,
		       front_channel_logout_uri, back_channel_logout_uri, allowed_scopes, default_scopes, allowed_audiences, default_idp_id, updated_at
		FROM application_groups
		WHERE id = $1 AND tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $2 LIMIT 1)
	`, toPGUUID(id), toPGUUID(tenantUUID)).Scan(&pgID, &g.GroupName, &g.IsEnabled, &g.RedirectURIs, &g.PostLogoutRedirectURIs,
		&g.FrontChannelLogoutURI, &g.BackChannelLogoutURI, &g.AllowedScopes, &g.DefaultScopes, &g.AllowedAudiences, &defaultIdpID, &updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("group not found")
		}
		return nil, fmt.Errorf("storage: get group by id: %w", err)
	}

	g.ID = id
	g.TenantID = tenantUUID
	g.UpdatedAt = pgTimestamptzToTimeOrZero(updatedAt)

	if defaultIdpID.Valid {
		parsed, _ := pgUUIDToUUID(defaultIdpID)
		g.DefaultIDPID = &parsed
	}

	// Load group IDP join relation array
	idpRows, err := s.pool.Query(ctx, "SELECT idp_id FROM application_group_idps WHERE group_id = $1", pgID)
	if err == nil {
		var idps []uuid.UUID
		for idpRows.Next() {
			var pgIDP pgtype.UUID
			if err := idpRows.Scan(&pgIDP); err == nil {
				parsed, _ := pgUUIDToUUID(pgIDP)
				idps = append(idps, parsed)
			}
		}
		idpRows.Close()
		g.AllowedIDPIDs = idps
	}

	return &g, nil
}

// --- Dynamic Mapping Internal Converter ---

func toDomainFederatedSession(row sqlcdb.FederatedSession, tenantUUID uuid.UUID) *model.FederatedSession {
	return &model.FederatedSession{
		ID:                   row.ID.Bytes, // Direct field unpacking safe for your compiled sqlc models
		TenantUUID:           tenantUUID,
		PartitionID:          row.PartitionID,
		SessionID:            row.SessionID,
		IdentityProviderID:   row.IdentityProviderID.Bytes,
		UpstreamSubject:      row.UpstreamSubject,
		UpstreamAccessToken:  valueOrEmpty(row.UpstreamAccessToken),
		UpstreamIDToken:      valueOrEmpty(row.UpstreamIDToken),
		UpstreamRefreshToken: valueOrEmpty(row.UpstreamRefreshToken),
		CreatedAt:            row.CreatedAt.Time,
		ExpiresAt:            row.ExpiresAt.Time,
	}
}

/* OLD code */

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

	scheme := model.SchemeHttps
	if s.appEnv == "local" {
		scheme = model.SchemeHttp
	}

	var tenants []model.Tenant
	for rows.Next() {
		tenant, err := scanTenantRow(rows)
		if err != nil {
			return nil, err
		}
		tenant.Scheme = scheme
		tenants = append(tenants, tenant)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenants: %w", err)
	}

	return tenants, nil
}

// CreateTenant persists a tenant record and automatically initializes its
// default partition as a single, atomic transactional side effect.
func (s *PostgresStorage) CreateTenant(ctx context.Context, tenant model.Tenant) error {
	// 1. Initialize a transactional block to guarantee strict atomic data safety
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("storage: failed to initiate create tenant transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // Safe fail-secure rollback loop

	txQueries := s.queries.WithTx(tx)
	pgTenantUUID := toPGUUID(tenant.ID)

	// Safely resolve the nullable default partition pointer to a primitive int64
	var defaultPartitionID int64
	if tenant.DefaultPartition != nil {
		defaultPartitionID = *tenant.DefaultPartition
	}

	// Marshal your tenant config matrix safely down to JSON bytes for the jsonb column
	configBytes, err := json.Marshal(tenant.Config)
	if err != nil {
		return fmt.Errorf("storage: failed to marshal tenant config payload: %w", err)
	}

	// 2. Insert or update the root tenant record using your exact column layout structure.
	// Aligned precisely to your true compiled db.CreateTenantParams generated signature.
	internalTenantID, err := txQueries.CreateTenant(ctx, sqlcdb.CreateTenantParams{
		TenantUuid:       pgTenantUUID,
		Name:             tenant.Name,
		DomainName:       tenant.Domain,
		IsActive:         tenant.IsActive,
		CreatedAt:        toPGTimestamptz(tenant.CreatedAt),
		Config:           configBytes,
		DefaultPartition: defaultPartitionID, // Passed cleanly as a primitive int64
		EncryptedDek:     nil,                // Safely isolated here to satisfy sqlc generation criteria
		DekNonce:         nil,                // Safely isolated here to satisfy sqlc generation criteria
	})
	if err != nil {
		return fmt.Errorf("storage: failed to persist tenant profile row: %w", err)
	}

	// 3. ENCAPSULATED SIDE EFFECT: Verify and automate default partition initialization
	// Uses the int32 primary key returned directly by your compiled row execution pass
	existingPartitions, err := txQueries.GetPartitionsByInternalTenantID(ctx, internalTenantID)
	if err != nil {
		return fmt.Errorf("storage: failed to evaluate pre-existing tenant partitions matrix: %w", err)
	}

	// If no partitions exist yet for this brand new tenant record, create the default boundary block
	if len(existingPartitions) == 0 {
		// Insert the canonical default partition linked to the returned internal integer tenant ID
		newPartition, err := txQueries.InsertPartition(ctx, sqlcdb.InsertPartitionParams{
			TenantID:  internalTenantID, // Satisfies the generated int32 constraint
			Name:      "default",
			AliasName: "default",
		})
		if err != nil {
			return fmt.Errorf("storage: failed to initialize automated default partition: %w", err)
		}

		// Self-link the tenant back to its newly created default partition integer ID instantly
		err = txQueries.UpdateTenantDefaultPartition(ctx, sqlcdb.UpdateTenantDefaultPartitionParams{
			TenantUuid:       pgTenantUUID,
			DefaultPartition: int64(newPartition.ID), // Matches the generated int64 column target
		})
		if err != nil {
			return fmt.Errorf("storage: failed to bind tenant default partition relation node: %w", err)
		}

		// Synchronize your in-memory domain tracking pointer for downstream service consumption code
		allocatedID := int64(newPartition.ID)
		tenant.DefaultPartition = &allocatedID
	}

	// 4. Commit everything down to disk safely
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("storage: failed to lock and commit tenant side-effect transaction: %w", err)
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

func (s *PostgresStorage) GetIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error) {
	rows, err := s.queries.GetIdentityProviders(ctx, toPGUUID(tenantID))
	if err != nil {
		return nil, fmt.Errorf("get identity providers collection: %w", err)
	}

	providers := make([]model.IdentityProvider, len(rows))
	for i, row := range rows {
		providerUUID, err := pgUUIDToUUID(row.ID)
		if err != nil {
			return nil, fmt.Errorf("parse provider UUID at index %d: %w", i, err)
		}
		parsedCreatedAt, _ := pgTimestamptzToTime(row.CreatedAt)
		parsedUpdatedAt, _ := pgTimestamptzToTime(row.UpdatedAt)

		var providerCfg model.IdentityProviderConfig
		if len(row.Config) > 0 {
			_ = json.Unmarshal(row.Config, &providerCfg)
		}

		var issuer string
		if row.Issuer != nil {
			issuer = *row.Issuer
		}

		providers[i] = model.IdentityProvider{
			ID:          providerUUID,
			TenantID:    tenantID,
			IDPType:     row.IdpType,
			Enabled:     row.Enabled,
			Alias:       row.Alias,
			Name:        row.Name,
			PartitionID: row.PartitionID,
			Issuer:      issuer,
			Config:      providerCfg,
			CreatedAt:   parsedCreatedAt,
			UpdatedAt:   parsedUpdatedAt,
		}
	}
	return providers, nil
}

func (s *PostgresStorage) GetIdentityProvidersByUUIDs(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) ([]model.IdentityProvider, error) {
	// Map slice items cleanly into pgtype matrix formats
	pgUUIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgUUIDs[i] = toPGUUID(id)
	}

	rows, err := s.queries.GetIdentityProvidersByUUIDs(ctx, sqlcdb.GetIdentityProvidersByUUIDsParams{
		IdpUuids:   pgUUIDs,
		TenantUuid: toPGUUID(tenantID),
	})
	if err != nil {
		return nil, fmt.Errorf("get identity providers by uuids slice: %w", err)
	}

	providers := make([]model.IdentityProvider, len(rows))
	for i, row := range rows {
		providerUUID, err := pgUUIDToUUID(row.ID)
		if err != nil {
			return nil, fmt.Errorf("parse slice items at index %d: %w", i, err)
		}
		parsedCreatedAt, _ := pgTimestamptzToTime(row.CreatedAt)
		parsedUpdatedAt, _ := pgTimestamptzToTime(row.UpdatedAt)

		var providerCfg model.IdentityProviderConfig
		if len(row.Config) > 0 {
			_ = json.Unmarshal(row.Config, &providerCfg)
		}

		var issuer string
		if row.Issuer != nil {
			issuer = *row.Issuer
		}

		providers[i] = model.IdentityProvider{
			ID:          providerUUID,
			TenantID:    tenantID,
			IDPType:     row.IdpType,
			Enabled:     row.Enabled,
			Alias:       row.Alias,
			Name:        row.Name,
			PartitionID: row.PartitionID,
			Issuer:      issuer,
			Config:      providerCfg,
			CreatedAt:   parsedCreatedAt,
			UpdatedAt:   parsedUpdatedAt,
		}
	}
	return providers, nil
}

// GetIdentityProvidersByTypeAndPartition pulls all matching trust records from the database layer.
func (s *PostgresStorage) GetIdentityProvidersByTypeAndPartition(ctx context.Context, tenantUUID uuid.UUID, partitionID int64, idpType string) ([]model.IdentityProvider, error) {
	rows, err := s.queries.GetIdentityProvidersByTypeAndPartition(ctx, sqlcdb.GetIdentityProvidersByTypeAndPartitionParams{
		PartitionID: partitionID,
		IdpType:     idpType,
		TenantUuid:  toPGUUID(tenantUUID),
	})
	if err != nil {
		return nil, err
	}

	providers := make([]model.IdentityProvider, 0, len(rows))
	for _, row := range rows {
		var config model.IdentityProviderConfig
		if len(row.Config) > 0 {
			if err := json.Unmarshal(row.Config, &config); err != nil {
				continue
			}
		}

		parsedID, err := uuid.Parse(row.ID.String())
		if err != nil {
			continue
		}

		var issuerStr string
		if row.Issuer != nil {
			issuerStr = *row.Issuer
		}

		providers = append(providers, model.IdentityProvider{
			ID:          parsedID,
			TenantID:    tenantUUID,
			IDPType:     row.IdpType,
			Enabled:     row.Enabled,
			Alias:       row.Alias,
			Name:        row.Name,
			PartitionID: row.PartitionID,
			Issuer:      issuerStr,
			Config:      config,
			CreatedAt:   row.CreatedAt.Time,
			UpdatedAt:   row.UpdatedAt.Time,
		})
	}

	return providers, nil
}

func (s *PostgresStorage) GetIdentityProviderByAlias(ctx context.Context, tenantID uuid.UUID, alias string) (*model.IdentityProvider, error) {
	row, err := s.queries.GetIdentityProviderByAlias(ctx, sqlcdb.GetIdentityProviderByAliasParams{
		IdpAlias:   alias,
		TenantUuid: toPGUUID(tenantID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("identity provider alias %s not found: %w", alias, port.ErrIdentityProviderNotFound)
		}
		return nil, fmt.Errorf("get identity provider by alias: %w", err)
	}

	providerUUID, err := pgUUIDToUUID(row.ID)
	if err != nil {
		return nil, fmt.Errorf("parse provider UUID: %w", err)
	}
	parsedCreatedAt, _ := pgTimestamptzToTime(row.CreatedAt)
	parsedUpdatedAt, _ := pgTimestamptzToTime(row.UpdatedAt)

	var providerCfg model.IdentityProviderConfig
	if len(row.Config) > 0 {
		if err := json.Unmarshal(row.Config, &providerCfg); err != nil {
			return nil, fmt.Errorf("unmarshal provider config: %w", err)
		}
	}

	var issuer string
	if row.Issuer != nil {
		issuer = *row.Issuer
	}

	return &model.IdentityProvider{
		ID:          providerUUID,
		TenantID:    tenantID,
		IDPType:     row.IdpType,
		Enabled:     row.Enabled,
		Alias:       row.Alias,
		Name:        row.Name,
		PartitionID: row.PartitionID,
		Issuer:      issuer,
		Config:      providerCfg,
		CreatedAt:   parsedCreatedAt,
		UpdatedAt:   parsedUpdatedAt,
	}, nil
}

// GetIdentityProviderByUUID resolves a singular provider configuration using its unique identifier key.
func (s *PostgresStorage) GetIdentityProviderByUUID(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) (*model.IdentityProvider, error) {
	// 1. Invoke the type-safe generated sqlc query block
	row, err := s.queries.GetIdentityProviderByUUID(ctx, sqlcdb.GetIdentityProviderByUUIDParams{
		IdpUuid:    toPGUUID(idpID),    // $1: Maps securely to pgtype.UUID via existing helper
		TenantUuid: toPGUUID(tenantID), // $2: Maps securely to pgtype.UUID via existing helper
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) { // Protects downstream architecture from leaky DB implementation details
			return nil, fmt.Errorf("identity provider %s not found for tenant %s: %w", idpID, tenantID, port.ErrIdentityProviderNotFound)
		}
		return nil, fmt.Errorf("get identity provider by uuid query failed: %w", err)
	}

	// 2. Perform safe, clean data-type conversion sweeps utilizing your exact internal helpers
	providerUUID, err := pgUUIDToUUID(row.ID)
	if err != nil {
		return nil, fmt.Errorf("parse provider uuid: %w", err)
	}

	parsedCreatedAt, _ := pgTimestamptzToTime(row.CreatedAt)
	parsedUpdatedAt, _ := pgTimestamptzToTime(row.UpdatedAt)

	var providerCfg model.IdentityProviderConfig
	if len(row.Config) > 0 {
		if err := json.Unmarshal(row.Config, &providerCfg); err != nil {
			return nil, fmt.Errorf("unmarshal identity provider configuration payload: %w", err)
		}
	}

	var issuer string
	if row.Issuer != nil {
		issuer = *row.Issuer
	}

	// 3. Reconstruct your clean, unpolluted core domain model instance matching structural rules
	return &model.IdentityProvider{
		ID:          providerUUID,
		TenantID:    tenantID,
		IDPType:     row.IdpType,
		Enabled:     row.Enabled,
		Alias:       row.Alias,
		Name:        row.Name,
		PartitionID: row.PartitionID,
		Issuer:      issuer,
		Config:      providerCfg,
		CreatedAt:   parsedCreatedAt,
		UpdatedAt:   parsedUpdatedAt,
	}, nil
}

func (s *PostgresStorage) GetEnabledIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error) {
	rows, err := s.queries.GetEnabledIdentityProviders(ctx, toPGUUID(tenantID))
	if err != nil {
		return nil, fmt.Errorf("get active identity providers fleet: %w", err)
	}

	providers := make([]model.IdentityProvider, len(rows))
	for i, row := range rows {
		providerUUID, err := pgUUIDToUUID(row.ID)
		if err != nil {
			return nil, fmt.Errorf("parse active provider UUID at index %d: %w", i, err)
		}
		parsedCreatedAt, _ := pgTimestamptzToTime(row.CreatedAt)
		parsedUpdatedAt, _ := pgTimestamptzToTime(row.UpdatedAt)

		var providerCfg model.IdentityProviderConfig
		if len(row.Config) > 0 {
			_ = json.Unmarshal(row.Config, &providerCfg)
		}

		var issuer string
		if row.Issuer != nil {
			issuer = *row.Issuer
		}

		providers[i] = model.IdentityProvider{
			ID:          providerUUID,
			TenantID:    tenantID,
			IDPType:     row.IdpType,
			Enabled:     row.Enabled,
			Alias:       row.Alias,
			Name:        row.Name,
			PartitionID: row.PartitionID,
			Issuer:      issuer,
			Config:      providerCfg,
			CreatedAt:   parsedCreatedAt,
			UpdatedAt:   parsedUpdatedAt,
		}
	}
	return providers, nil
}

// SaveUserProfile provisions user profiles using multi-tenant partition parameters and structural collision validations.
func (s *PostgresStorage) SaveUserProfile(ctx context.Context, tenantID uuid.UUID, partitionID int64, profile model.UserProfile) error {
	// 1. Validate boundary collisions against the strict tenant and partition combination walls
	exists, err := s.queries.CheckUserProfileCollision(ctx, sqlcdb.CheckUserProfileCollisionParams{
		TenantUuid:        toPGUUID(tenantID),
		PartitionID:       partitionID,
		PreferredUsername: profile.PreferredUsername,
		Email:             profile.Email,
	})
	if err != nil {
		return fmt.Errorf("collision check user profile: %w", err)
	}
	if exists {
		count, _ := s.queries.CheckExactUsernameCollision(ctx, sqlcdb.CheckExactUsernameCollisionParams{
			TenantUuid:        toPGUUID(tenantID),
			PartitionID:       partitionID,
			PreferredUsername: profile.PreferredUsername,
		})
		if count > 0 {
			return port.ErrUsernameAlreadyExists
		}
		return port.ErrEmailAlreadyExists
	}

	// 2. Commit the initialized entry profile parameters down into the schema
	err = s.queries.SaveUserProfile(ctx, sqlcdb.SaveUserProfileParams{
		ID:                toPGUUID(profile.ID),
		PreferredUsername: profile.PreferredUsername,
		Name:              profile.Name,
		FirstName:         profile.FirstName,
		LastName:          profile.LastName,
		Email:             profile.Email,
		EmailVerified:     profile.EmailVerified,
		PartitionID:       partitionID,
		LifecycleState:    sqlcdb.ProfileLifecycleState(profile.LifecycleState), // Bound cleanly to generated enum type
		Blocked:           profile.Blocked,                                      // Maps orthogonal security flag
		TenantUuid:        toPGUUID(tenantID),
	})
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

//nolint:unused
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
		Issuer:      "", // TODO Placeholder for issuer, adjust as needed
		Config:      providerCfg,
		CreatedAt:   parsedCreatedAt,
		UpdatedAt:   parsedUpdatedAt,
	}, nil
}

// GetUserProfileByPreferredUsername queries user rows cleanly using the optimized single-index username track.
func (s *PostgresStorage) GetUserProfileByPreferredUsername(ctx context.Context, tenantID uuid.UUID, partitionID int64, username string) (*model.UserProfile, error) {
	row, err := s.queries.GetUserProfileByPreferredUsername(ctx, sqlcdb.GetUserProfileByPreferredUsernameParams{
		PartitionID:       partitionID,
		PreferredUsername: username,
		TenantUuid:        toPGUUID(tenantID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user profile not found for username %s: %w", username, port.ErrUserProfileNotFound)
		}
		return nil, fmt.Errorf("get user profile by preferred username query: %w", err)
	}

	parsedID, _ := pgUUIDToUUID(row.ID)

	return &model.UserProfile{
		ID:                parsedID,
		TenantID:          tenantID,
		PartitionID:       row.PartitionID,
		PreferredUsername: row.PreferredUsername,
		Name:              row.Name,
		FirstName:         row.FirstName,
		LastName:          row.LastName,
		Email:             row.Email,
		EmailVerified:     row.EmailVerified,
		LifecycleState:    model.ProfileLifecycleState(row.LifecycleState),
		Blocked:           row.Blocked,
		CreatedAt:         pgTimestamptzToTimeOrZero(row.CreatedAt),
		UpdatedAt:         pgTimestamptzToTimeOrZero(row.UpdatedAt),
	}, nil
}

// GetUserProfileByEmail queries user rows cleanly using the optimized single-index email track.
func (s *PostgresStorage) GetUserProfileByEmail(ctx context.Context, tenantID uuid.UUID, partitionID int64, email string) (*model.UserProfile, error) {
	row, err := s.queries.GetUserProfileByEmail(ctx, sqlcdb.GetUserProfileByEmailParams{
		PartitionID: partitionID,
		Email:       email,
		TenantUuid:  toPGUUID(tenantID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user profile not found for email %s: %w", email, port.ErrUserProfileNotFound)
		}
		return nil, fmt.Errorf("get user profile by email query: %w", err)
	}

	parsedID, _ := pgUUIDToUUID(row.ID)

	return &model.UserProfile{
		ID:                parsedID,
		TenantID:          tenantID,
		PartitionID:       row.PartitionID,
		PreferredUsername: row.PreferredUsername,
		Name:              row.Name,
		FirstName:         row.FirstName,
		LastName:          row.LastName,
		Email:             row.Email,
		EmailVerified:     row.EmailVerified,
		LifecycleState:    model.ProfileLifecycleState(row.LifecycleState),
		Blocked:           row.Blocked,
		CreatedAt:         pgTimestamptzToTimeOrZero(row.CreatedAt),
		UpdatedAt:         pgTimestamptzToTimeOrZero(row.UpdatedAt),
	}, nil
}

// GetUserProfileByID fetches a user profile strictly using its numeric partition ID and tenant isolation context [5.7].
func (s *PostgresStorage) GetUserProfileByID(
	ctx context.Context,
	tenantUUID uuid.UUID,
	partitionID int64,
	profileID uuid.UUID,
) (*model.UserProfile, error) {

	// Note: Your compiled sqlc model (GetUserProfileByIDParams) does not feature an explicit @id parameter.
	// It uses the primary sequential composite unique key combination (tenant_id, partition_id) to return the head row [5.7].
	arg := sqlcdb.GetUserProfileByIDParams{
		TenantUuid:  toPGUUID(tenantUUID),
		PartitionID: partitionID,
	}

	row, err := s.queries.GetUserProfileByID(ctx, arg)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("storage: user profile not found for partition %d: %w", partitionID, port.ErrUserProfileNotFound)
		}
		return nil, fmt.Errorf("storage: database error during partitioned profile lookup: %w", err)
	}

	return &model.UserProfile{
		ID:                row.ID.Bytes,
		TenantID:          tenantUUID,
		PartitionID:       row.PartitionID,
		PreferredUsername: row.PreferredUsername,
		Name:              row.Name,
		FirstName:         row.FirstName,
		LastName:          row.LastName,
		Email:             row.Email,
		EmailVerified:     row.EmailVerified,
		Blocked:           row.Blocked,
		LifecycleState:    model.ProfileLifecycleState(row.LifecycleState),
	}, nil
}

// GetUserProfileByIDAndPartitionAlias resolves a partitioned user profile using the stateless string partition alias [5.7].
func (s *PostgresStorage) GetUserProfileByIDAndPartitionAlias(
	ctx context.Context,
	tenantID uuid.UUID,
	partitionAlias string,
	profileID uuid.UUID,
) (*model.UserProfile, error) {

	// 1. Pack the clean domain types straight into your compiled sqlc parameter structure
	arg := sqlcdb.GetUserProfileByIDAndPartitionAliasParams{
		TenantUuid:     toPGUUID(tenantID),
		PartitionAlias: partitionAlias,
		ID:             toPGUUID(profileID),
	}

	// 2. Execute the indexed CTE query transaction over the sqlc receiver
	row, err := s.queries.GetUserProfileByIDAndPartitionAlias(ctx, arg)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("storage: partitioned user profile %s not found: %w", profileID, port.ErrUserProfileNotFound)
		}
		return nil, fmt.Errorf("storage: database error during alias-joined profile query: %w", err)
	}

	// 3. Re-map the generated sqlc types safely back into your decoupled domain model format [3.1]
	parsedID, _ := pgUUIDToUUID(row.ID)

	return &model.UserProfile{
		ID:                parsedID,
		TenantID:          tenantID,
		PartitionID:       row.PartitionID,
		PreferredUsername: row.PreferredUsername,
		Name:              row.Name,
		FirstName:         row.FirstName,
		LastName:          row.LastName,
		Email:             row.Email,
		EmailVerified:     row.EmailVerified,
		LifecycleState:    model.ProfileLifecycleState(row.LifecycleState),
		Blocked:           row.Blocked,
		CreatedAt:         pgTimestamptzToTimeOrZero(row.CreatedAt),
		UpdatedAt:         pgTimestamptzToTimeOrZero(row.UpdatedAt),
	}, nil
}

// GetUserProfileByIdentifier fetches a user profile row matching a specific identity provider
// under strict multi-tenant partition isolation rules.
func (s *PostgresStorage) GetUserProfileByIdentifier(
	ctx context.Context,
	tenantUUID uuid.UUID,
	partitionID int64,
	providerID uuid.UUID,
	identifier string,
) (*model.UserProfile, error) {

	// 1. Pack parameters into the type-safe compiled sqlc container params struct [3.1]
	arg := sqlcdb.GetUserProfileByIdentifierParams{
		PartitionID:        partitionID,
		IdentityProviderID: toPGUUID(providerID),
		Identifier:         strings.TrimSpace(identifier),
		TenantUuid:         toPGUUID(tenantUUID), // Materialized CTE parameter hook [5.7]
	}

	// 2. Execute the indexed database query pass over the queries repository handle [3.1]
	row, err := s.queries.GetUserProfileByIdentifier(ctx, arg)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("storage: user profile context not found for provider: %w", port.ErrUserProfileNotFound)
		}
		return nil, fmt.Errorf("storage: database error during provider-scoped profile lookup: %w", err)
	}

	// 3. Unpack type-safe pgtype database columns back into your decoupled domain model layout [3.1]
	parsedID, err := pgUUIDToUUID(row.ID)
	if err != nil {
		return nil, fmt.Errorf("storage: corrupt user profile identifier layout: %w", err)
	}

	return &model.UserProfile{
		ID:                parsedID,
		TenantID:          tenantUUID,
		PartitionID:       row.PartitionID,
		PreferredUsername: row.PreferredUsername,
		Name:              row.Name,
		FirstName:         row.FirstName,
		LastName:          row.LastName,
		Email:             row.Email,
		EmailVerified:     row.EmailVerified,
		LifecycleState:    model.ProfileLifecycleState(row.LifecycleState), // Safely casts sqlcdb.ProfileLifecycleState to domain string types [3.1]
		Blocked:           row.Blocked,
		CreatedAt:         pgTimestamptzToTimeOrZero(row.CreatedAt),
		UpdatedAt:         pgTimestamptzToTimeOrZero(row.UpdatedAt),
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

// GetIdentitiesByProfileID queries the persistent relational table layers using an active
// user profile ID and partition key to fetch all linked external identity mapping records.
func (s *PostgresStorage) GetUserIdentitiesByProfileID(ctx context.Context, tenantUUID uuid.UUID, partitionID int64, profileID uuid.UUID) ([]model.UserIdentity, error) {
	// 1. Marshall domain primitives cleanly over to driver-native pgtype variables
	var pgTenantUUID pgtype.UUID
	if err := pgTenantUUID.Scan(tenantUUID.String()); err != nil {
		return nil, err
	}

	var pgProfileUUID pgtype.UUID
	if err := pgProfileUUID.Scan(profileID.String()); err != nil {
		return nil, err
	}

	// 2. Delegate execution straight across to your auto-generated SQLC code compiler layer
	rows, err := s.queries.GetUserIdentitiesByProfileID(ctx, sqlcdb.GetUserIdentitiesByProfileIDParams{
		PartitionID:   partitionID,
		UserProfileID: pgProfileUUID,
		TenantUuid:    pgTenantUUID,
	})
	if err != nil {
		return nil, err
	}

	// 3. Hydrate the driver row collections back into a clean slice of un-annotated pure domain model entities
	domainIdentities := make([]model.UserIdentity, 0, len(rows))
	for _, row := range rows {
		parsedIdentUUID, err := uuid.Parse(row.ID.String())
		if err != nil {
			continue
		}

		parsedProviderUUID, err := uuid.Parse(row.IdentityProviderID.String())
		if err != nil {
			continue
		}

		ident := model.UserIdentity{
			ID:                 parsedIdentUUID,
			UserProfileID:      profileID,
			IdentityProviderID: parsedProviderUUID,
			ExternalIdentityID: row.ExternalIdentityID,
			LoginCount:         int(row.LoginCount),
			LastLoginAt:        pgTimestamptzToTimePtr(row.LastLoginAt),
			CoupledAt:          row.CoupledAt.Time,
		}

		domainIdentities = append(domainIdentities, ident)
	}

	return domainIdentities, nil
}

func (s *PostgresStorage) GetIdentityByProfileAndProvider(ctx context.Context, userProfileID uuid.UUID, providerID uuid.UUID) (*model.UserIdentity, error) {
	row, err := s.queries.GetUserIdentityByProfileIDAndProviderID(ctx, sqlcdb.GetUserIdentityByProfileIDAndProviderIDParams{
		UserProfileID:      toPGUUID(userProfileID),
		IdentityProviderID: toPGUUID(providerID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("identity not found: %w", port.ErrIdentityNotFound)
		}
		return nil, fmt.Errorf("get identity: %w", err)
	}

	return &model.UserIdentity{
		ID:                 uuid.UUID(row.ID.Bytes),
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		ExternalIdentityID: row.ExternalIdentityID,
		LoginCount:         int(row.LoginCount),
		LastLoginAt:        pgTimestamptzToTimePtr(row.LastLoginAt),
		CoupledAt:          row.CoupledAt.Time,
	}, nil
}

// GetUserIdentityByProviderAndExternalID handles lookup routing requests for incoming federated validation assertions.
func (s *PostgresStorage) GetUserIdentityByProviderAndExternalID(ctx context.Context, tenantID uuid.UUID, partitionID int64, providerID uuid.UUID, externalID string) (*model.UserIdentity, error) {
	row, err := s.queries.GetUserIdentityByProviderAndExternalID(ctx, sqlcdb.GetUserIdentityByProviderAndExternalIDParams{
		PartitionID:        partitionID,
		IdentityProviderID: toPGUUID(providerID),
		ExternalIdentityID: externalID,
		TenantUuid:         toPGUUID(tenantID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("federated link not found for external id %s: %w", externalID, port.ErrIdentityNotFound)
		}
		return nil, fmt.Errorf("get identity by provider and external ID tracker: %w", err)
	}

	userProfileUUID, err := pgUUIDToUUID(row.UserProfileID)
	if err != nil {
		return nil, fmt.Errorf("parse user profile link uuid: %w", err)
	}

	return &model.UserIdentity{
		ID:                 row.ID.Bytes,
		UserProfileID:      userProfileUUID,
		IdentityProviderID: providerID,
		ExternalIdentityID: row.ExternalIdentityID,
		LoginCount:         int(row.LoginCount),
		LastLoginAt:        pgTimestamptzToTimePtr(row.LastLoginAt),
		CoupledAt:          row.CoupledAt.Time,
	}, nil
}

// GetUserIdentityByIdentifier resolves a user identity mapping using a username or email handle
// from the user_identities table under explicit multi-tenant partition isolation rules.
func (s *PostgresStorage) GetUserIdentityByIdentifier(
	ctx context.Context,
	tenantUUID uuid.UUID,
	partitionID int64,
	providerID uuid.UUID,
	identifier string,
) (*model.UserIdentity, error) {

	// 1. Pack domain parameters into the type-safe compiled sqlc params container [10]
	arg := sqlcdb.GetUserIdentityByIdentifierParams{
		PartitionID:        partitionID,
		IdentityProviderID: toPGUUID(providerID),
		Identifier:         strings.TrimSpace(identifier),
		TenantUuid:         toPGUUID(tenantUUID), // Materialized CTE parameter hook [10]
	}

	// 2. Execute the indexed database query pass over the queries repository handle [10]
	row, err := s.queries.GetUserIdentityByIdentifier(ctx, arg)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("storage: user identity mapping not found: %w", port.ErrIdentityNotFound)
		}
		return nil, fmt.Errorf("storage: database error during identity identifier lookup: %w", err)
	}

	// 3. Unpack type-safe pgtype values back into your decoupled domain model layout [11]
	userProfileID, err := pgUUIDToUUID(row.UserProfileID)
	if err != nil {
		return nil, fmt.Errorf("storage: corrupt profile link identity payload: %w", err)
	}

	identityProviderID, err := pgUUIDToUUID(row.IdentityProviderID)
	if err != nil {
		return nil, fmt.Errorf("storage: corrupt provider link identity payload: %w", err)
	}

	return &model.UserIdentity{
		ID:                 row.ID.Bytes,
		UserProfileID:      userProfileID,
		IdentityProviderID: identityProviderID,
		ExternalIdentityID: row.ExternalIdentityID,
		LoginCount:         int(row.LoginCount),
		LastLoginAt:        pgTimestamptzToTimePtr(row.LastLoginAt),
		CoupledAt:          row.CoupledAt.Time,
	}, nil
}

// FindProfileByEmail queries across global partitions via compiled cross-tenant indexes.
func (s *PostgresStorage) FindProfileByEmail(ctx context.Context, partitionID int64, email string) (*model.UserProfile, error) {
	row, err := s.queries.FindProfileByEmail(ctx, sqlcdb.FindProfileByEmailParams{
		PartitionID: partitionID,
		Email:       email,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user profile not found for email %s: %w", email, port.ErrUserProfileNotFound)
		}
		return nil, fmt.Errorf("find user profile by email: %w", err)
	}

	parsedID, _ := pgUUIDToUUID(row.ID)
	parsedTenantID, _ := pgUUIDToUUID(row.TenantUuid)
	parsedCreatedAt, _ := pgTimestamptzToTime(row.CreatedAt)
	parsedUpdatedAt, _ := pgTimestamptzToTime(row.UpdatedAt)

	return &model.UserProfile{
		ID:                parsedID,
		TenantID:          parsedTenantID,
		PartitionID:       row.PartitionID,
		PreferredUsername: row.PreferredUsername,
		Name:              row.Name,
		FirstName:         row.FirstName,
		LastName:          row.LastName,
		Email:             row.Email,
		EmailVerified:     row.EmailVerified,
		LifecycleState:    model.ProfileLifecycleState(row.LifecycleState),
		Blocked:           row.Blocked,
		CreatedAt:         parsedCreatedAt,
		UpdatedAt:         parsedUpdatedAt,
	}, nil
}

// UpsertUserIdentity commits structural linkage changes during onboarding loops under multi-tenant isolation gates.
func (s *PostgresStorage) UpsertUserIdentity(ctx context.Context, tenantID uuid.UUID, partitionID int64, identity model.UserIdentity) error {
	err := s.queries.UpsertUserIdentity(ctx, sqlcdb.UpsertUserIdentityParams{
		ID:                 toPGUUID(identity.ID),
		PartitionID:        partitionID,
		UserProfileID:      toPGUUID(identity.UserProfileID),
		IdentityProviderID: toPGUUID(identity.IdentityProviderID),
		ExternalIdentityID: identity.ExternalIdentityID,
		LoginCount:         int32(identity.LoginCount),
		LastLoginAt:        toPGTimestamptzPtr(identity.LastLoginAt),
		CoupledAt:          toPGTimestamptz(identity.CoupledAt),
		TenantUuid:         toPGUUID(tenantID),
	})
	if err != nil {
		return fmt.Errorf("upsert user identity parameters mapping block: %w", err)
	}
	return nil
}

// IncrementUserIdentityLoginTracker logs metrics securely and registers usage metrics.
func (s *PostgresStorage) IncrementUserIdentityLoginTracker(ctx context.Context, tenantID uuid.UUID, partitionID int64, identityID uuid.UUID, loginTime time.Time) error {
	err := s.queries.IncrementUserIdentityLoginTracker(ctx, sqlcdb.IncrementUserIdentityLoginTrackerParams{
		LastLoginAt: toPGTimestamptz(loginTime),
		PartitionID: partitionID,
		IdentityID:  toPGUUID(identityID),
		TenantUuid:  toPGUUID(tenantID),
	})
	if err != nil {
		return fmt.Errorf("increment user identity login track: %w", err)
	}
	return nil
}

// RevokeSession terminates active authorization code and refresh token sessions
// by passing tracking parameters straight through your safe generated sqlc queries.
func (s *PostgresStorage) RevokeSession(ctx context.Context, tenantID uuid.UUID, subject string, clientID string) error {
	// 1. Initialize a transaction block to ensure atomic execution passes
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("revoke session: failed to initiate database transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 2. Bind the transactional handle straight to your type-safe query container
	txQueries := s.queries.WithTx(tx)

	pgTenantID := toPGUUID(tenantID)

	// 3. Fire the type-safe generated auth session deletion query
	err = txQueries.RevokeSession(ctx, sqlcdb.RevokeSessionParams{
		TenantUuid: pgTenantID,
		Subject:    subject,
		ClientID:   clientID,
	})
	if err != nil {
		return fmt.Errorf("revoke session: failed to execute auth session clear: %w", err)
	}

	// 4. Fire the type-safe generated refresh token family deletion query
	err = txQueries.RevokeRefreshTokens(ctx, sqlcdb.RevokeRefreshTokensParams{
		TenantUuid: pgTenantID,
		Subject:    subject,
		ClientID:   clientID,
	})
	if err != nil {
		return fmt.Errorf("revoke session: failed to execute refresh token clear: %w", err)
	}

	// 5. Commit everything safely down to the database catalog
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("revoke session: failed to commit transaction state changes: %w", err)
	}

	return nil
}

// GetPasswordCredentialByProfileID isolates hash extraction routes safely behind tenant and partition cross-checks.
func (s *PostgresStorage) GetPasswordCredentialByProfileID(ctx context.Context, tenantID uuid.UUID, partitionID int64, userProfileID uuid.UUID, providerID uuid.UUID) (*model.PasswordCredential, error) {
	// Invokes the compiled, type-safe sqlc wrapper method passing all isolation boundaries
	row, err := s.queries.GetPasswordCredentialByProfileID(ctx, sqlcdb.GetPasswordCredentialByProfileIDParams{
		PartitionID:        partitionID,
		UserProfileID:      toPGUUID(userProfileID),
		IdentityProviderID: toPGUUID(providerID),
		TenantUuid:         toPGUUID(tenantID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("password signature missing for profile: %w", port.ErrPasswordCredentialNotFound)
		}
		return nil, fmt.Errorf("get password credential by profile ID query failed: %w", err)
	}

	return &model.PasswordCredential{
		UserProfileID:           userProfileID,
		IdentityProviderID:      providerID,
		Argon2Hash:              row.PasswordHash, // Cleanly extracts the string hash value
		FailedVerificationCount: int(row.FailedVerificationCount),
		LastVerificationAttempt: pgTimestamptzToTimePtr(row.LastVerificationAttempt),
		BlockedUntil:            pgTimestamptzToTimePtr(row.BlockedUntil),
		CreatedAt:               pgTimestamptzToTimeOrZero(row.CreatedAt),
		UpdatedAt:               pgTimestamptzToTimeOrZero(row.UpdatedAt),
	}, nil
}

// CreateApplicationProfile registers a central configuration profile blueprint template for a tenant.
func (s *PostgresStorage) CreateApplicationProfile(ctx context.Context, tenantUUID uuid.UUID, profile model.ApplicationProfile) error {
	// Convert domain slices to native string slices for sqlc parameters
	grantTypes := make([]string, len(profile.GrantTypes))
	for i, gt := range profile.GrantTypes {
		grantTypes[i] = string(gt)
	}

	responseTypes := make([]string, len(profile.ResponseTypes))
	for i, rt := range profile.ResponseTypes {
		responseTypes[i] = string(rt)
	}

	// Maps exactly onto sqlcdb.CreateApplicationProfileParams generated fields
	err := s.queries.CreateApplicationProfile(ctx, sqlcdb.CreateApplicationProfileParams{
		ID:                      toPGUUID(profile.ID),
		ProfileName:             profile.ProfileName,
		IsEnabled:               profile.IsEnabled,
		TokenEndpointAuthMethod: string(profile.TokenEndpointAuthMethod),
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		AccessTokenLifetime:     int32(profile.AccessTokenLifetime / time.Second),
		IDTokenLifetime:         int32(profile.IDTokenLifetime / time.Second),
		RefreshTokenLifetime:    int32(profile.RefreshTokenLifetime / time.Second),
		EnforceRtr:              profile.EnforceRTR,
		SigningAlgorithm:        string(profile.SigningAlgorithm),
		TenantUuid:              toPGUUID(tenantUUID),
	})
	if err != nil {
		return fmt.Errorf("storage: failed to create application profile: %w", err)
	}
	return nil
}

// CreateApplicationGroup registers an independent authorization group parameter constraint boundary block.
func (s *PostgresStorage) CreateApplicationGroup(ctx context.Context, tenantUUID uuid.UUID, group model.ApplicationGroup) error {
	// 1. Initialize a transactional context block to guarantee strict relational safety [fail-secure]
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("storage: failed to initiate group creation transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // Safe implicit rollback guard loop if an operation panics

	// Bind the transactional handles straight to your compiled query container
	txQueries := s.queries.WithTx(tx)

	var pgDefaultIDPID pgtype.UUID
	if group.DefaultIDPID != nil {
		pgDefaultIDPID = toPGUUID(*group.DefaultIDPID)
	}

	// 2. Provision the parent row record inside the core groups table
	err = txQueries.CreateApplicationGroup(ctx, sqlcdb.CreateApplicationGroupParams{
		ID:                     toPGUUID(group.ID),
		GroupName:              group.GroupName,
		IsEnabled:              group.IsEnabled,
		AllowedScopes:          group.AllowedScopes,
		DefaultScopes:          group.DefaultScopes,
		AllowedAudiences:       group.AllowedAudiences,
		DefaultIdpID:           pgDefaultIDPID,
		RedirectUris:           group.RedirectURIs,
		PostLogoutRedirectUris: group.PostLogoutRedirectURIs,
		TenantUuid:             toPGUUID(tenantUUID),
	})
	if err != nil {
		return fmt.Errorf("storage: failed to create application group: %w", err)
	}

	// 3. Conditional Batch Step: Only stream join entries if whitelisted providers are specified
	if len(group.AllowedIDPIDs) > 0 {
		tenantID, err := txQueries.GetTenantIDByUUID(ctx, toPGUUID(tenantUUID))
		if err != nil {
			return fmt.Errorf("storage: failed to resolve tenant internal ID: %w", err)
		}

		// Map our type-safe Go domain slices into the SQLC-generated COPY layout schema matrix
		batchEntries := make([]sqlcdb.BindIdentityProvidersToGroupParams, len(group.AllowedIDPIDs))

		pgGroupUUID := toPGUUID(group.ID)

		for i, idpID := range group.AllowedIDPIDs {
			batchEntries[i] = sqlcdb.BindIdentityProvidersToGroupParams{
				GroupID:  pgGroupUUID,
				IdpID:    toPGUUID(idpID),
				TenantID: tenantID,
			}
		}

		// Execute ultra-fast streaming injection over the native PostgreSQL COPY protocol [O(1) insertion pass]
		_, err = txQueries.BindIdentityProvidersToGroup(ctx, batchEntries)
		if err != nil {
			return fmt.Errorf("storage: failed to stream mapping indices into permission join matrix: %w", err)
		}
	}

	// 4. Lock and commit all mutations down to disk atomically
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("storage: transaction serialization lock commit phase rejected: %w", err)
	}

	return nil
}

// CreateApplication provisions an independent application mapping instance under the specific tenant.
func (s *PostgresStorage) CreateApplication(ctx context.Context, tenantUUID uuid.UUID, app model.Application) error {
	// Maps exactly onto sqlcdb.CreateApplicationParams generated fields
	err := s.queries.CreateApplication(ctx, sqlcdb.CreateApplicationParams{
		ID:               toPGUUID(app.ID),
		ProfileID:        toPGUUID(app.ProfileID),
		GroupID:          toPGUUID(app.GroupID),
		ClientID:         app.ClientID,
		ClientSecretHash: app.ClientSecretHash,
		ApplicationName:  app.ApplicationName,
		TenantUuid:       toPGUUID(tenantUUID),
	})
	if err != nil {
		if strings.Contains(err.Error(), "violates unique constraint") {
			return fmt.Errorf("storage: application client_id already exists: %w", port.ErrApplicationNotFound)
		}
		return fmt.Errorf("storage: failed to create application record: %w", err)
	}
	return nil
}

// DeleteApplication drops a core client application node completely from the database namespace.
func (s *PostgresStorage) DeleteApplication(ctx context.Context, tenantUUID uuid.UUID, clientID string) error {
	// Maps exactly onto sqlcdb.DeleteApplicationParams generated fields
	err := s.queries.DeleteApplication(ctx, sqlcdb.DeleteApplicationParams{
		ClientID:   clientID,
		TenantUuid: toPGUUID(tenantUUID),
	})
	if err != nil {
		return fmt.Errorf("storage: failed to remove application record: %w", err)
	}
	return nil
}

func (s *PostgresStorage) DeleteIdentityProvider(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM identity_providers
		WHERE tenant_id = (SELECT id FROM tenants WHERE tenant_uuid = $1::uuid) AND id = $2::uuid
	`, toPGUUID(tenantID), toPGUUID(idpID))
	return err
}

//nolint:unused
func scanUserProfileRow(row pgx.Row, tenantID uuid.UUID) (model.UserProfile, error) {
	var id pgtype.UUID
	var preferredUsername string
	var name string
	var firstName string // New mapping slot
	var lastName string  // New mapping slot
	var email string
	var emailVerified bool
	var partitionID int64
	var createdAt, updatedAt pgtype.Timestamptz

	// Added explicit columns to match structural mutations
	if err := row.Scan(&id, &preferredUsername, &name, &firstName, &lastName, &email, &emailVerified, &partitionID, &createdAt, &updatedAt); err != nil {
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
		FirstName:         firstName,
		LastName:          lastName,
		Email:             email,
		EmailVerified:     emailVerified,
		PartitionID:       partitionID,
		CreatedAt:         parsedCreatedAt,
		UpdatedAt:         parsedUpdatedAt,
	}, nil
}

// GetUserProfilesByTenant extracts profiles matching a specified partition context arranged in alphabetical sorting sequence.
func (s *PostgresStorage) GetUserProfilesByTenant(ctx context.Context, tenantID uuid.UUID, partitionID int64) ([]model.UserProfile, error) {
	rows, err := s.queries.GetUserProfilesByTenant(ctx, sqlcdb.GetUserProfilesByTenantParams{
		TenantUuid:  toPGUUID(tenantID),
		PartitionID: partitionID, // Restricts leakage paths strictly inside the slice caller
	})
	if err != nil {
		return nil, fmt.Errorf("get user profiles collection by tenant partition: %w", err)
	}

	profiles := make([]model.UserProfile, len(rows))
	for i, r := range rows {
		parsedID, _ := pgUUIDToUUID(r.ID)

		profiles[i] = model.UserProfile{
			ID:                parsedID,
			TenantID:          tenantID,
			PartitionID:       r.PartitionID,
			PreferredUsername: r.PreferredUsername,
			Name:              r.Name,
			FirstName:         r.FirstName,
			LastName:          r.LastName,
			Email:             r.Email,
			EmailVerified:     r.EmailVerified,
			LifecycleState:    model.ProfileLifecycleState(r.LifecycleState),
			Blocked:           r.Blocked,
			CreatedAt:         pgTimestamptzToTimeOrZero(r.CreatedAt),
			UpdatedAt:         pgTimestamptzToTimeOrZero(r.UpdatedAt),
		}
	}
	return profiles, nil
}

// DeleteUserProfile drops user entries explicitly validating both the target uuid and partitionID layout blocks.
func (s *PostgresStorage) DeleteUserProfile(ctx context.Context, tenantID uuid.UUID, partitionID int64, userID uuid.UUID) error {
	err := s.queries.DeleteUserProfile(ctx, sqlcdb.DeleteUserProfileParams{
		TenantUuid:  toPGUUID(tenantID),
		PartitionID: partitionID,
		ID:          toPGUUID(userID),
	})
	if err != nil {
		return fmt.Errorf("delete user profile transaction block: %w", err)
	}
	return nil
}

// UpdateUserProfile writes changes matching the structural layouts back into your storage rows natively.
func (s *PostgresStorage) UpdateUserProfile(ctx context.Context, tenantID uuid.UUID, profile model.UserProfile) error {
	err := s.queries.UpdateUserProfile(ctx, sqlcdb.UpdateUserProfileParams{
		PartitionID:       profile.PartitionID,
		PreferredUsername: profile.PreferredUsername,
		Name:              profile.Name,
		FirstName:         profile.FirstName,
		LastName:          profile.LastName,
		Email:             profile.Email,
		EmailVerified:     profile.EmailVerified,
		LifecycleState:    sqlcdb.ProfileLifecycleState(profile.LifecycleState),
		Blocked:           profile.Blocked,
		ID:                toPGUUID(profile.ID),
		TenantUuid:        toPGUUID(tenantID),
	})
	if err != nil {
		return fmt.Errorf("update user profile structural data layout: %w", err)
	}
	return nil
}

func (s *PostgresStorage) GetUserIdentities(ctx context.Context, userProfileID uuid.UUID) ([]model.UserIdentity, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_profile_id, identity_provider_id, external_identity_id, login_count, last_login_at, coupled_at
		FROM user_identities
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
		var lastLogin pgtype.Timestamptz
		var coupled pgtype.Timestamptz
		if err := rows.Scan(&id, &upID, &idpID, &extID, &loginCount, &lastLogin, &coupled); err != nil {
			return nil, err
		}
		parsedID, _ := pgUUIDToUUID(id)
		parsedUP, _ := pgUUIDToUUID(upID)
		parsedIDP, _ := pgUUIDToUUID(idpID)
		identities = append(identities, model.UserIdentity{
			ID:                 parsedID,
			UserProfileID:      parsedUP,
			IdentityProviderID: parsedIDP,
			ExternalIdentityID: extID,
			LoginCount:         loginCount,
			LastLoginAt:        pgTimestamptzToTimePtr(lastLogin),
			CoupledAt:          pgTimestamptzToTimeOrZero(coupled),
		})
	}
	return identities, nil
}

func (s *PostgresStorage) DecoupleIdentity(ctx context.Context, userProfileID uuid.UUID, identityProviderID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM user_identities
		WHERE user_profile_id = $1::uuid AND identity_provider_id = $2::uuid
	`, toPGUUID(userProfileID), toPGUUID(identityProviderID))
	return err
}

// SaveOutboundHandshake persists the outbound OIDC handshake state tracing metrics.
// It maps the URL-Safe Base64 state token string directly to the ID primary key.
func (s *PostgresStorage) SaveOutboundHandshake(ctx context.Context, handshake model.OutboundHandshakeSession) error {
	var targetURI *string
	if handshake.TargetURI != "" {
		targetURI = &handshake.TargetURI
	}

	var callbackURI *string
	if handshake.CallbackURI != "" {
		callbackURI = &handshake.CallbackURI
	}

	// Aligned to the comprehensive model containing PartitionID and CreatedAt
	err := s.queries.SaveOutboundHandshake(ctx, sqlcdb.SaveOutboundHandshakeParams{
		StateToken:         handshake.ID,                           // State token string acts as the primary key lookup slot
		TenantUuid:         toPGUUID(handshake.TenantID),           // CTE automatically resolves to internal int
		PartitionID:        handshake.PartitionID,                  // Enforces strict data isolation
		IdentityProviderID: toPGUUID(handshake.IdentityProviderID), // Links the active upstream configuration profile
		ClientID:           handshake.ClientID,                     // Tracks the consumer core client application
		CodeVerifier:       handshake.CodeVerifier,                 // High-entropy PKCE verifier secret string
		CreatedAt:          toPGTimestamptz(handshake.CreatedAt),   // Mandatory TTL clean up cron index anchor
		ExpiresAt:          toPGTimestamptz(handshake.ExpiresAt),   // 5-minute protocol window boundary ceiling
		TargetUri:          valueOrEmpty(targetURI),                // Remembers the intended landing zone target URL
		CallbackUri:        valueOrEmpty(callbackURI),              // Local verification return path parameter context
	})
	if err != nil {
		return fmt.Errorf("storage: failed to execute outbound handshake insert: %w", err)
	}
	return nil
}

// GetAndConsumeOutboundHandshake executes a single-trip atomic destructive read.
// This completely neutralizes Time-of-Check to Time-of-Use (TOCTOU) race condition vectors.
func (s *PostgresStorage) GetAndConsumeOutboundHandshake(ctx context.Context, tenantID uuid.UUID, stateToken string) (*model.OutboundHandshakeSession, error) {
	// Relies on the atomic SQLC 'GetAndConsumeOutboundHandshake' (DELETE ... RETURNING) query structure.
	// This guarantees that a state-token string CAN ONLY BE READ ONCE across application nodes.
	row, err := s.queries.ConsumeOutboundHandshake(ctx, sqlcdb.ConsumeOutboundHandshakeParams{
		TenantUuid: toPGUUID(tenantID),
		StateToken: stateToken,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("handshake state %s: %w", stateToken, port.ErrSessionNotFound)
		}
		return nil, fmt.Errorf("storage: atomic handshake consumption failure: %w", err)
	}

	providerUUID, err := pgUUIDToUUID(row.IdentityProviderID)
	if err != nil {
		return nil, fmt.Errorf("storage: corrupt handshake provider uuid data mapping: %w", err)
	}

	expiresAt, err := pgTimestamptzToTime(row.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("storage: corrupt handshake expires_at mapping: %w", err)
	}

	createdAt, err := pgTimestamptzToTime(row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("storage: corrupt handshake created_at mapping: %w", err)
	}

	return &model.OutboundHandshakeSession{
		ID:                 row.ID,
		TenantID:           tenantID,
		PartitionID:        row.PartitionID,
		IdentityProviderID: providerUUID,
		ClientID:           row.ClientID,
		CodeVerifier:       row.CodeVerifier,
		CreatedAt:          createdAt,
		ExpiresAt:          expiresAt,
		TargetURI:          valueOrEmpty(row.TargetUri),
		CallbackURI:        valueOrEmpty(row.CallbackUri),
	}, nil
}

// SaveRefreshToken logs long-lived session chains while preserving multi-IdP validation track variables.
func (s *PostgresStorage) SaveRefreshToken(ctx context.Context, token model.RefreshToken) error {
	var parsedIDPUUID pgtype.UUID
	if token.IdentityProviderID != uuid.Nil {
		parsedIDPUUID = toPGUUID(token.IdentityProviderID)
	}

	err := s.queries.SaveRefreshToken(ctx, sqlcdb.SaveRefreshTokenParams{
		TokenID:               token.TokenID,
		ClientID:              token.ClientID,
		Subject:               token.Subject,
		Scopes:                token.Scopes,
		TokenFamilyID:         token.TokenFamilyID,
		IsUsed:                token.IsUsed,
		ExpiresAt:             toPGTimestamptz(token.ExpiresAt),
		IdentityProviderID:    parsedIDPUUID,
		IdentityProviderAlias: stringPtr(token.IdentityProviderAlias),
		SessionID:             stringPtr(token.SessionID),
		TenantUuid:            toPGUUID(token.TenantID),
	})
	if err != nil {
		return fmt.Errorf("save refresh token: %w", err)
	}
	return nil
}

// GetRefreshToken loads an active or replayed refresh token lineage row.
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

	var localIDPUUID uuid.UUID
	if row.IdentityProviderID.Valid {
		localIDPUUID, _ = pgUUIDToUUID(row.IdentityProviderID)
	}

	return &model.RefreshToken{
		TokenID:               row.TokenID,
		TenantID:              tenantUUID,
		ClientID:              row.ClientID,
		Subject:               row.Subject,
		Scopes:                row.Scopes,
		TokenFamilyID:         row.TokenFamilyID,
		IsUsed:                row.IsUsed,
		ExpiresAt:             expiresAt,
		CreatedAt:             createdAt,
		IdentityProviderID:    localIDPUUID,
		IdentityProviderAlias: valueOrEmpty(row.IdentityProviderAlias),
		SessionID:             valueOrEmpty(row.SessionID),
	}, nil
}

func (s *PostgresStorage) MarkRefreshTokenUsed(ctx context.Context, tokenID string) error {
	err := s.queries.MarkRefreshTokenUsed(ctx, tokenID)
	if err != nil {
		return fmt.Errorf("mark refresh token used: %w", err)
	}
	return nil
}

func (s *PostgresStorage) RevokeRefreshTokenFamily(ctx context.Context, tokenFamilyID string) error {
	err := s.queries.RevokeRefreshTokenFamily(ctx, tokenFamilyID)
	if err != nil {
		return fmt.Errorf("revoke refresh token family: %w", err)
	}
	return nil
}

// PurgeTenantSessionsAndTokens performs a cascading atomic wipe of all active user tokens and sessions for a tenant.
func (s *PostgresStorage) PurgeTenantSessionsAndTokens(ctx context.Context, tenantID uuid.UUID) error {
	// 1. Initialize a transaction block to ensure atomic deletion safety across schemas
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("purge tenant session data: failed to initiate database transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 2. Bind the transactional handle straight to your type-safe query container
	txQueries := s.queries.WithTx(tx)
	pgTenantID := toPGUUID(tenantID)

	// 3. Fire the type-safe generated authorization code session purge query
	if err = txQueries.PurgeAuthSessionsByTenant(ctx, pgTenantID); err != nil {
		return fmt.Errorf("purge tenant session data: failed to clear auth sessions cache: %w", err)
	}

	// 4. Fire the type-safe generated refresh token family tree purge query
	if err = txQueries.PurgeRefreshTokensByTenant(ctx, pgTenantID); err != nil {
		return fmt.Errorf("purge tenant session data: failed to clear refresh token chains: %w", err)
	}

	// 5. Commit everything safely down to the database catalog to lock in modifications
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("purge tenant session data: failed to commit transaction state updates: %w", err)
	}

	return nil
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

// GetPartitionByID resolves a partition's configuration and human-readable string alias
// using its internal numeric ID. Satisfies the updated port.Storage contract.
func (s *PostgresStorage) GetPartitionByID(ctx context.Context, tenantUUID uuid.UUID, partitionID int64) (*model.Partition, error) {
	// 1. Execute the type-safe query loop through the compiled SQLC handler layer
	row, err := s.queries.GetPartitionByID(ctx, sqlcdb.GetPartitionByIDParams{
		PartitionID: partitionID,
		TenantUuid:  toPGUUID(tenantUUID), // Encapsulates standard pgtype mappings natively
	})
	if err != nil {
		// Catch standard missing row matrices to prevent leaky database errors downstream
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("partition with internal id %d not found for tenant %s: %w", partitionID, tenantUUID, port.ErrPartitionNotFound)
		}
		return nil, fmt.Errorf("storage: failed to execute partition id lookup: %w", err)
	}

	// 2. Map the structural database outputs cleanly into your domain model layout
	return &model.Partition{
		ID:        row.ID,
		TenantID:  tenantUUID,
		Name:      row.Name,
		AliasName: row.AliasName, // This provides the string name (e.g. "eu-west") for your JWT "pid" claims
	}, nil
}

// GetPartitionByAlias retrieves a specific data isolation boundary using the clean named parameter mapping.
func (s *PostgresStorage) GetPartitionByAlias(ctx context.Context, tenantID uuid.UUID, alias string) (*model.Partition, error) {
	// FIXED: Replaced legacy "Column1" with the newly generated "TenantUuid" struct key
	row, err := s.queries.GetPartitionByAlias(ctx, sqlcdb.GetPartitionByAliasParams{
		TenantUuid: toPGUUID(tenantID),
		AliasName:  alias,
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

// CreatePartition registers a fresh tenant partition, matching your updated named parameter fields perfectly.
func (s *PostgresStorage) CreatePartition(ctx context.Context, tenantID uuid.UUID, name, aliasName string) (*model.Partition, error) {
	row, err := s.queries.CreatePartition(ctx, sqlcdb.CreatePartitionParams{
		TenantUuid: toPGUUID(tenantID),
		Name:       name,
		AliasName:  aliasName,
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

// UpdatePasswordLockoutState writes password lockout metrics to postgres.
func (s *PostgresStorage) UpdatePasswordLockoutState(ctx context.Context, tenantID uuid.UUID, partitionID int64, userProfileID uuid.UUID, providerID uuid.UUID, failedCount int, lastAttempt *time.Time, blockedUntil *time.Time) error {
	err := s.queries.UpdatePasswordLockoutState(ctx, sqlcdb.UpdatePasswordLockoutStateParams{
		FailedVerificationCount: int32(failedCount),
		LastVerificationAttempt: toPGTimestamptzPtr(lastAttempt),
		BlockedUntil:            toPGTimestamptzPtr(blockedUntil),
		UserProfileID:           toPGUUID(userProfileID),
		IdentityProviderID:      toPGUUID(providerID),
	})
	if err != nil {
		return fmt.Errorf("update password lockout state: %w", err)
	}
	return nil
}

// ResetPasswordCounters clears password lockout metrics on login success.
func (s *PostgresStorage) ResetPasswordCounters(ctx context.Context, tenantID uuid.UUID, partitionID int64, userProfileID uuid.UUID, providerID uuid.UUID) error {
	err := s.queries.ResetPasswordCounters(ctx, sqlcdb.ResetPasswordCountersParams{
		UserProfileID:      toPGUUID(userProfileID),
		IdentityProviderID: toPGUUID(providerID),
	})
	if err != nil {
		return fmt.Errorf("reset password counters: %w", err)
	}
	return nil
}

// GetIdentityProviderByType resolves an identity provider by its type under a tenant.
func (s *PostgresStorage) GetIdentityProviderByType(ctx context.Context, tenantID uuid.UUID, idpType string) (*model.IdentityProvider, error) {
	providers, err := s.GetIdentityProviders(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, p := range providers {
		if p.IDPType == idpType {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("identity provider type %s not found: %w", idpType, port.ErrIdentityProviderNotFound)
}
