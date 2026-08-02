package postgres

import (
	"context"
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
			return nil, fmt.Errorf("client %s for tenant %s: %w", clientID, tenantID, port.ErrTenantNotFound)
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
	}, nil
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
			return nil, fmt.Errorf("session %s for tenant %s: %w", code, tenantID, port.ErrTenantNotFound)
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
		ID:        tenantID,
		Name:      row.Name,
		Domain:    row.DomainName,
		IsActive:  row.IsActive,
		CreatedAt: createdAt,
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
		ID:        resolvedID,
		Name:      row.Name,
		Domain:    row.DomainName,
		IsActive:  row.IsActive,
		CreatedAt: createdAt,
	}, nil
}

func (s *PostgresStorage) CreateTenant(ctx context.Context, tenant model.Tenant) error {
	commandTag, err := s.queries.CreateTenant(ctx, sqlcdb.CreateTenantParams{
		TenantUuid: toPGUUID(tenant.ID),
		Name:       tenant.Name,
		DomainName: tenant.Domain,
		IsActive:   tenant.IsActive,
		CreatedAt:  toPGTimestamptz(tenant.CreatedAt),
	})
	if err != nil {
		return fmt.Errorf("create tenant: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		return fmt.Errorf("create tenant: expected 1 row to be inserted, affected %d", commandTag.RowsAffected())
	}

	return nil
}

func (s *PostgresStorage) RevokeSession(ctx context.Context, tenantID uuid.UUID, subject string, clientID string) error {
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
