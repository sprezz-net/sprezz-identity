package port

import (
	"context"
	"errors"
	"time"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

var (
	ErrTenantNotFound              = errors.New("tenant not found")
	ErrClientNotFound              = errors.New("client not found")
	ErrSessionNotFound             = errors.New("session not found")
	ErrIdentityProviderNotFound    = errors.New("identity provider not found")
	ErrUserProfileNotFound         = errors.New("user profile not found")
	ErrPasswordCredentialNotFound  = errors.New("password credential not found")
	ErrIdentityNotFound            = errors.New("identity not found")
	ErrInteractionSessionNotFound  = errors.New("interaction session not found")
)

type Storage interface {
	SaveClient(ctx context.Context, client model.ClientApplication) error
	GetClient(ctx context.Context, tenantID uuid.UUID, clientID string) (*model.ClientApplication, error)
	SaveAuthSession(ctx context.Context, session model.AuthorizationCodeSession) error
	GetAndConsumeAuthSession(ctx context.Context, tenantID uuid.UUID, code string) (*model.AuthorizationCodeSession, error)
	ResolveTenantByDomain(ctx context.Context, domain string) (*model.Tenant, error)
	ResolveTenantByID(ctx context.Context, tenantID uuid.UUID) (*model.Tenant, error)
	CreateTenant(ctx context.Context, tenant model.Tenant) error
	CreateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) error
	GetEnabledIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error)
	GetUserProfileByIdentifier(ctx context.Context, tenantID uuid.UUID, providerID uuid.UUID, identifier string) (*model.UserProfile, error)
	GetPasswordCredential(ctx context.Context, userProfileID uuid.UUID, providerID uuid.UUID) (*model.PasswordCredential, error)
	GetIdentityByProfileAndProvider(ctx context.Context, userProfileID uuid.UUID, providerID uuid.UUID) (*model.UserIdentity, error)
	UpsertIdentity(ctx context.Context, identity model.UserIdentity) error
	RevokeSession(ctx context.Context, tenantID uuid.UUID, subject string, clientID string) error
	SaveInteractionSession(ctx context.Context, session model.InteractionSession) error
	GetAndConsumeInteractionSession(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.InteractionSession, error)
	RevokeToken(ctx context.Context, tokenID string, expiresAt time.Time) error
	IsTokenRevoked(ctx context.Context, tokenID string) (bool, error)
	PruneExpiredTokens(ctx context.Context) error
	GetClientsByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.ClientApplication, error)
}
