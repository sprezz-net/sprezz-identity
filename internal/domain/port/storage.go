package port

import (
	"context"
	"errors"
	"time"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

var (
	ErrTenantNotFound             = errors.New("tenant not found")
	ErrClientNotFound             = errors.New("client not found")
	ErrSessionNotFound            = errors.New("session not found")
	ErrUserProfileNotFound        = errors.New("user profile not found")
	ErrPasswordCredentialNotFound = errors.New("password credential not found")
	ErrIdentityNotFound           = errors.New("identity not found")
	ErrInteractionSessionNotFound = errors.New("interaction session not found")
)

type Storage interface {
	SaveClient(ctx context.Context, client model.ClientApplication) error
	GetClient(ctx context.Context, tenantID uuid.UUID, clientID string) (*model.ClientApplication, error)
	SaveAuthSession(ctx context.Context, session model.AuthorizationCodeSession) error
	GetAndConsumeAuthSession(ctx context.Context, tenantID uuid.UUID, code string) (*model.AuthorizationCodeSession, error)
	ResolveTenantByDomain(ctx context.Context, domain string) (*model.Tenant, error)
	ResolveTenantByID(ctx context.Context, tenantID uuid.UUID) (*model.Tenant, error)
	CreateTenant(ctx context.Context, tenant model.Tenant) error
	GetAllTenants(ctx context.Context) ([]model.Tenant, error)
	CreateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) error
	GetEnabledIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error)
	GetUserProfileByIdentifier(ctx context.Context, tenantID uuid.UUID, providerID uuid.UUID, identifier string) (*model.UserProfile, error)
	GetUserProfileByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.UserProfile, error)
	GetPasswordCredential(ctx context.Context, userProfileID uuid.UUID, providerID uuid.UUID) (*model.PasswordCredential, error)
	GetIdentityByProfileAndProvider(ctx context.Context, userProfileID uuid.UUID, providerID uuid.UUID) (*model.UserIdentity, error)
	SaveUserProfile(ctx context.Context, tenantID uuid.UUID, profile model.UserProfile) error
	SavePasswordCredential(ctx context.Context, credential model.PasswordCredential) error
	UpsertIdentity(ctx context.Context, identity model.UserIdentity) error
	GetIdentityProviderByType(ctx context.Context, tenantID uuid.UUID, idpType string) (*model.IdentityProvider, error)
	RevokeSession(ctx context.Context, tenantID uuid.UUID, subject string, clientID string) error
	SaveInteractionSession(ctx context.Context, session model.InteractionSession) error
	GetAndConsumeInteractionSession(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.InteractionSession, error)
	RevokeToken(ctx context.Context, tokenID string, expiresAt time.Time) error
	IsTokenRevoked(ctx context.Context, tokenID string) (bool, error)
	PruneExpiredTokens(ctx context.Context) error
	GetClientsByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.ClientApplication, error)
	DeleteClient(ctx context.Context, tenantID uuid.UUID, clientID string) error
	GetIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error)
	DeleteIdentityProvider(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) error
	GetUserProfilesByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.UserProfile, error)
	DeleteUserProfile(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) error
	UpdateUserProfile(ctx context.Context, tenantID uuid.UUID, profile model.UserProfile) error
	GetUserIdentities(ctx context.Context, userProfileID uuid.UUID) ([]model.UserIdentity, error)
	DecoupleIdentity(ctx context.Context, userProfileID uuid.UUID, identityProviderID uuid.UUID) error

	SavePAR(ctx context.Context, req model.PushedAuthorizationRequest) error
	GetAndConsumePAR(ctx context.Context, tenantID uuid.UUID, requestURI string) (*model.PushedAuthorizationRequest, error)
	IsDPoPProofUsed(ctx context.Context, jti string) (bool, error)
	SaveDPoPProof(ctx context.Context, jti string, expiresAt time.Time) error

	SaveRefreshToken(ctx context.Context, token model.RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenID string) (*model.RefreshToken, error)
	MarkRefreshTokenUsed(ctx context.Context, tokenID string) error
	RevokeRefreshTokenFamily(ctx context.Context, tokenFamilyID string) error
	PurgeTenantSessionsAndTokens(ctx context.Context, tenantID uuid.UUID) error
}

// Errors returned by the StoragePort.
var (
	ErrIdentityProviderNotFound = errors.New("identity provider not found")
	ErrUserProfileAlreadyExists = errors.New("user profile with this identifier already exists")
	ErrEmailAlreadyExists       = errors.New("email address already in use")
	ErrUsernameAlreadyExists    = errors.New("username already in use")
)
