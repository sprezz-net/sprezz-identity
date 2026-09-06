package port

import (
	"context"
	"time"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

// CreateApplicationCommand defines parameter inputs for creating an application standalone entity.
type CreateApplicationCommand struct {
	TenantID        uuid.UUID
	ClientID        string
	ApplicationName string
	ProfileID       uuid.UUID
	GroupID         uuid.UUID
}

// UpdateApplicationCommand defines parameter inputs for updating an application standalone entity.
type UpdateApplicationCommand struct {
	TenantID        uuid.UUID
	ClientID        string
	ApplicationName string
	ProfileID       uuid.UUID
	GroupID         uuid.UUID
	IsEnabled       bool
}

// CreateProfileCommand defines parameter inputs for creating a security policy profile standalone.
type CreateProfileCommand struct {
	TenantID                uuid.UUID
	ProfileName             string
	TokenEndpointAuthMethod model.TokenEndpointAuthMethod
	GrantTypes              []model.GrantType
	ResponseTypes           []model.ResponseType
	AccessTokenLifetime     time.Duration
	RefreshTokenLifetime    time.Duration
	IDTokenLifetime         time.Duration
	EnforceRTR              bool
	SigningAlgorithm        model.SignatureAlgorithm
}

// UpdateProfileCommand defines parameter inputs for updating an existing security policy profile.
type UpdateProfileCommand struct {
	TenantID                uuid.UUID
	ID                      uuid.UUID
	ProfileName             string
	TokenEndpointAuthMethod model.TokenEndpointAuthMethod
	GrantTypes              []model.GrantType
	ResponseTypes           []model.ResponseType
	AccessTokenLifetime     time.Duration
	RefreshTokenLifetime    time.Duration
	IDTokenLifetime         time.Duration
	EnforceRTR              bool
	SigningAlgorithm        model.SignatureAlgorithm
}

// CreateGroupCommand defines parameter inputs for creating a standalone routing / authorization group.
type CreateGroupCommand struct {
	TenantID               uuid.UUID
	GroupName              string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	FrontChannelLogoutURI  string
	BackChannelLogoutURI   string
	AllowedScopes          []string
	DefaultScopes          []string
	AllowedAudiences       []string
	AllowedIDPIDs          []uuid.UUID
	DefaultIDPID           *uuid.UUID
}

// UpdateGroupCommand defines parameter inputs for updating an existing routing / authorization group.
type UpdateGroupCommand struct {
	TenantID               uuid.UUID
	ID                     uuid.UUID
	GroupName              string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	FrontChannelLogoutURI  string
	BackChannelLogoutURI   string
	AllowedScopes          []string
	DefaultScopes          []string
	AllowedAudiences       []string
	AllowedIDPIDs          []uuid.UUID
	DefaultIDPID           *uuid.UUID
}

// AdminApplicationUseCase defines the driving ports for admin applications, profiles, and groups operations.
type AdminApplicationUseCase interface {
	GetApplicationDashboard(ctx context.Context, tenantID uuid.UUID) ([]model.ApplicationSummary, []model.ApplicationProfile, []model.ApplicationGroup, error)
	GetApplicationDetails(ctx context.Context, tenantID uuid.UUID, clientID string) (*model.ApplicationDetailsProps, error)

	// Standalone Application CRUD
	CreateApplication(ctx context.Context, cmd CreateApplicationCommand) (*model.Application, string, error)
	UpdateApplication(ctx context.Context, cmd UpdateApplicationCommand) error
	DeleteApplication(ctx context.Context, tenantID uuid.UUID, clientID string) error
	ToggleApplicationStatus(ctx context.Context, tenantID uuid.UUID, clientID string) (*model.Application, error)
	ResetApplicationSecret(ctx context.Context, tenantID uuid.UUID, clientID string) (string, error)

	// Standalone Profile CRUD
	GetProfiles(ctx context.Context, tenantID uuid.UUID) ([]model.ApplicationProfile, error)
	GetProfile(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.ApplicationProfile, error)
	CreateProfile(ctx context.Context, cmd CreateProfileCommand) error
	UpdateProfile(ctx context.Context, cmd UpdateProfileCommand) error

	// Standalone Group CRUD
	GetGroups(ctx context.Context, tenantID uuid.UUID) ([]model.ApplicationGroup, error)
	GetGroup(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.ApplicationGroup, error)
	CreateGroup(ctx context.Context, cmd CreateGroupCommand) error
	UpdateGroup(ctx context.Context, cmd UpdateGroupCommand) error
}

// IdentityProviderUseCase defines the driving ports for identity provider operations.
type IdentityProviderUseCase interface {
	GetIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error)
	DiscoverOIDC(ctx context.Context, endpoint string) (string, error)
	CreateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) (*model.IdentityProvider, error)
	UpdateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) (*model.IdentityProvider, error)
	DeleteIdentityProvider(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) error
}
