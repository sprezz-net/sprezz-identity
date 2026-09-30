package port

import (
	"context"
	"time"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

// CommitCallback is executed by the HTTP transport adapter.
// Returning an error forces the domain service layer to trigger a ROLLBACK.
type CommitCallback func(plaintextSecret string) error

// CreateApplicationCommand defines parameter inputs for creating an application standalone entity.
type CreateApplicationCommand struct {
	TenantID        uuid.UUID
	ClientID        string
	ApplicationName string
	ProfileID       uuid.UUID
	GroupID         uuid.UUID
	OnDelivery      CommitCallback // Handshake callback: runs AFTER write but BEFORE commit
}

// UpdateApplicationCommand defines parameter inputs for updating an application standalone entity.
type UpdateApplicationCommand struct {
	TenantID        uuid.UUID
	ClientID        string
	ApplicationName string
	ProfileID       uuid.UUID
	GroupID         uuid.UUID
	IsEnabled       *bool // nil preserves the current enabled state
}

// ResetApplicationSecretCommand encapsulates parameters for transaction-locked credential rotation.
type ResetApplicationSecretCommand struct {
	TenantID   uuid.UUID
	ClientID   string
	OnDelivery CommitCallback // Callback channel: holds DB lock open until HTTP write acknowledges success
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
	IsEnabled               *bool // nil preserves the stored enabled state
}

// CreateGroupCommand defines parameter inputs for creating a standalone routing / authorization group.
type CreateGroupCommand struct {
	TenantID               uuid.UUID
	GroupName              string
	DefaultRedirectURI     string // must be one of RedirectURIs; empty means the first entry is used
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
	DefaultRedirectURI     string // must be one of RedirectURIs; empty means the first entry is used
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	FrontChannelLogoutURI  string
	BackChannelLogoutURI   string
	AllowedScopes          []string
	DefaultScopes          []string
	AllowedAudiences       []string
	AllowedIDPIDs          []uuid.UUID
	DefaultIDPID           *uuid.UUID
	IsEnabled              *bool // nil preserves the stored enabled state
}

// GroupSection names one independently saved part of the group page.
type GroupSection string

const (
	GroupSectionGeneral   GroupSection = "general"
	GroupSectionRedirects GroupSection = "redirects"
	GroupSectionLogout    GroupSection = "logout"
	GroupSectionScopes    GroupSection = "scopes"
	GroupSectionSignIn    GroupSection = "signin"
)

// PatchGroupCommand saves a single section of a group. Only the fields that belong to Section are read; every
// other part of the group keeps its stored value, because the service re-reads the group at save time.
type PatchGroupCommand struct {
	TenantID uuid.UUID
	ID       uuid.UUID
	Section  GroupSection

	// General
	GroupName string
	IsEnabled bool

	// Redirects
	DefaultRedirectURI string
	RedirectURIs       []string

	// Logout
	PostLogoutRedirectURIs []string
	FrontChannelLogoutURI  string
	BackChannelLogoutURI   string

	// Scopes
	AllowedScopes    []string
	DefaultScopes    []string
	AllowedAudiences []string

	// SignIn
	AllowedIDPIDs []uuid.UUID
	DefaultIDPID  *uuid.UUID
}

// ProfileSection names one independently saved part of the profile page.
type ProfileSection string

const (
	ProfileSectionGeneral        ProfileSection = "general"
	ProfileSectionAuthentication ProfileSection = "authentication"
	ProfileSectionLifetimes      ProfileSection = "lifetimes"
)

// PatchProfileCommand saves a single section of a security profile, with the same semantics as PatchGroupCommand.
type PatchProfileCommand struct {
	TenantID uuid.UUID
	ID       uuid.UUID
	Section  ProfileSection

	// General
	ProfileName string
	IsEnabled   bool

	// Authentication
	TokenEndpointAuthMethod model.TokenEndpointAuthMethod
	SigningAlgorithm        model.SignatureAlgorithm
	GrantTypes              []model.GrantType
	EnforceRTR              bool

	// Lifetimes
	AccessTokenLifetime  time.Duration
	RefreshTokenLifetime time.Duration
	IDTokenLifetime      time.Duration
}

// AdminApplicationUseCase defines the driving ports for admin applications, profiles, and groups operations.
type AdminApplicationUseCase interface {
	GetApplicationDashboard(ctx context.Context, tenantID uuid.UUID) ([]model.ApplicationSummary, []model.ApplicationProfile, []model.ApplicationGroup, error)
	GetApplicationDetails(ctx context.Context, tenantID uuid.UUID, clientID string) (*model.ApplicationDetailsProps, error)
	// GetApplication is the detail-page lookup; it returns the application together with its profile and group.
	GetApplication(ctx context.Context, tenantID uuid.UUID, clientID string) (*model.ApplicationDetailsProps, error)

	// Standalone Application CRUD
	CreateApplication(ctx context.Context, cmd CreateApplicationCommand) (*model.Application, error)
	UpdateApplication(ctx context.Context, cmd UpdateApplicationCommand) error
	DeleteApplication(ctx context.Context, tenantID uuid.UUID, clientID string) error
	ToggleApplicationStatus(ctx context.Context, tenantID uuid.UUID, clientID string) (*model.Application, error)
	ResetApplicationSecret(ctx context.Context, cmd ResetApplicationSecretCommand) error

	// Standalone Profile CRUD
	GetProfiles(ctx context.Context, tenantID uuid.UUID) ([]model.ApplicationProfile, error)
	GetProfile(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.ApplicationProfile, error)
	CreateProfile(ctx context.Context, cmd CreateProfileCommand) (*model.ApplicationProfile, error)
	UpdateProfile(ctx context.Context, cmd UpdateProfileCommand) error

	// Standalone Group CRUD
	GetGroups(ctx context.Context, tenantID uuid.UUID) ([]model.ApplicationGroup, error)
	GetGroup(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.ApplicationGroup, error)
	CreateGroup(ctx context.Context, cmd CreateGroupCommand) (*model.ApplicationGroup, error)
	UpdateGroup(ctx context.Context, cmd UpdateGroupCommand) error

	// PatchGroup and PatchProfile save one page section at a time; see PatchGroupCommand.
	PatchGroup(ctx context.Context, cmd PatchGroupCommand) error
	PatchProfile(ctx context.Context, cmd PatchProfileCommand) error

	// Removal is refused with ErrSystemManaged for bootstrap objects and ErrInUse while applications still use them.
	DeleteGroup(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
	DeleteProfile(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error

	// Usage listings feed the "used by" sections of the group and profile pages.
	ListApplicationsByGroup(ctx context.Context, tenantID uuid.UUID, groupID uuid.UUID) ([]model.ApplicationSummary, error)
	ListApplicationsByProfile(ctx context.Context, tenantID uuid.UUID, profileID uuid.UUID) ([]model.ApplicationSummary, error)
}

// IdentityProviderSection names one independently saved part of the identity provider page.
type IdentityProviderSection string

const (
	IDPSectionGeneral     IdentityProviderSection = "general"
	IDPSectionConnection  IdentityProviderSection = "connection"
	IDPSectionCredentials IdentityProviderSection = "credentials"
	IDPSectionBehavior    IdentityProviderSection = "behavior"
	IDPSectionAssurance   IdentityProviderSection = "assurance"
	IDPSectionLocalPolicy IdentityProviderSection = "local-policy"
)

// PatchIdentityProviderCommand saves one section of a provider. Only the fields that belong to Section are read.
// Every other part of the stored provider, including configuration the form never shows, keeps its value.
type PatchIdentityProviderCommand struct {
	TenantID uuid.UUID
	ID       uuid.UUID
	Section  IdentityProviderSection

	// General
	Name    string
	Enabled bool

	// Connection (OIDC)
	DiscoveryEndpoint    string
	Issuer               string
	AuthenticationMethod string
	PkceEnabled          bool
	ParEnabled           bool
	SLOEnabled           bool

	// Credentials (OIDC). An empty ClientSecret keeps the stored secret; ClearSecret removes it.
	ClientID     string
	ClientSecret string
	ClearSecret  bool

	// Behavior (OIDC)
	Scopes              []string
	UserIdentifierClaim string
	DomainAliases       []string
	AutoProvisionUser   bool
	AutoVerifyEmail     bool

	// Assurance
	AAL        int
	IAL        int
	ACRValues  []string
	AcrToTuple map[string]model.AcrTuple
	AmrToAAL   map[string]int

	// LocalPolicy
	UsernameField              string
	MaxFailedVerificationCount int
	PasswordBlockedTime        int
	AllowDecoupling            bool
}

// IdentityProviderDeletion describes what removing a provider would do, for the delete dialog.
type IdentityProviderDeletion struct {
	LinkedUsers int
	GroupNames  []string
}

// IdentityProviderUseCase defines the driving ports for identity provider operations.
type IdentityProviderUseCase interface {
	GetIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error)
	GetPartitionsWithProviders(ctx context.Context, tenantID uuid.UUID) ([]model.PartitionWithProviders, error)
	DiscoverOIDC(ctx context.Context, endpoint string) (*model.OIDCDiscoveryMetadata, error)
	CreateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) (*model.IdentityProvider, error)
	UpdateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) (*model.IdentityProvider, error)
	DeleteIdentityProvider(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) error

	// GetIdentityProvider returns one provider of the tenant.
	GetIdentityProvider(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) (*model.IdentityProvider, error)
	// PatchIdentityProvider saves one page section; see PatchIdentityProviderCommand.
	PatchIdentityProvider(ctx context.Context, cmd PatchIdentityProviderCommand) error
	// GetIdentityProviderUsage feeds the list and detail pages with linked users, groups and last sign-in.
	GetIdentityProviderUsage(ctx context.Context, tenantID uuid.UUID) (map[uuid.UUID]model.IdentityProviderUsage, error)
}
