package port

import (
	"context"
	"time"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

// Storage handles high-frequency, low-latency hot-paths for core OAuth/OIDC transactions.
// This interface is optimized for targeted lookups and is heavily cached at runtime.
type Storage interface {
	GetApplicationByClientID(ctx context.Context, tenantUUID uuid.UUID, clientID string) (*model.Application, *model.ApplicationProfile, *model.ApplicationGroup, error)
	RegisterApplication(ctx context.Context, app model.Application) error
	GetProfileByName(ctx context.Context, tenantUUID uuid.UUID, name string) (*model.ApplicationProfile, error)
	GetGroupByName(ctx context.Context, tenantUUID uuid.UUID, name string) (*model.ApplicationGroup, error)

	SaveAuthSession(ctx context.Context, session model.AuthorizationCodeSession) error
	GetAndConsumeAuthSession(ctx context.Context, tenantID uuid.UUID, code string) (*model.AuthorizationCodeSession, error)
	ResolveTenantByDomain(ctx context.Context, domain string) (*model.Tenant, error)
	ResolveTenantByUUID(ctx context.Context, tenantID uuid.UUID) (*model.Tenant, error)
	GetIdentityProviderByType(ctx context.Context, tenantID uuid.UUID, idpType string) (*model.IdentityProvider, error)

	GetEnabledIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error)
	GetIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error)
	GetIdentityProvidersByUUIDs(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) ([]model.IdentityProvider, error)
	GetIdentityProvidersByTypeAndPartition(ctx context.Context, tenantID uuid.UUID, partitionID int64, idpType string) ([]model.IdentityProvider, error)
	GetIdentityProviderByAlias(ctx context.Context, tenantID uuid.UUID, alias string) (*model.IdentityProvider, error)
	GetIdentityProviderByUUID(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) (*model.IdentityProvider, error)

	// Refactored User Profile and Identity Storage Methods to enforce strict multi-tenant boundaries
	GetUserProfileByIdentifier(ctx context.Context, tenantID uuid.UUID, partitionID int64, providerID uuid.UUID, identifier string) (*model.UserProfile, error)
	GetUserProfileByID(ctx context.Context, tenantID uuid.UUID, partitionID int64, id uuid.UUID) (*model.UserProfile, error)
	GetUserProfileByIDAndPartitionAlias(ctx context.Context, tenantID uuid.UUID, partitionAlias string, id uuid.UUID) (*model.UserProfile, error)
	FindProfileByEmail(ctx context.Context, partitionID int64, email string) (*model.UserProfile, error)
	SaveUserProfile(ctx context.Context, tenantID uuid.UUID, partitionID int64, profile model.UserProfile) error

	// Identity Handling and Security Brute-Force lockout ports
	GetIdentityByProfileAndProvider(ctx context.Context, userProfileID uuid.UUID, providerID uuid.UUID) (*model.UserIdentity, error)

	GetUserIdentitiesByProfileID(ctx context.Context, tenantUUID uuid.UUID, partitionID int64, profileID uuid.UUID) ([]model.UserIdentity, error)
	GetUserIdentityByIdentifier(ctx context.Context, tenantID uuid.UUID, partitionID int64, providerID uuid.UUID, identifier string) (*model.UserIdentity, error)
	GetUserIdentityByProviderAndExternalID(ctx context.Context, tenantID uuid.UUID, partitionID int64, providerID uuid.UUID, externalID string) (*model.UserIdentity, error)
	UpsertUserIdentity(ctx context.Context, tenantID uuid.UUID, partitionID int64, identity model.UserIdentity) error
	UpdatePasswordLockoutState(ctx context.Context, tenantID uuid.UUID, partitionID int64, userProfileID uuid.UUID, providerID uuid.UUID, failedCount int, lastAttempt *time.Time, blockedUntil *time.Time) error
	ResetPasswordCounters(ctx context.Context, tenantID uuid.UUID, partitionID int64, userProfileID uuid.UUID, providerID uuid.UUID) error
	IncrementUserIdentityLoginTracker(ctx context.Context, tenantID uuid.UUID, partitionID int64, identityID uuid.UUID, loginTime time.Time) error

	// Password Credential Verification Gating Methods
	GetPasswordCredentialByProfileID(ctx context.Context, tenantID uuid.UUID, partitionID int64, userProfileID uuid.UUID, providerID uuid.UUID) (*model.PasswordCredential, error)
	SavePasswordCredential(ctx context.Context, credential model.PasswordCredential) error

	RevokeSession(ctx context.Context, tenantID uuid.UUID, subject string, clientID string) error
	SaveInteractionSession(ctx context.Context, session model.InteractionSession) error
	GetAndConsumeInteractionSession(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.InteractionSession, error)
	GetInteractionSession(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.InteractionSession, error)
	RevokeToken(ctx context.Context, tokenID string, expiresAt time.Time) error
	IsTokenRevoked(ctx context.Context, tokenID string) (bool, error)

	// RecordClientSessionLink stores an idempotent entry linking an active browser single-sign-on
	// session directly to a client application footprint inside the database backend.
	RecordClientSessionLink(ctx context.Context, tenantID uuid.UUID, sessionID string, clientID string, associatedAt time.Time) error

	// GetApplicationsLogoutContextBySession queries the relational storage using an active session ID
	// to extract only the target application nodes and logout destinations utilized during that specific browser lifecycle.
	GetApplicationsLogoutContextBySession(ctx context.Context, tenantUUID uuid.UUID, sessionID string) ([]model.Application, error)

	// PruneExpiredTokens clears out stale cache partitions across all operational session tables,
	// now including automated cleanup of orphaned client sessions records on 15-minute ticks.
	PruneExpiredTokens(ctx context.Context) error

	// SaveOutboundHandshake persists the transient protocol tracking parameters (PKCE/State)
	// for any ongoing inbound or outbound OIDC federation handshake transaction.
	SaveOutboundHandshake(ctx context.Context, session model.OutboundHandshakeSession) error
	// GetAndConsumeOutboundHandshake retrieves a tracking handshake record by its unique
	// state token ID and instantly deletes it from persistence to prevent token replay vectors.
	GetAndConsumeOutboundHandshake(ctx context.Context, tenantID uuid.UUID, incomingState string) (*model.OutboundHandshakeSession, error)

	SavePAR(ctx context.Context, req model.PushedAuthorizationRequest) error
	GetAndConsumePAR(ctx context.Context, tenantID uuid.UUID, requestURI string) (*model.PushedAuthorizationRequest, error)
	IsDPoPProofUsed(ctx context.Context, jti string) (bool, error)
	SaveDPoPProof(ctx context.Context, jti string, expiresAt time.Time) error

	SaveRefreshToken(ctx context.Context, token model.RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenID string) (*model.RefreshToken, error)
	MarkRefreshTokenUsed(ctx context.Context, tokenID string) error
	RevokeRefreshTokenFamily(ctx context.Context, tokenFamilyID string) error
	PurgeTenantSessionsAndTokens(ctx context.Context, tenantID uuid.UUID) error

	GetPartitions(ctx context.Context, tenantID uuid.UUID) ([]model.Partition, error)
	GetPartitionByID(ctx context.Context, tenantID uuid.UUID, partitionID int64) (*model.Partition, error)
	GetPartitionByAlias(ctx context.Context, tenantID uuid.UUID, alias string) (*model.Partition, error)

	// SaveFederatedSession persists or mutates an upstream cryptographic session state securely [5.7]
	SaveFederatedSession(ctx context.Context, session model.FederatedSession) error
	// GetFederatedSessionByLocalSessionID retrieves upstream tokens using our native tracking session reference [7.3]
	GetFederatedSessionByLocalSessionID(ctx context.Context, tenantUUID uuid.UUID, partitionID int64, sessionID string) (*model.FederatedSession, error)
	// FindFederatedSessionByUpstreamSubject locates a mapping record for incoming upstream Back-Channel SLO webhooks [7.2]
	FindFederatedSessionByUpstreamSubject(ctx context.Context, tenantUUID uuid.UUID, idpID uuid.UUID, upstreamSub string) (*model.FederatedSession, error)
	// DeleteFederatedSession explicitly purges a single federated mapping layer during single-logouts [7.1]
	DeleteFederatedSession(ctx context.Context, tenantUUID uuid.UUID, partitionID int64, sessionID string) error
	// PruneExpiredFederatedSessions sweeps old, obsolete upstream keys matching background cleaning intervals [6.3]
	PruneExpiredFederatedSessions(ctx context.Context, now time.Time) (int64, error)
}

// AdminStorage handles administrative data-heavy queries and mutations driven by the dashboard panel.
type AdminStorage interface {
	GetDynamicApplicationsSummary(ctx context.Context, tenantUUID uuid.UUID) ([]model.ApplicationSummary, error)
	GetStaticApplicationsSummary(ctx context.Context, tenantUUID uuid.UUID) ([]model.ApplicationSummary, error)

	CreateApplication(ctx context.Context, tenantUUID uuid.UUID, app model.Application) error
	UpdateApplication(ctx context.Context, tenantUUID uuid.UUID, clientID string, app model.Application) error
	DeleteApplication(ctx context.Context, tenantID uuid.UUID, clientID string) error

	CreateApplicationProfile(ctx context.Context, tenantUUID uuid.UUID, profile model.ApplicationProfile) error
	UpdateApplicationProfile(ctx context.Context, tenantUUID uuid.UUID, profile model.ApplicationProfile) error

	CreateApplicationGroup(ctx context.Context, tenantUUID uuid.UUID, group model.ApplicationGroup) error
	UpdateApplicationGroup(ctx context.Context, tenantUUID uuid.UUID, group model.ApplicationGroup) error

	CreateTenant(ctx context.Context, tenant model.Tenant) error
	GetAllTenants(ctx context.Context) ([]model.Tenant, error)

	CreateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) error
	DeleteIdentityProvider(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) error

	GetUserProfilesByTenant(ctx context.Context, tenantID uuid.UUID, partitionID int64) ([]model.UserProfile, error)
	DeleteUserProfile(ctx context.Context, tenantID uuid.UUID, partitionID int64, userID uuid.UUID) error
	UpdateUserProfile(ctx context.Context, tenantID uuid.UUID, profile model.UserProfile) error
	GetUserIdentities(ctx context.Context, userProfileID uuid.UUID) ([]model.UserIdentity, error)
	DecoupleIdentity(ctx context.Context, userProfileID uuid.UUID, identityProviderID uuid.UUID) error

	CreatePartition(ctx context.Context, tenantID uuid.UUID, name, aliasName string) (*model.Partition, error)
}
