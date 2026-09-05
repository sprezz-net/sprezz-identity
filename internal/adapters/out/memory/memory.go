package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

type Storage struct {
	mu      sync.RWMutex
	tenants map[string]*model.Tenant

	// Modernized 3-Table Relational Memory Stores
	applications map[uuid.UUID]*model.Application
	profiles     map[uuid.UUID]*model.ApplicationProfile
	groups       map[uuid.UUID]*model.ApplicationGroup

	// Semantic name lookup index maps to satisfy Name-based queries quickly
	profileNames map[string]uuid.UUID // maps "tenantStr|profileName" -> profileID
	groupNames   map[string]uuid.UUID // maps "tenantStr|groupName" -> groupID

	sessions            map[string]model.AuthorizationCodeSession
	providers           map[string]map[uuid.UUID]model.IdentityProvider
	userProfiles        map[string]*model.UserProfile
	passwordCredentials map[string]*model.PasswordCredential
	identities          map[string]*model.UserIdentity
	interactionSessions map[uuid.UUID]model.InteractionSession
	revokedTokens       map[string]time.Time
	parSessions         map[string]model.PushedAuthorizationRequest
	dpopProofs          map[string]time.Time
	refreshTokens       map[string]model.RefreshToken
	partitions          map[string]map[int64]model.Partition
	deks                map[uuid.UUID][]byte
	nonces              map[uuid.UUID][]byte
	signingKeys         map[uuid.UUID][]model.SigningKey
	outboundHandshakes  map[string]model.OutboundHandshakeSession
	appEnv              string
}

func NewStorage(appEnv string) *Storage {
	return &Storage{
		tenants:             make(map[string]*model.Tenant),
		applications:        make(map[uuid.UUID]*model.Application),
		profiles:            make(map[uuid.UUID]*model.ApplicationProfile),
		groups:              make(map[uuid.UUID]*model.ApplicationGroup),
		profileNames:        make(map[string]uuid.UUID),
		groupNames:          make(map[string]uuid.UUID),
		sessions:            make(map[string]model.AuthorizationCodeSession),
		providers:           make(map[string]map[uuid.UUID]model.IdentityProvider),
		userProfiles:        make(map[string]*model.UserProfile),
		passwordCredentials: make(map[string]*model.PasswordCredential),
		identities:          make(map[string]*model.UserIdentity),
		interactionSessions: make(map[uuid.UUID]model.InteractionSession),
		revokedTokens:       make(map[string]time.Time),
		parSessions:         make(map[string]model.PushedAuthorizationRequest),
		dpopProofs:          make(map[string]time.Time),
		refreshTokens:       make(map[string]model.RefreshToken),
		partitions:          make(map[string]map[int64]model.Partition),
		deks:                make(map[uuid.UUID][]byte),
		nonces:              make(map[uuid.UUID][]byte),
		signingKeys:         make(map[uuid.UUID][]model.SigningKey),
		outboundHandshakes:  make(map[string]model.OutboundHandshakeSession),
		appEnv:              appEnv,
	}
}

// Compile-time type assertions to ensure strict compliance with your new multi-port interfaces.
var _ port.Storage = (*Storage)(nil)
var _ port.CryptoStorage = (*Storage)(nil)
var _ port.AdminStorage = (*Storage)(nil)

// =========================================================================
// PORT.STORAGE INTERFACE IMPLEMENTATION (RUNTIME HOT-PATHS)
// =========================================================================

func (s *Storage) ResolveTenantByDomain(ctx context.Context, domain string) (*model.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenant, ok := s.tenants[domain]
	if !ok {
		return nil, port.ErrTenantNotFound
	}
	clone := *tenant
	if clone.Config.PredefinedScopes == nil {
		clone.Config.PredefinedScopes = []string{"openid", "profile", "email", "offline_access"}
	}
	if clone.Config.PredefinedAudiences == nil {
		clone.Config.PredefinedAudiences = []string{}
	}
	if clone.Config.RedirectWhitelist == nil {
		clone.Config.RedirectWhitelist = []string{}
	}
	if clone.Scheme == "" {
		clone.Scheme = model.SchemeHttps
		if s.appEnv == "local" {
			clone.Scheme = model.SchemeHttp
		}
	}
	return &clone, nil
}

func (s *Storage) ResolveTenantByUUID(ctx context.Context, tenantID uuid.UUID) (*model.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, tenant := range s.tenants {
		if tenant.ID == tenantID {
			clone := *tenant
			if clone.Config.PredefinedScopes == nil {
				clone.Config.PredefinedScopes = []string{"openid", "profile", "email", "offline_access"}
			}
			if clone.Config.PredefinedAudiences == nil {
				clone.Config.PredefinedAudiences = []string{}
			}
			if clone.Config.RedirectWhitelist == nil {
				clone.Config.RedirectWhitelist = []string{}
			}
			if clone.Scheme == "" {
				clone.Scheme = model.SchemeHttps
				if s.appEnv == "local" {
					clone.Scheme = model.SchemeHttp
				}
			}
			return &clone, nil
		}
	}
	return nil, port.ErrTenantNotFound
}

func (s *Storage) RegisterApplication(ctx context.Context, app model.Application) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Enforce fail-secure UNIQUE constraint validation on client_id boundaries
	for _, existing := range s.applications {
		if existing.ClientID == app.ClientID && existing.TenantID == app.TenantID {
			return fmt.Errorf("repository: client_id already exists")
		}
	}

	clone := app
	s.applications[app.ID] = &clone
	return nil
}

func (s *Storage) GetApplicationByClientID(ctx context.Context, tenantUUID uuid.UUID, clientID string) (*model.Application, *model.ApplicationProfile, *model.ApplicationGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var targetApp *model.Application
	for _, app := range s.applications {
		if app.ClientID == clientID && app.TenantID == tenantUUID {
			targetApp = app
			break
		}
	}

	if targetApp == nil {
		return nil, nil, nil, port.ErrApplicationNotFound
	}

	profile, ok := s.profiles[targetApp.ProfileID]
	if !ok {
		return nil, nil, nil, port.ErrProfileNotFound
	}

	group, ok := s.groups[targetApp.GroupID]
	if !ok {
		return nil, nil, nil, port.ErrGroupNotFound
	}

	appClone := *targetApp
	profileClone := *profile
	groupClone := *group

	return &appClone, &profileClone, &groupClone, nil
}

func (s *Storage) GetProfileByName(ctx context.Context, tenantUUID uuid.UUID, name string) (*model.ApplicationProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s|%s", tenantUUID.String(), name)
	id, ok := s.profileNames[key]
	if !ok {
		return nil, port.ErrProfileNotFound
	}

	profile, ok := s.profiles[id]
	if !ok {
		return nil, port.ErrProfileNotFound
	}

	clone := *profile
	return &clone, nil
}

func (s *Storage) GetGroupByName(ctx context.Context, tenantUUID uuid.UUID, name string) (*model.ApplicationGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s|%s", tenantUUID.String(), name)
	id, ok := s.groupNames[key]
	if !ok {
		return nil, port.ErrGroupNotFound
	}

	group, ok := s.groups[id]
	if !ok {
		return nil, port.ErrGroupNotFound
	}

	clone := *group
	return &clone, nil
}

// =========================================================================
// PORT.STORAGE INTERFACE IMPLEMENTATION (SESSION, IDENTITY & CORE AUTH HANDLERS)
// =========================================================================

func (s *Storage) SaveAuthSession(ctx context.Context, session model.AuthorizationCodeSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Preserves complete tracking metrics including IdentityProvider validations
	s.sessions[session.Code] = session
	return nil
}

func (s *Storage) GetAndConsumeAuthSession(ctx context.Context, tenantID uuid.UUID, code string) (*model.AuthorizationCodeSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[code]
	if !ok {
		return nil, fmt.Errorf("session %s: %w", code, port.ErrSessionNotFound)
	}
	if session.TenantID != tenantID {
		return nil, fmt.Errorf("session tenant mismatch: %w", port.ErrSessionNotFound)
	}
	delete(s.sessions, code)
	return &session, nil
}

func (s *Storage) SaveInteractionSession(ctx context.Context, session model.InteractionSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interactionSessions[session.ID] = session
	return nil
}

func (s *Storage) GetAndConsumeInteractionSession(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.InteractionSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.interactionSessions[id]
	if !ok {
		return nil, port.ErrInteractionSessionNotFound
	}
	if session.TenantID != tenantID {
		return nil, port.ErrInteractionSessionNotFound
	}
	delete(s.interactionSessions, id)
	return &session, nil
}

func (s *Storage) GetInteractionSession(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.InteractionSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.interactionSessions[id]
	if !ok {
		return nil, port.ErrInteractionSessionNotFound
	}
	if session.TenantID != tenantID {
		return nil, port.ErrInteractionSessionNotFound
	}
	return &session, nil
}

func (s *Storage) RevokeToken(ctx context.Context, tokenID string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokedTokens[tokenID] = expiresAt
	return nil
}

func (s *Storage) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	exp, ok := s.revokedTokens[tokenID]
	if !ok {
		return false, nil
	}
	if time.Now().After(exp) {
		return false, nil
	}
	return true, nil
}

func (s *Storage) GetApplicationsLogoutContextByTenant(ctx context.Context, tenantUUID uuid.UUID) ([]model.Application, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []model.Application
	for _, app := range s.applications {
		if app.TenantID == tenantUUID && app.IsEnabled {
			group, ok := s.groups[app.GroupID]
			if !ok || !group.IsEnabled {
				continue // Skip if group whitelist layout is deactivated
			}
			profile, ok := s.profiles[app.ProfileID]
			if !ok || !profile.IsEnabled {
				continue // Skip if master profile blueprint is deactivated
			}

			result = append(result, model.Application{
				ID:                    app.ID,
				TenantID:              app.TenantID,
				ClientID:              app.ClientID,
				FrontChannelLogoutURI: group.FrontChannelLogoutURI,
				BackChannelLogoutURI:  group.BackChannelLogoutURI,
				SigningAlgorithm:      profile.SigningAlgorithm,
			})
		}
	}
	return result, nil
}

func (s *Storage) SavePAR(ctx context.Context, req model.PushedAuthorizationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.parSessions[req.RequestURI] = req
	return nil
}

func (s *Storage) GetAndConsumePAR(ctx context.Context, tenantID uuid.UUID, requestURI string) (*model.PushedAuthorizationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.parSessions[requestURI]
	if !ok {
		return nil, fmt.Errorf("pushed authorization request not found")
	}
	if req.TenantID != tenantID {
		return nil, fmt.Errorf("pushed authorization request tenant mismatch")
	}
	delete(s.parSessions, requestURI)
	return &req, nil
}

func (s *Storage) IsDPoPProofUsed(ctx context.Context, jti string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	exp, ok := s.dpopProofs[jti]
	if !ok {
		return false, nil
	}
	if time.Now().After(exp) {
		return false, nil
	}
	return true, nil
}

func (s *Storage) SaveDPoPProof(ctx context.Context, jti string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dpopProofs[jti] = expiresAt
	return nil
}

// =========================================================================
// PORT.CRYPTOSTORAGE INTERFACE IMPLEMENTATION (KEY WRAPPERS)
// =========================================================================

func (s *Storage) GetTenantDEK(ctx context.Context, tenantUUID uuid.UUID) ([]byte, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.deks[tenantUUID], s.nonces[tenantUUID], nil
}

func (s *Storage) InsertTenantDEK(ctx context.Context, tenantUUID uuid.UUID, encryptedDEK, nonce []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deks[tenantUUID] = encryptedDEK
	s.nonces[tenantUUID] = nonce
	return nil
}

func (s *Storage) GetActiveSigningKeys(ctx context.Context, tenantUUID uuid.UUID) ([]model.SigningKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.signingKeys[tenantUUID], nil
}

func (s *Storage) GetActiveVerificationKeys(ctx context.Context, tenantUUID uuid.UUID) ([]model.SigningKey, error) {
	return s.GetActiveSigningKeys(ctx, tenantUUID)
}

func (s *Storage) InsertSigningKey(ctx context.Context, tenantUUID uuid.UUID, key model.SigningKey, encryptedPrivateKey, nonce []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key.Kid == "" {
		key.Kid = uuid.New().String()
	}
	key.RawEncryptedPrivateKey = encryptedPrivateKey
	key.CryptoNonce = nonce
	s.signingKeys[tenantUUID] = append(s.signingKeys[tenantUUID], key)
	return key.Kid, nil
}

func (s *Storage) RotateSigningKeys(ctx context.Context, tenantUUID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signingKeys[tenantUUID] = nil
	return nil
}

// =========================================================================
// NEW TRANSACTIONAL PRUNING PARTITIONS (SECTION 6.3 PORT COMPLIANCE)
// =========================================================================

func (s *Storage) PruneExpiredTokens(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, exp := range s.revokedTokens {
		if now.After(exp) {
			delete(s.revokedTokens, k)
		}
	}
	for k, p := range s.parSessions {
		if now.After(p.ExpiresAt) {
			delete(s.parSessions, k)
		}
	}
	for k, exp := range s.dpopProofs {
		if now.After(exp) {
			delete(s.dpopProofs, k)
		}
	}
	return nil
}

func (s *Storage) PruneExpiredRevokedTokens(ctx context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tokenID, exp := range s.revokedTokens {
		if now.After(exp) {
			delete(s.revokedTokens, tokenID)
		}
	}
	return nil
}

func (s *Storage) PruneExpiredAuthSessions(ctx context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for code, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, code)
		}
	}
	return nil
}

func (s *Storage) PruneExpiredInteractionSessions(ctx context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range s.interactionSessions {
		if now.After(session.ExpiresAt) {
			delete(s.interactionSessions, id)
		}
	}
	return nil
}

// =========================================================================
// PORT.ADMINSTORAGE INTERFACE IMPLEMENTATION (DASHBOARD PATHWAYS)
// =========================================================================

func (s *Storage) GetDynamicApplicationsSummary(ctx context.Context, tenantUUID uuid.UUID) ([]model.ApplicationSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []model.ApplicationSummary
	for _, app := range s.applications {
		if app.TenantID == tenantUUID && app.IsDynamic {
			profile := s.profiles[app.ProfileID]
			group := s.groups[app.GroupID]

			result = append(result, model.ApplicationSummary{
				ID:              app.ID,
				ClientID:        app.ClientID,
				ApplicationName: app.ApplicationName,
				IsEnabled:       app.IsEnabled,
				IsDynamic:       true,
				CreatedAt:       app.CreatedAt,
				UpdatedAt:       app.UpdatedAt,
				LastUsedAt:      app.LastUsedAt,
				ProfileID:       app.ProfileID,
				ProfileName:     profile.ProfileName,
				GroupID:         app.GroupID,
				GroupName:       group.GroupName,
			})
		}
	}
	return result, nil
}

func (s *Storage) GetStaticApplicationsSummary(ctx context.Context, tenantUUID uuid.UUID) ([]model.ApplicationSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []model.ApplicationSummary
	for _, app := range s.applications {
		if app.TenantID == tenantUUID && !app.IsDynamic {
			profile := s.profiles[app.ProfileID]
			group := s.groups[app.GroupID]

			result = append(result, model.ApplicationSummary{
				ID:              app.ID,
				ClientID:        app.ClientID,
				ApplicationName: app.ApplicationName,
				IsEnabled:       app.IsEnabled,
				IsDynamic:       false,
				CreatedAt:       app.CreatedAt,
				UpdatedAt:       app.UpdatedAt,
				LastUsedAt:      app.LastUsedAt,
				ProfileID:       app.ProfileID,
				ProfileName:     profile.ProfileName,
				GroupID:         app.GroupID,
				GroupName:       group.GroupName,
			})
		}
	}
	return result, nil
}

// CreateApplicationProfile registers a central configuration blueprint template in memory.
func (s *Storage) CreateApplicationProfile(ctx context.Context, tenantUUID uuid.UUID, profile model.ApplicationProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Safety check: Assert that the incoming model context matches the tenancy perimeter
	if profile.TenantID != tenantUUID {
		return fmt.Errorf("repository: tenant UUID mismatch during profile creation")
	}

	clone := profile
	clone.TenantID = tenantUUID
	s.profiles[profile.ID] = &clone

	nameKey := fmt.Sprintf("%s|%s", tenantUUID.String(), profile.ProfileName)
	s.profileNames[nameKey] = profile.ID
	return nil
}

// CreateApplicationGroup registers an authorization group constraint boundary in memory.
func (s *Storage) CreateApplicationGroup(ctx context.Context, tenantUUID uuid.UUID, group model.ApplicationGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Safety check: Assert that the incoming model context matches the tenancy perimeter
	if group.TenantID != tenantUUID {
		return fmt.Errorf("repository: tenant UUID mismatch during group creation")
	}

	clone := group
	clone.TenantID = tenantUUID
	s.groups[group.ID] = &clone

	nameKey := fmt.Sprintf("%s|%s", tenantUUID.String(), group.GroupName)
	s.groupNames[nameKey] = group.ID
	return nil
}

// CreateApplication provisions a core decoupled application instance node in memory.
func (s *Storage) CreateApplication(ctx context.Context, tenantUUID uuid.UUID, app model.Application) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if app.TenantID != tenantUUID {
		return fmt.Errorf("repository: tenant UUID mismatch during application creation")
	}

	for _, existing := range s.applications {
		if existing.ClientID == app.ClientID && existing.TenantID == tenantUUID {
			return fmt.Errorf("repository: client_id already exists for this tenant")
		}
	}

	clone := app
	clone.TenantID = tenantUUID
	s.applications[app.ID] = &clone
	return nil
}

func (s *Storage) UpdateApplication(ctx context.Context, tenantUUID uuid.UUID, clientID string, app model.Application) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var target *model.Application
	for _, existing := range s.applications {
		if existing.ClientID == clientID && existing.TenantID == tenantUUID {
			target = existing
			break
		}
	}

	if target == nil {
		return port.ErrApplicationNotFound
	}

	target.ApplicationName = app.ApplicationName
	target.IsEnabled = app.IsEnabled
	target.ProfileID = app.ProfileID
	target.GroupID = app.GroupID
	target.UpdatedAt = time.Now().UTC() // Simulates database trigger bump
	return nil
}

// DeleteApplication removes a core application instance from memory based on tenant and client IDs.
func (s *Storage) DeleteApplication(ctx context.Context, tenantUUID uuid.UUID, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var targetID uuid.UUID
	found := false

	// Scan memory map cache for matching business properties
	for id, app := range s.applications {
		if app.ClientID == clientID && app.TenantID == tenantUUID {
			targetID = id
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("repository: application not found for deletion")
	}

	// Evict the record node safely
	delete(s.applications, targetID)
	return nil
}

/* OLD code */

func (s *Storage) GetAndConsumeOutboundHandshake(ctx context.Context, tenantID uuid.UUID, incomingState string) (*model.OutboundHandshakeSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.outboundHandshakes[incomingState]
	if !ok || session.TenantID != tenantID {
		return nil, nil // Return explicitly safe nil if state is expired or unknown
	}

	// Destructive single-use protection: immediately erase tracking state to block replay exploits
	delete(s.outboundHandshakes, incomingState)

	clone := session
	return &clone, nil
}

func (s *Storage) SaveOutboundHandshake(ctx context.Context, session model.OutboundHandshakeSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outboundHandshakes[session.ID] = session
	return nil
}

// DecoupleIdentity breaks the relational binding link between an internal user profile
// and an external identity provider token namespace inside your in-memory cluster.
func (s *Storage) DecoupleIdentity(ctx context.Context, userProfileID uuid.UUID, identityProviderID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reconstruct the matching tracking key mapping layout
	key := fmt.Sprintf("%s|%s", userProfileID.String(), identityProviderID.String())

	if _, ok := s.identities[key]; !ok {
		return port.ErrIdentityNotFound
	}

	delete(s.identities, key)
	return nil
}

func (s *Storage) CreateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.providers[tenantID.String()]; !ok {
		s.providers[tenantID.String()] = make(map[uuid.UUID]model.IdentityProvider)
	}
	provider.Issuer = provider.Config.DiscoveryEndpoint
	s.providers[tenantID.String()][provider.ID] = provider
	return nil
}

// DeleteIdentityProvider purges a specific identity provider entry from the tenant context catalog.
func (s *Storage) DeleteIdentityProvider(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	providers, ok := s.providers[tenantID.String()]
	if !ok {
		return port.ErrTenantNotFound
	}

	if _, exists := providers[idpID]; !exists {
		return port.ErrIdentityProviderNotFound
	}

	delete(providers, idpID)
	return nil
}

func (s *Storage) GetIdentityProviderByType(ctx context.Context, tenantID uuid.UUID, idpType string) (*model.IdentityProvider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	providers, ok := s.providers[tenantID.String()]
	if !ok {
		return nil, port.ErrTenantNotFound
	}

	for _, provider := range providers {
		if provider.IDPType == idpType && provider.Enabled {
			clone := provider
			return &clone, nil
		}
	}

	return nil, port.ErrIdentityProviderNotFound
}

func (s *Storage) GetEnabledIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	providers, ok := s.providers[tenantID.String()]
	if !ok {
		return nil, port.ErrTenantNotFound
	}

	result := make([]model.IdentityProvider, 0)
	for _, provider := range providers {
		if provider.Enabled {
			clone := provider
			result = append(result, clone)
		}
	}
	return result, nil
}

// GetIdentityProviders returns all identity provider definitions associated with the tenant.
func (s *Storage) GetIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	providers, ok := s.providers[tenantID.String()]
	if !ok {
		return []model.IdentityProvider{}, nil
	}

	res := make([]model.IdentityProvider, 0, len(providers))
	for _, p := range providers {
		clone := p
		res = append(res, clone)
	}
	return res, nil
}

// GetUserProfilesByTenant lists all administrative user profile entries
// registered under a specific tenant context boundary.
func (s *Storage) GetUserProfilesByTenant(ctx context.Context, tenantID uuid.UUID, partitionID int64) ([]model.UserProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var res []model.UserProfile
	for _, p := range s.userProfiles {
		if p.TenantID == tenantID && (partitionID == 0 || p.PartitionID == partitionID) {
			clone := *p
			res = append(res, clone)
		}
	}
	return res, nil
}

// UpdateUserProfile mutates an existing administrative user profile entry
// within the context boundary of a specific tenant.
func (s *Storage) UpdateUserProfile(ctx context.Context, tenantID uuid.UUID, profile model.UserProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := profile.ID.String()
	existing, ok := s.userProfiles[key]
	if !ok || existing.TenantID != tenantID {
		return port.ErrUserProfileNotFound
	}

	existing.PreferredUsername = profile.PreferredUsername
	existing.Name = profile.Name
	existing.FirstName = profile.FirstName // Preserves split name parameter fields
	existing.LastName = profile.LastName   // Preserves split name parameter fields
	existing.Email = profile.Email
	existing.EmailVerified = profile.EmailVerified
	existing.PartitionID = profile.PartitionID
	existing.UpdatedAt = time.Now().UTC()

	return nil
}

func (s *Storage) SaveUserProfile(ctx context.Context, tenantID uuid.UUID, partitionID int64, profile model.UserProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Section 5.3 Collision Check Simulation
	for _, p := range s.userProfiles {
		if p.TenantID == tenantID && p.PartitionID == profile.PartitionID {
			if p.PreferredUsername == profile.PreferredUsername {
				return port.ErrUsernameAlreadyExists
			}
			if profile.Email != "" && p.Email == profile.Email {
				return port.ErrEmailAlreadyExists
			}
		}
	}

	clone := profile
	s.userProfiles[profile.ID.String()] = &clone
	return nil
}

// DeleteUserProfile removes an administrative user profile entry from the persistence mapping.
func (s *Storage) DeleteUserProfile(ctx context.Context, tenantID uuid.UUID, partitionID int64, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := userID.String()
	profile, ok := s.userProfiles[key]
	if !ok || profile.TenantID != tenantID {
		return port.ErrUserProfileNotFound
	}

	delete(s.userProfiles, key)
	return nil
}

func (s *Storage) GetAllTenants(ctx context.Context) ([]model.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	scheme := model.SchemeHttps
	if s.appEnv == "local" {
		scheme = model.SchemeHttp
	}

	var result []model.Tenant
	for _, t := range s.tenants {
		clone := *t
		clone.Scheme = scheme
		result = append(result, clone)
	}
	return result, nil
}

// GetUserIdentities lists all linked third-party or federated identity mappings
// that belong to a single, specific internal user profile UUID.
func (s *Storage) GetUserIdentities(ctx context.Context, userProfileID uuid.UUID) ([]model.UserIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var res []model.UserIdentity
	for _, identity := range s.identities {
		if identity.UserProfileID == userProfileID {
			clone := *identity
			res = append(res, clone)
		}
	}
	return res, nil
}

func (s *Storage) SavePasswordCredential(ctx context.Context, credential model.PasswordCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("%s|%s", credential.UserProfileID.String(), credential.IdentityProviderID.String())
	s.passwordCredentials[key] = &credential
	return nil
}

func (s *Storage) GetUserProfileByIdentifier(ctx context.Context, tenantID uuid.UUID, partitionID int64, providerID uuid.UUID, identifier string) (*model.UserProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, profile := range s.userProfiles {
		if profile.TenantID == tenantID && profile.PartitionID == partitionID && (profile.PreferredUsername == identifier || profile.Email == identifier) {
			clone := *profile
			return &clone, nil
		}
	}
	return nil, port.ErrUserProfileNotFound
}

func (s *Storage) GetUserProfileByID(ctx context.Context, tenantID uuid.UUID, partitionID int64, id uuid.UUID) (*model.UserProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	profile, ok := s.userProfiles[id.String()]
	if !ok || profile.TenantID != tenantID {
		return nil, port.ErrUserProfileNotFound
	}
	clone := *profile
	return &clone, nil
}

func (s *Storage) GetPasswordCredentialByProfileID(ctx context.Context, tenantID uuid.UUID, partitionID int64, userProfileID uuid.UUID, providerID uuid.UUID) (*model.PasswordCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s|%s", userProfileID.String(), providerID.String())
	credential, ok := s.passwordCredentials[key]
	if !ok {
		return nil, fmt.Errorf("password credential for user %s provider %s: %w", userProfileID, providerID, port.ErrPasswordCredentialNotFound)
	}
	clone := *credential
	return &clone, nil
}

func (s *Storage) UpdatePasswordLockoutState(ctx context.Context, tenantID uuid.UUID, partitionID int64, userProfileID uuid.UUID, providerID uuid.UUID, failedCount int, lastAttempt *time.Time, blockedUntil *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s|%s", userProfileID.String(), providerID.String())
	credential, ok := s.passwordCredentials[key]
	if !ok {
		return fmt.Errorf("password credential for user %s provider %s: %w", userProfileID, providerID, port.ErrPasswordCredentialNotFound)
	}
	credential.FailedVerificationCount = failedCount
	credential.LastVerificationAttempt = lastAttempt
	credential.BlockedUntil = blockedUntil
	return nil
}

func (s *Storage) ResetPasswordCounters(ctx context.Context, tenantID uuid.UUID, partitionID int64, userProfileID uuid.UUID, providerID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s|%s", userProfileID.String(), providerID.String())
	credential, ok := s.passwordCredentials[key]
	if !ok {
		return fmt.Errorf("password credential for user %s provider %s: %w", userProfileID, providerID, port.ErrPasswordCredentialNotFound)
	}
	credential.FailedVerificationCount = 0
	credential.BlockedUntil = nil
	return nil
}

func (s *Storage) GetIdentityByProfileAndProvider(ctx context.Context, userProfileID uuid.UUID, providerID uuid.UUID) (*model.UserIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s|%s", userProfileID.String(), providerID.String())
	identity, ok := s.identities[key]
	if !ok {
		return nil, fmt.Errorf("identity for user %s provider %s: %w", userProfileID, providerID, port.ErrIdentityNotFound)
	}
	clone := *identity
	return &clone, nil
}

func (s *Storage) GetUserIdentitiesByProfileID(ctx context.Context, tenantUUID uuid.UUID, partitionID int64, profileID uuid.UUID) ([]model.UserIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []model.UserIdentity
	for _, ident := range s.identities {
		if ident.UserProfileID == profileID {
			result = append(result, *ident)
		}
	}
	return result, nil
}

func (s *Storage) GetUserIdentityByIdentifier(ctx context.Context, tenantID uuid.UUID, partitionID int64, providerID uuid.UUID, identifier string) (*model.UserIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	profile, err := s.GetUserProfileByIdentifier(ctx, tenantID, partitionID, providerID, identifier)
	if err != nil {
		return nil, port.ErrIdentityNotFound
	}

	key := fmt.Sprintf("%s|%s", profile.ID.String(), providerID.String())
	identity, ok := s.identities[key]
	if !ok {
		return nil, port.ErrIdentityNotFound
	}
	clone := *identity
	return &clone, nil
}

func (s *Storage) GetUserIdentityByProviderAndExternalID(ctx context.Context, tenantID uuid.UUID, partitionID int64, providerID uuid.UUID, externalID string) (*model.UserIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, identity := range s.identities {
		if identity.IdentityProviderID == providerID && identity.ExternalIdentityID == externalID {
			clone := *identity
			return &clone, nil
		}
	}
	return nil, port.ErrIdentityNotFound
}

func (s *Storage) FindProfileByEmail(ctx context.Context, partitionID int64, email string) (*model.UserProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, profile := range s.userProfiles {
		if profile.PartitionID == partitionID && profile.Email == email {
			clone := *profile
			return &clone, nil
		}
	}
	return nil, port.ErrUserProfileNotFound
}

func (s *Storage) UpsertUserIdentity(ctx context.Context, tenantID uuid.UUID, partitionID int64, identity model.UserIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s|%s", identity.UserProfileID.String(), identity.IdentityProviderID.String())
	s.identities[key] = &identity
	return nil
}

func (s *Storage) CreateTenant(ctx context.Context, tenant model.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Maintain idempotent unique domain constraints matching your SQL logic
	for _, existing := range s.tenants {
		if existing.ID == tenant.ID && existing.Domain != tenant.Domain {
			return fmt.Errorf("tenant with UUID %s already exists", tenant.ID)
		}
	}

	clone := tenant
	if clone.Scheme == "" {
		clone.Scheme = model.SchemeHttps
		if s.appEnv == "local" {
			clone.Scheme = model.SchemeHttp
		}
	}

	// ENCAPSULATED SIDE EFFECT: Automate default partition mapping if completely empty
	tenantKey := clone.ID.String()
	parts, exists := s.partitions[tenantKey]
	if !exists || len(parts) == 0 {
		if !exists {
			s.partitions[tenantKey] = make(map[int64]model.Partition)
		}

		// Simulate database auto-incrementing integer key allocation
		allocatedID := int64(len(s.partitions[tenantKey]) + 1)
		defaultPartition := model.Partition{
			ID:        allocatedID,
			TenantID:  clone.ID,
			Name:      "default",
			AliasName: "default", // Aligned straight to your exact schema field names
		}

		// Persist the partition entry directly into the mock grid
		s.partitions[tenantKey][allocatedID] = defaultPartition

		// Self-link the tenant clone pointer natively to mimic the database transaction
		clone.DefaultPartition = &allocatedID
	}

	s.tenants[clone.Domain] = &clone
	return nil
}

func (s *Storage) RevokeSession(ctx context.Context, tenantID uuid.UUID, subject string, clientID string) error {
	return nil
}

func (s *Storage) SaveRefreshToken(ctx context.Context, token model.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[token.TokenID] = token
	return nil
}

func (s *Storage) GetRefreshToken(ctx context.Context, tokenID string) (*model.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	token, ok := s.refreshTokens[tokenID]
	if !ok {
		return nil, fmt.Errorf("refresh token %s: %w", tokenID, port.ErrSessionNotFound)
	}
	return &token, nil
}

func (s *Storage) MarkRefreshTokenUsed(ctx context.Context, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, ok := s.refreshTokens[tokenID]
	if !ok {
		return fmt.Errorf("refresh token not found")
	}
	token.IsUsed = true
	s.refreshTokens[tokenID] = token
	return nil
}

func (s *Storage) RevokeRefreshTokenFamily(ctx context.Context, tokenFamilyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.refreshTokens {
		if v.TokenFamilyID == tokenFamilyID {
			delete(s.refreshTokens, k)
		}
	}
	return nil
}

func (s *Storage) PurgeTenantSessionsAndTokens(ctx context.Context, tenantID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, v := range s.sessions {
		if v.TenantID == tenantID {
			delete(s.sessions, k)
		}
	}

	for k, v := range s.refreshTokens {
		if v.TenantID == tenantID {
			delete(s.refreshTokens, k)
		}
	}

	return nil
}

func (s *Storage) GetPartitions(ctx context.Context, tenantID uuid.UUID) ([]model.Partition, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	parts, ok := s.partitions[tenantID.String()]
	if !ok {
		return []model.Partition{}, nil
	}

	res := make([]model.Partition, 0, len(parts))
	for _, p := range parts {
		res = append(res, p)
	}
	return res, nil
}

func (s *Storage) GetPartitionByAlias(ctx context.Context, tenantID uuid.UUID, alias string) (*model.Partition, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	parts, ok := s.partitions[tenantID.String()]
	if !ok {
		return nil, port.ErrPartitionNotFound
	}

	for _, p := range parts {
		if p.AliasName == alias {
			return &p, nil
		}
	}
	return nil, port.ErrPartitionNotFound
}

func (s *Storage) CreatePartition(ctx context.Context, tenantID uuid.UUID, name, aliasName string) (*model.Partition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.partitions[tenantID.String()]; !ok {
		s.partitions[tenantID.String()] = make(map[int64]model.Partition)
	}

	id := int64(len(s.partitions[tenantID.String()]) + 1)
	p := model.Partition{
		ID:        id,
		TenantID:  tenantID,
		Name:      name,
		AliasName: aliasName,
	}
	s.partitions[tenantID.String()][id] = p
	return &p, nil
}

func (s *Storage) SaveFederatedSession(ctx context.Context, session model.FederatedSession) error {
	return nil
}

func (s *Storage) GetFederatedSessionByLocalSessionID(ctx context.Context, tenantUUID uuid.UUID, partitionID int64, sessionID string) (*model.FederatedSession, error) {
	return nil, nil
}

func (s *Storage) FindFederatedSessionByUpstreamSubject(ctx context.Context, tenantUUID uuid.UUID, idpID uuid.UUID, upstreamSub string) (*model.FederatedSession, error) {
	return nil, nil
}

func (s *Storage) DeleteFederatedSession(ctx context.Context, tenantUUID uuid.UUID, partitionID int64, sessionID string) error {
	return nil
}

func (s *Storage) PruneExpiredFederatedSessions(ctx context.Context, now time.Time) (int64, error) {
	return 0, nil
}

func (s *Storage) GetApplicationsLogoutContextBySession(ctx context.Context, tenantUUID uuid.UUID, sessionID string) ([]model.Application, error) {
	return nil, nil
}

func (s *Storage) GetIdentityProviderByAlias(ctx context.Context, tenantID uuid.UUID, alias string) (*model.IdentityProvider, error) {
	return nil, nil
}

func (s *Storage) UpdateApplicationGroup(ctx context.Context, tenantUUID uuid.UUID, group model.ApplicationGroup) error {
	return nil
}

func (s *Storage) GetIdentityProviderByUUID(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) (*model.IdentityProvider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenantProviders, ok := s.providers[tenantID.String()]
	if !ok {
		return nil, port.ErrIdentityProviderNotFound
	}
	p, ok := tenantProviders[idpID]
	if !ok {
		return nil, port.ErrIdentityProviderNotFound
	}
	clone := p
	return &clone, nil
}

func (s *Storage) UpdateApplicationProfile(ctx context.Context, tenantUUID uuid.UUID, profile model.ApplicationProfile) error {
	return nil
}

func (s *Storage) GetIdentityProvidersByTypeAndPartition(ctx context.Context, tenantID uuid.UUID, partitionID int64, idpType string) ([]model.IdentityProvider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []model.IdentityProvider
	tenantProviders, ok := s.providers[tenantID.String()]
	if !ok {
		return nil, nil
	}
	for _, p := range tenantProviders {
		if p.IDPType == idpType && (partitionID == 0 || p.PartitionID == partitionID) {
			result = append(result, p)
		}
	}
	return result, nil
}

func (s *Storage) GetIdentityProvidersByUUIDs(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) ([]model.IdentityProvider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []model.IdentityProvider
	tenantProviders, ok := s.providers[tenantID.String()]
	if !ok {
		return nil, nil
	}
	for _, id := range ids {
		if p, ok := tenantProviders[id]; ok {
			result = append(result, p)
		}
	}
	return result, nil
}

func (s *Storage) GetPartitionByID(ctx context.Context, tenantID uuid.UUID, partitionID int64) (*model.Partition, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	parts, ok := s.partitions[tenantID.String()]
	if !ok {
		return nil, port.ErrPartitionNotFound
	}
	p, ok := parts[partitionID]
	if !ok {
		return nil, port.ErrPartitionNotFound
	}
	clone := p
	return &clone, nil
}

func (s *Storage) GetUserProfileByIDAndPartitionAlias(ctx context.Context, tenantID uuid.UUID, partitionAlias string, id uuid.UUID) (*model.UserProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	profile, ok := s.userProfiles[id.String()]
	if !ok || profile.TenantID != tenantID {
		return nil, port.ErrUserProfileNotFound
	}
	clone := *profile
	return &clone, nil
}

func (s *Storage) IncrementUserIdentityLoginTracker(ctx context.Context, tenantID uuid.UUID, partitionID int64, identityID uuid.UUID, loginTime time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ident := range s.identities {
		if ident.ID == identityID {
			ident.LoginCount++
			ident.LastLoginAt = &loginTime
			return nil
		}
	}
	return port.ErrIdentityNotFound
}

func (s *Storage) RecordClientSessionLink(ctx context.Context, tenantID uuid.UUID, sessionID string, clientID string, associatedAt time.Time) error {
	return nil
}
