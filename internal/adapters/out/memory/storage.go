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
	mu                  sync.RWMutex
	tenants             map[string]*model.Tenant
	clients             map[string]map[string]model.ClientApplication
	sessions            map[string]model.AuthorizationCodeSession
	providers           map[string]map[uuid.UUID]model.IdentityProvider
	profiles            map[string]*model.UserProfile
	passwordCredentials map[string]*model.PasswordCredential
	identities          map[string]*model.UserIdentity
	interactionSessions map[uuid.UUID]model.InteractionSession
	revokedTokens       map[string]time.Time
	parSessions         map[string]model.PushedAuthorizationRequest
	dpopProofs          map[string]time.Time
	refreshTokens       map[string]model.RefreshToken
	partitions          map[string]map[int64]model.Partition
}

func NewStorage() *Storage {
	return &Storage{
		tenants:             make(map[string]*model.Tenant),
		clients:             make(map[string]map[string]model.ClientApplication),
		sessions:            make(map[string]model.AuthorizationCodeSession),
		providers:           make(map[string]map[uuid.UUID]model.IdentityProvider),
		profiles:            make(map[string]*model.UserProfile),
		passwordCredentials: make(map[string]*model.PasswordCredential),
		identities:          make(map[string]*model.UserIdentity),
		interactionSessions: make(map[uuid.UUID]model.InteractionSession),
		revokedTokens:       make(map[string]time.Time),
		parSessions:         make(map[string]model.PushedAuthorizationRequest),
		dpopProofs:          make(map[string]time.Time),
		refreshTokens:       make(map[string]model.RefreshToken),
		partitions:          make(map[string]map[int64]model.Partition),
	}
}

func (s *Storage) ResolveTenantByID(ctx context.Context, tenantID uuid.UUID) (*model.Tenant, error) {
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
			return &clone, nil
		}
	}
	return nil, port.ErrTenantNotFound
}

func (s *Storage) CreateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.providers[tenantID.String()]; !ok {
		s.providers[tenantID.String()] = make(map[uuid.UUID]model.IdentityProvider)
	}
	s.providers[tenantID.String()][provider.ID] = provider
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

func (s *Storage) SaveUserProfile(ctx context.Context, tenantID uuid.UUID, profile model.UserProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for username collision
	for _, p := range s.profiles {
		if p.TenantID == tenantID && p.PreferredUsername == profile.PreferredUsername {
			return port.ErrUsernameAlreadyExists
		}
	}

	// Check for email collision if provided
	if profile.Email != "" {
		for _, p := range s.profiles {
			if p.TenantID == tenantID && p.Email == profile.Email {
				return port.ErrEmailAlreadyExists
			}
		}
	}

	profile.ID = uuid.New()
	profile.TenantID = tenantID

	// Keep the original string key for memory storage (the memory storage maps profiles by string key "%s|%s|%s")
	// Let's actually look at the key format: fmt.Sprintf("%s|%s|%s", tenantID.String(), providerID.String(), identifier)
	// Wait, our Storage struct profiles is map[string]*model.UserProfile. Let's see how it was defined in original file.
	// Ah! Original was map[string]*model.UserProfile.
	// When saving, we can just use a generic key or profile.ID.String() since s.profiles is map[string]*model.UserProfile!
	s.profiles[profile.ID.String()] = &profile
	return nil
}

func (s *Storage) SavePasswordCredential(ctx context.Context, credential model.PasswordCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("%s|%s", credential.UserProfileID.String(), credential.IdentityProviderID.String())
	s.passwordCredentials[key] = &credential
	return nil
}

func (s *Storage) GetUserProfileByIdentifier(ctx context.Context, tenantID uuid.UUID, identifier string) (*model.UserProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, profile := range s.profiles {
		if profile.TenantID == tenantID && (profile.PreferredUsername == identifier || profile.Email == identifier) {
			clone := *profile
			return &clone, nil
		}
	}

	return nil, port.ErrUserProfileNotFound
}

func (s *Storage) GetUserProfileByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.UserProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	profile, ok := s.profiles[id.String()]
	if !ok || profile.TenantID != tenantID {
		return nil, port.ErrUserProfileNotFound
	}
	clone := *profile
	return &clone, nil
}

func (s *Storage) GetPasswordCredential(ctx context.Context, userProfileID uuid.UUID, providerID uuid.UUID) (*model.PasswordCredential, error) {
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

func (s *Storage) UpsertIdentity(ctx context.Context, identity model.UserIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s|%s", identity.UserProfileID.String(), identity.IdentityProviderID.String())
	s.identities[key] = &identity
	return nil
}

func (s *Storage) SaveClient(ctx context.Context, client model.ClientApplication) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.clients[client.TenantID.String()]; !ok {
		s.clients[client.TenantID.String()] = make(map[string]model.ClientApplication)
	}
	s.clients[client.TenantID.String()][client.ClientID] = client
	return nil
}

func (s *Storage) GetClient(ctx context.Context, tenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenantClients, ok := s.clients[tenantID.String()]
	if !ok {
		return nil, fmt.Errorf("client %s for tenant %s: %w", clientID, tenantID, port.ErrClientNotFound)
	}

	client, ok := tenantClients[clientID]
	if !ok {
		return nil, fmt.Errorf("client %s for tenant %s: %w", clientID, tenantID, port.ErrClientNotFound)
	}
	return &client, nil
}

func (s *Storage) GetClientsByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.ClientApplication, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenantClients, ok := s.clients[tenantID.String()]
	if !ok {
		return []model.ClientApplication{}, nil
	}

	clients := make([]model.ClientApplication, 0, len(tenantClients))
	for _, client := range tenantClients {
		clients = append(clients, client)
	}
	return clients, nil
}

func (s *Storage) SaveAuthSession(ctx context.Context, session model.AuthorizationCodeSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	if session.TenantID != tenantID.String() {
		return nil, fmt.Errorf("session tenant mismatch: %w", port.ErrSessionNotFound)
	}
	delete(s.sessions, code)
	return &session, nil
}

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
	return &clone, nil
}

func (s *Storage) CreateTenant(ctx context.Context, tenant model.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.tenants {
		if existing.ID == tenant.ID {
			return fmt.Errorf("tenant with UUID %s already exists", tenant.ID)
		}
	}
	s.tenants[tenant.Domain] = &tenant
	return nil
}

func (s *Storage) RevokeSession(ctx context.Context, tenantID uuid.UUID, subject string, clientID string) error {
	return nil
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
		if v.TenantID == tenantID.String() {
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

func (s *Storage) GetPartitionByID(ctx context.Context, id int64) (*model.Partition, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, parts := range s.partitions {
		if p, ok := parts[id]; ok {
			return &p, nil
		}
	}
	return nil, port.ErrPartitionNotFound
}
