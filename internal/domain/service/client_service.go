package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

type ClientService struct {
	storage port.Storage
	crypto  port.Crypto
}

func NewClientService(s port.Storage, c port.Crypto) *ClientService {
	return &ClientService{
		storage: s,
		crypto:  c,
	}
}

func (s *ClientService) GetClientsByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.ClientApplication, error) {
	return s.storage.GetClientsByTenant(ctx, tenantID)
}

func (s *ClientService) CreateClient(ctx context.Context, tenantID uuid.UUID, client model.ClientApplication) (*model.ClientApplication, error) {
	if client.ClientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if client.ClientName == "" {
		return nil, fmt.Errorf("client name is required")
	}

	client.ID = uuid.New().String()
	client.TenantID = tenantID

	// Set required OIDC Defaults for schema constraints
	if client.RedirectURIs == nil {
		client.RedirectURIs = []string{}
	}
	if client.PostLogoutRedirectURIs == nil {
		client.PostLogoutRedirectURIs = []string{}
	}
	if client.GrantTypes == nil {
		client.GrantTypes = []string{"authorization_code"}
	}
	if client.ResponseTypes == nil {
		client.ResponseTypes = []string{"code"}
	}
	if client.AllowedScopes == nil {
		client.AllowedScopes = []string{"openid", "profile", "email"}
	}
	if client.DefaultScopes == nil {
		client.DefaultScopes = []string{"openid", "profile", "email"}
	}
	if client.AllowedIDPs == nil {
		client.AllowedIDPs = []string{"username-password"}
	}
	if client.AllowedAudiences == nil {
		client.AllowedAudiences = []string{}
	}
	if client.Algorithm == "" {
		client.Algorithm = model.AlgRS256
	}

	if err := s.storage.SaveClient(ctx, client); err != nil {
		return nil, err
	}

	return &client, nil
}

func (s *ClientService) DeleteClient(ctx context.Context, tenantID uuid.UUID, clientID string) error {
	if clientID == "" {
		return fmt.Errorf("client ID is required")
	}
	return s.storage.DeleteClient(ctx, tenantID, clientID)
}

func applyClientUpdates(existing *model.ClientApplication, client model.ClientApplication) {
	applyClientMetadata(existing, client)
	applyClientSecurityAndLifetimes(existing, client)
}

func applyClientMetadata(existing *model.ClientApplication, client model.ClientApplication) {
	if client.ClientName != "" {
		existing.ClientName = client.ClientName
	}
	if client.ClientType != "" {
		existing.ClientType = client.ClientType
	}
	if client.RedirectURI != "" {
		existing.RedirectURI = client.RedirectURI
	}
	if client.RedirectURIs != nil {
		existing.RedirectURIs = client.RedirectURIs
	}
	if client.PostLogoutRedirectURIs != nil {
		existing.PostLogoutRedirectURIs = client.PostLogoutRedirectURIs
	}
	if client.FrontChannelLogoutURI != "" {
		existing.FrontChannelLogoutURI = client.FrontChannelLogoutURI
	}
	if client.BackChannelLogoutURI != "" {
		existing.BackChannelLogoutURI = client.BackChannelLogoutURI
	}
}

func applyClientSecurityAndLifetimes(existing *model.ClientApplication, client model.ClientApplication) {
	if client.GrantTypes != nil {
		existing.GrantTypes = client.GrantTypes
	}
	if client.ResponseTypes != nil {
		existing.ResponseTypes = client.ResponseTypes
	}
	if client.AllowedScopes != nil {
		existing.AllowedScopes = client.AllowedScopes
	}
	if client.DefaultScopes != nil {
		existing.DefaultScopes = client.DefaultScopes
	}
	if client.AllowedIDPs != nil {
		existing.AllowedIDPs = client.AllowedIDPs
	}
	if client.DefaultIDP != "" {
		existing.DefaultIDP = client.DefaultIDP
	}
	if client.AllowedAudiences != nil {
		existing.AllowedAudiences = client.AllowedAudiences
	}
	if client.AccessTokenLifetime > 0 {
		existing.AccessTokenLifetime = client.AccessTokenLifetime
	}
	if client.RefreshTokenLifetime > 0 {
		existing.RefreshTokenLifetime = client.RefreshTokenLifetime
	}
	if client.IDTokenLifetime > 0 {
		existing.IDTokenLifetime = client.IDTokenLifetime
	}
	existing.EnforceRTR = client.EnforceRTR
}

func ensureNonNullClientFields(existing *model.ClientApplication) {
	if existing.RedirectURIs == nil {
		existing.RedirectURIs = []string{}
	}
	if existing.PostLogoutRedirectURIs == nil {
		existing.PostLogoutRedirectURIs = []string{}
	}
	if existing.GrantTypes == nil {
		existing.GrantTypes = []string{"authorization_code"}
	}
	if existing.ResponseTypes == nil {
		existing.ResponseTypes = []string{"code"}
	}
	if existing.AllowedScopes == nil {
		existing.AllowedScopes = []string{"openid", "profile", "email"}
	}
	if existing.DefaultScopes == nil {
		existing.DefaultScopes = []string{"openid", "profile", "email"}
	}
	if existing.AllowedIDPs == nil {
		existing.AllowedIDPs = []string{"username-password"}
	}
	if existing.AllowedAudiences == nil {
		existing.AllowedAudiences = []string{}
	}
}

func (s *ClientService) UpdateClient(ctx context.Context, tenantID uuid.UUID, client model.ClientApplication) (*model.ClientApplication, error) {
	existing, err := s.storage.GetClient(ctx, tenantID, client.ClientID)
	if err != nil {
		return nil, err
	}

	applyClientUpdates(existing, client)
	ensureNonNullClientFields(existing)

	if err := s.storage.SaveClient(ctx, *existing); err != nil {
		return nil, err
	}

	return existing, nil
}

// ResetClientSecret safely handles credential generation and lifecycle rotation.
func (s *ClientService) ResetClientSecret(ctx context.Context, tenantID uuid.UUID, clientID string) (*model.ClientApplication, string, error) {
	if tenantID == uuid.Nil {
		return nil, "", fmt.Errorf("tenant identifier cannot be empty")
	}
	if clientID == "" {
		return nil, "", fmt.Errorf("client identifier cannot be empty")
	}

	// 1. Fetch the target application using the exact storage port signature contract
	client, err := s.storage.GetClient(ctx, tenantID, clientID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to locate client application: %w", err)
	}

	// 2. Structural Security Guard Rule Check
	if client.ClientType != model.ClientTypeConfidential {
		return nil, "", fmt.Errorf("cannot reset secret of a non-confidential client")
	}

	// 3. Core Domain Logic: Generate a cryptographically secure random base64 secret string
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return nil, "", fmt.Errorf("failed to generate secure random bytes: %w", err)
	}
	plainSecret := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)

	// 4. Hash using default algorithm
	hashedSecret, err := s.crypto.HashCredential(plainSecret)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash credential payload: %w", err)
	}

	// 5. Update the entity state with the secure hash reference string
	client.ClientSecret = &hashedSecret

	// 6. Persist the updated state through your outbound repository storage port
	if err := s.storage.SaveClient(ctx, *client); err != nil {
		return nil, "", fmt.Errorf("failed to persist updated client credentials: %w", err)
	}

	// 7. Return the modified client along with the unhashed plain text secret for UI rendering
	return client, plainSecret, nil
}
