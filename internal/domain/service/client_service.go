package service

import (
	"context"
	"fmt"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

type ClientService struct {
	storage port.Storage
}

func NewClientService(storage port.Storage) *ClientService {
	return &ClientService{storage: storage}
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
