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

func (s *ClientService) UpdateClient(ctx context.Context, tenantID uuid.UUID, client model.ClientApplication) (*model.ClientApplication, error) {
	existing, err := s.storage.GetClient(ctx, tenantID, client.ClientID)
	if err != nil {
		return nil, err
	}

	existing.ClientName = client.ClientName
	existing.RedirectURIs = client.RedirectURIs
	existing.PostLogoutRedirectURIs = client.PostLogoutRedirectURIs
	existing.FrontChannelLogoutURI = client.FrontChannelLogoutURI
	existing.BackChannelLogoutURI = client.BackChannelLogoutURI
	existing.GrantTypes = client.GrantTypes
	existing.ResponseTypes = client.ResponseTypes
	existing.AllowedScopes = client.AllowedScopes
	existing.DefaultScopes = client.DefaultScopes
	existing.AllowedIDPs = client.AllowedIDPs
	existing.DefaultIDP = client.DefaultIDP
	existing.AllowedAudiences = client.AllowedAudiences
	existing.ClientType = client.ClientType
	existing.AccessTokenLifetime = client.AccessTokenLifetime
	existing.RefreshTokenLifetime = client.RefreshTokenLifetime
	existing.IDTokenLifetime = client.IDTokenLifetime

	if err := s.storage.SaveClient(ctx, *existing); err != nil {
		return nil, err
	}

	return existing, nil
}
