package service

import (
	"context"
	"errors"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

// TenantBootstrapService is the domain-level orchestration point that ensures
// the configured admin tenant domain resolves to a tenant record.
type TenantBootstrapService struct {
	storage port.Storage
}

func NewTenantBootstrapService(storage port.Storage) *TenantBootstrapService {
	return &TenantBootstrapService{storage: storage}
}

func (s *TenantBootstrapService) BootstrapAdminTenant(ctx context.Context, domain string) (*model.Tenant, error) {
	tenant, err := s.storage.ResolveTenantByDomain(ctx, domain)
	if err == nil {
		providers, providerErr := s.storage.GetEnabledIdentityProviders(ctx, tenant.ID)
		if providerErr != nil || len(providers) == 0 {
			defaultProvider := model.IdentityProvider{
				ID:       uuid.New(),
				TenantID: tenant.ID,
				IDPType:  model.UsernamePasswordIDPType,
				Enabled:  true,
				Alias:    "username-password",
				Config: model.IdentityProviderConfig{
					UsernameField: "preferredUsername",
				},
			}
			if err := s.storage.CreateIdentityProvider(ctx, tenant.ID, defaultProvider); err != nil {
				return nil, err
			}
		}
		return tenant, nil
	}

	if !errors.Is(err, port.ErrTenantNotFound) {
		return nil, err
	}

	newTenant := &model.Tenant{
		ID:               uuid.New(),
		Name:             domain,
		Domain:           domain,
		IsActive:         true,
		CreatedAt:        time.Now().UTC(),
		PredefinedScopes: []string{"openid", "profile", "email", "offline_access"},
	}

	if err := s.storage.CreateTenant(ctx, *newTenant); err != nil {
		return nil, err
	}

	defaultProvider := model.IdentityProvider{
		ID:       uuid.New(),
		TenantID: newTenant.ID,
		IDPType:  model.UsernamePasswordIDPType,
		Enabled:  true,
		Alias:    "username-password",
		Config: model.IdentityProviderConfig{
			UsernameField: "preferredUsername",
		},
	}
	if err := s.storage.CreateIdentityProvider(ctx, newTenant.ID, defaultProvider); err != nil {
		return nil, err
	}

	return newTenant, nil
}
