package service

import (
	"context"
	"fmt"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

type TenantService struct {
	storage port.Storage
	clock   port.Clock
}

func NewTenantService(storage port.Storage, cl port.Clock) *TenantService {
	return &TenantService{storage: storage, clock: cl}
}

func (s *TenantService) CreateTenant(ctx context.Context, name, domain string) (*model.Tenant, error) {
	if name == "" {
		return nil, fmt.Errorf("tenant name is required")
	}
	if domain == "" {
		return nil, fmt.Errorf("canonical domain is required")
	}

	newTenant := model.Tenant{
		ID:        uuid.New(),
		Name:      name,
		Domain:    domain,
		IsActive:  true,
		CreatedAt: s.clock.Now(),
		Config: model.TenantConfig{
			PredefinedScopes:    []string{"openid", "profile", "email", "offline_access"},
			PredefinedAudiences: []string{},
			DefaultRedirectURI:  "http://" + domain,
			RedirectWhitelist:   []string{"http://" + domain, "https://" + domain},
			AllowSignup:         false,
		},
	}

	if err := s.storage.CreateTenant(ctx, newTenant); err != nil {
		return nil, err
	}

	return &newTenant, nil
}

func (s *TenantService) GetTenant(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
	return s.storage.ResolveTenantByID(ctx, id)
}

func (s *TenantService) GetAllTenants(ctx context.Context) ([]model.Tenant, error) {
	return s.storage.GetAllTenants(ctx)
}

func (s *TenantService) ToggleSignup(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
	tenant, err := s.storage.ResolveTenantByID(ctx, id)
	if err != nil {
		return nil, err
	}

	tenant.Config.AllowSignup = !tenant.Config.AllowSignup

	if err := s.storage.CreateTenant(ctx, *tenant); err != nil {
		return nil, err
	}

	return tenant, nil
}

func (s *TenantService) UpdateTenant(ctx context.Context, id uuid.UUID, name, domain string, config model.TenantConfig) (*model.Tenant, error) {
	tenant, err := s.storage.ResolveTenantByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if name != "" {
		tenant.Name = name
	}
	if domain != "" {
		tenant.Domain = domain
	}
	tenant.Config = config

	if err := s.storage.CreateTenant(ctx, *tenant); err != nil {
		return nil, err
	}

	return tenant, nil
}
