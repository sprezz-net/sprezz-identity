package service

import (
	"context"
	"errors"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

const (
	schemeHttp               = "http://"
	schemeHttps              = "https://"
	routeAdmin               = "/admin"
	routeCallback            = "/admin/callback"
	usernamePasswordIDPAlias = "username-password"
)

// TenantBootstrapService is the domain-level orchestration point that ensures
// the configured admin tenant domain resolves to a tenant record.
type TenantBootstrapService struct {
	storage port.Storage
	clock   port.Clock
}

func NewTenantBootstrapService(storage port.Storage, cl port.Clock) *TenantBootstrapService {
	return &TenantBootstrapService{storage: storage, clock: cl}
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
				Alias:    usernamePasswordIDPAlias,
				Config: model.IdentityProviderConfig{
					UsernameField: "preferredUsername",
				},
			}
			if err := s.storage.CreateIdentityProvider(ctx, tenant.ID, defaultProvider); err != nil {
				return nil, err
			}
		}
		if err := s.ensureAdminClient(ctx, tenant.ID, domain); err != nil {
			return nil, err
		}
		return tenant, nil
	}

	if !errors.Is(err, port.ErrTenantNotFound) {
		return nil, err
	}

	newTenant := &model.Tenant{
		ID:        uuid.New(),
		Name:      domain,
		Domain:    domain,
		IsActive:  true,
		CreatedAt: s.clock.Now(),
		Config: model.TenantConfig{
			PredefinedScopes:    []string{"openid", "profile", "email", "offline_access"},
			PredefinedAudiences: []string{},
			DefaultRedirectURI:  schemeHttps + domain + routeAdmin,
			RedirectWhitelist:   []string{schemeHttps + domain + routeAdmin, schemeHttp + domain + routeAdmin, schemeHttp + domain + routeCallback, schemeHttps + domain + routeCallback},
			AllowSignup:         true,
		},
	}

	if err := s.storage.CreateTenant(ctx, *newTenant); err != nil {
		return nil, err
	}

	defaultProvider := model.IdentityProvider{
		ID:       uuid.New(),
		TenantID: newTenant.ID,
		IDPType:  model.UsernamePasswordIDPType,
		Enabled:  true,
		Alias:    usernamePasswordIDPAlias,
		Config: model.IdentityProviderConfig{
			UsernameField: "preferredUsername",
		},
	}
	if err := s.storage.CreateIdentityProvider(ctx, newTenant.ID, defaultProvider); err != nil {
		return nil, err
	}

	if err := s.ensureAdminClient(ctx, newTenant.ID, domain); err != nil {
		return nil, err
	}

	return newTenant, nil
}

func (s *TenantBootstrapService) ensureAdminClient(ctx context.Context, tenantID uuid.UUID, domain string) error {
	_, err := s.storage.GetClient(ctx, tenantID, "admin_ui")
	if err == nil {
		return nil
	}
	if !errors.Is(err, port.ErrClientNotFound) {
		return err
	}

	adminClient := model.ClientApplication{
		ID:                     uuid.New().String(),
		TenantID:               tenantID,
		ClientID:               "admin_ui",
		ClientSecret:           nil,
		ClientName:             "Admin Interface",
		RedirectURIs:           []string{schemeHttp + domain + routeCallback, schemeHttps + domain + routeCallback},
		PostLogoutRedirectURIs: []string{schemeHttp + domain + routeAdmin, schemeHttps + domain + routeAdmin},
		GrantTypes:             []string{"authorization_code"},
		ResponseTypes:          []string{"code"},
		Algorithm:              model.AlgRS256,
		AccessTokenLifetime:    30 * time.Minute,
		RefreshTokenLifetime:   24 * time.Hour,
		IDTokenLifetime:        5 * time.Minute,
		AllowedScopes:          []string{"openid", "profile", "email"},
		DefaultScopes:          []string{"openid", "profile", "email"},
		AllowedIDPs:            []string{usernamePasswordIDPAlias},
		DefaultIDP:             usernamePasswordIDPAlias,
		AllowedAudiences:       []string{},
		ClientType:             model.ClientTypeInternalEphemeral,
	}

	return s.storage.SaveClient(ctx, adminClient)
}
