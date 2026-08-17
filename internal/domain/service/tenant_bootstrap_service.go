package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

const (
	routeAdmin               = "/admin"
	routeCallback            = "/admin/callback"
	usernamePasswordIDPAlias = "username-password"
)

// TenantBootstrapService is the domain-level orchestration point that ensures
// the configured admin tenant domain resolves to a tenant record.
type TenantBootstrapService struct {
	storage port.Storage
	clock   port.Clock
	appEnv  string
}

func NewTenantBootstrapService(storage port.Storage, cl port.Clock, appEnv string) *TenantBootstrapService {
	return &TenantBootstrapService{storage: storage, clock: cl, appEnv: appEnv}
}

func (s *TenantBootstrapService) BootstrapAdminTenant(ctx context.Context, domain string) (*model.Tenant, error) {
	tenant, err := s.storage.ResolveTenantByDomain(ctx, domain)
	if err == nil {
		return s.bootstrapExistingTenant(ctx, tenant, domain)
	}

	if !errors.Is(err, port.ErrTenantNotFound) {
		return nil, err
	}

	return s.bootstrapNewTenant(ctx, domain)
}

func (s *TenantBootstrapService) bootstrapExistingTenant(ctx context.Context, tenant *model.Tenant, domain string) (*model.Tenant, error) {
	baseURL := tenant.GetBaseURI()
	expectedRedirect := baseURL + routeAdmin
	if tenant.Config.DefaultRedirectURI != expectedRedirect {
		tenant.Config.DefaultRedirectURI = expectedRedirect
		tenant.Config.RedirectWhitelist = []string{baseURL + routeAdmin, baseURL + routeCallback}
		if err := s.storage.CreateTenant(ctx, *tenant); err != nil {
			return nil, err
		}
	}

	// Add local username-password identity provider if not present
	if err := s.ensureDefaultIdentityProvider(ctx, tenant.ID); err != nil {
		return nil, err
	}

	if err := s.ensureAdminClient(ctx, tenant.ID, domain); err != nil {
		return nil, err
	}

	return tenant, nil
}

func (s *TenantBootstrapService) bootstrapNewTenant(ctx context.Context, domain string) (*model.Tenant, error) {
	scheme := model.SchemeHttps
	if s.appEnv == "local" {
		// Allow to listen on localhost for local development on non-secure port
		scheme = model.SchemeHttp
	}
	baseURL := scheme + "://" + domain
	newTenant := &model.Tenant{
		ID:        uuid.New(),
		Name:      "Administrative Tenant",
		Domain:    domain,
		Scheme:    scheme,
		IsActive:  true,
		CreatedAt: s.clock.Now(),
		Config: model.TenantConfig{
			PredefinedScopes:    []string{"openid", "profile", "email", "offline_access"},
			PredefinedAudiences: []string{},
			DefaultRedirectURI:  baseURL + routeAdmin,
			RedirectWhitelist:   []string{baseURL + routeAdmin, baseURL + routeCallback},
			ACRToLevels: map[string]model.Levels{
				"aal1": {AAL: 1},
				"ial1": {IAL: 1},
			},
			AllowSignup: true,
		},
	}

	if err := s.storage.CreateTenant(ctx, *newTenant); err != nil {
		return nil, err
	}

	p1, err := s.storage.CreatePartition(ctx, newTenant.ID, newTenant.Name, "default")
	if err != nil {
		return nil, fmt.Errorf("create default partition: %w", err)
	}

	newTenant.DefaultPartition = &p1.ID
	if err := s.storage.CreateTenant(ctx, *newTenant); err != nil {
		return nil, fmt.Errorf("update tenant default partition: %w", err)
	}

	if err := s.ensureDefaultIdentityProvider(ctx, newTenant.ID); err != nil {
		return nil, err
	}

	if err := s.ensureAdminClient(ctx, newTenant.ID, domain); err != nil {
		return nil, err
	}

	return newTenant, nil
}

func (s *TenantBootstrapService) ensureDefaultIdentityProvider(ctx context.Context, tenantID uuid.UUID) error {
	providers, err := s.storage.GetEnabledIdentityProviders(ctx, tenantID)
	if err == nil && len(providers) > 0 {
		return nil
	}

	tenant, err := s.storage.ResolveTenantByID(ctx, tenantID)
	if err != nil {
		return err
	}

	var partitionID int64
	if tenant.DefaultPartition != nil {
		partitionID = *tenant.DefaultPartition
	} else {
		parts, err := s.storage.GetPartitions(ctx, tenantID)
		if err != nil || len(parts) == 0 {
			return fmt.Errorf("no partitions found for tenant: %w", err)
		}
		partitionID = parts[0].ID
	}

	defaultProvider := model.IdentityProvider{
		ID:          uuid.New(),
		TenantID:    tenantID,
		IDPType:     model.UsernamePasswordIDPType,
		Enabled:     true,
		Alias:       usernamePasswordIDPAlias,
		Name:        "Local Accounts",
		PartitionID: partitionID,
		Config: model.IdentityProviderConfig{
			UsernameField: "preferredUsername",
		},
	}
	return s.storage.CreateIdentityProvider(ctx, tenantID, defaultProvider)
}

func (s *TenantBootstrapService) ensureAdminClient(ctx context.Context, tenantID uuid.UUID, domain string) error {
	_, err := s.storage.GetClient(ctx, tenantID, "admin_ui")
	if err == nil {
		return nil
	}
	if !errors.Is(err, port.ErrClientNotFound) {
		return err
	}

	scheme := model.SchemeHttps
	if s.appEnv == "local" {
		// Allow to listen on localhost for local development on non-secure port
		scheme = model.SchemeHttp
	}

	adminClient := model.ClientApplication{
		ID:                     uuid.New().String(),
		TenantID:               tenantID,
		ClientID:               "admin_ui",
		ClientSecret:           nil,
		ClientName:             "Admin Interface",
		RedirectURIs:           []string{scheme + domain + routeCallback},
		PostLogoutRedirectURIs: []string{scheme + domain + routeAdmin},
		GrantTypes:             []string{"authorization_code"},
		ResponseTypes:          []string{"code"},
		Algorithm:              model.AlgRS256,
		AccessTokenLifetime:    900 * time.Second,
		IDTokenLifetime:        900 * time.Second,
		RefreshTokenLifetime:   1209600 * time.Second,
		AllowedScopes:          []string{"openid", "profile", "email"},
		DefaultScopes:          []string{"openid", "profile", "email"},
		AllowedIDPs:            []string{usernamePasswordIDPAlias},
		DefaultIDP:             usernamePasswordIDPAlias,
		AllowedAudiences:       []string{},
		ClientType:             model.ClientTypePublic,
	}

	return s.storage.SaveClient(ctx, adminClient)
}
