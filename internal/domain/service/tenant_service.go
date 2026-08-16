package service

import (
	"context"
	"fmt"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

type TenantService struct {
	storage     port.Storage
	clock       port.Clock
	idpService  *IdentityProviderService
	appEnv      string
	adminDomain string
}

func NewTenantService(storage port.Storage, cl port.Clock, idpService *IdentityProviderService, appEnv string, adminDomain string) *TenantService {
	return &TenantService{storage: storage, clock: cl, idpService: idpService, appEnv: appEnv, adminDomain: adminDomain}
}

func (s *TenantService) CreateTenant(ctx context.Context, name, domain string) (*model.Tenant, error) {
	if name == "" {
		return nil, fmt.Errorf("tenant name is required")
	}
	if domain == "" {
		return nil, fmt.Errorf("canonical domain is required")
	}

	scheme := model.SchemeHttps
	if s.appEnv == "local" {
		// Allow to listen on localhost for local development on non-secure port
		scheme = model.SchemeHttp
	}

	baseURL := scheme + "://" + domain
	newTenant := model.Tenant{
		ID:        uuid.New(),
		Name:      name,
		Domain:    domain,
		Scheme:    scheme,
		IsActive:  true,
		CreatedAt: s.clock.Now(),
		Config: model.TenantConfig{
			PredefinedScopes:    []string{"openid", "profile", "email", "offline_access"},
			PredefinedAudiences: []string{},
			DefaultRedirectURI:  baseURL,
			RedirectWhitelist:   []string{baseURL},
			ACRToLevels: map[string]model.Levels{
				"aal1": {AAL: 1},
				"ial1": {IAL: 1},
			},
			AllowSignup: false,
		},
	}

	// 1. Persist the new tenant first to get the ID for partition creation
	if err := s.storage.CreateTenant(ctx, newTenant); err != nil {
		return nil, err
	}

	// 2. Provision the default partition (Left completely clean, no default IDPs)
	p1, err := s.storage.CreatePartition(ctx, newTenant.ID, newTenant.Name, "default")
	if err != nil {
		return nil, fmt.Errorf("create default partition: %w", err)
	}

	// 3. Provision the administrative partition
	p2, err := s.storage.CreatePartition(ctx, newTenant.ID, "Sprezz Admin", "sprezz_admin")
	if err != nil {
		return nil, fmt.Errorf("create sprezz admin partition: %w", err)
	}

	// 4. Link back the root default reference to the base tenant context
	newTenant.DefaultPartition = &p1.ID
	if err := s.storage.CreateTenant(ctx, newTenant); err != nil {
		return nil, fmt.Errorf("update tenant default partition: %w", err)
	}

	// 5. Secure the admin partition with an OIDC identity provider pointing to the root admin domain
	adminIssuerURL := scheme + s.adminDomain
	adminDiscoveryEndpoint := adminIssuerURL + "/.well-known/openid-configuration"

	idpConfig := model.IdentityProviderConfig{
		Issuer:            adminIssuerURL,
		DiscoveryEndpoint: adminDiscoveryEndpoint,
		DCRMode:           model.DCRModeAuthenticated,
		Scopes:            []string{"openid", "profile", "email"},
	}

	idp := model.IdentityProvider{
		ID:          uuid.New(),
		TenantID:    newTenant.ID,
		IDPType:     model.OpenIDConnectIDPType,
		Enabled:     true,
		Alias:       "admin-sso",
		Name:        "Administrative SSO",
		PartitionID: p2.ID,
		IssuerURL:   adminIssuerURL,
		Config:      idpConfig,
	}

	// 6. Call the Identity Provider domain service to register the OIDC link safely
	_, err = s.idpService.CreateIdentityProvider(ctx, newTenant.ID, idp)
	if err != nil {
		return nil, fmt.Errorf("failed to broker secure administrative idp configuration: %w", err)
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

	// 1. Toggle state within the domain boundary
	tenant.Config.AllowSignup = !tenant.Config.AllowSignup

	// 2. Persist the updated configuration first
	// We can update tenant by calling CreateTenant since ON CONFLICT (tenant_uuid) DO UPDATE is used
	if err := s.storage.CreateTenant(ctx, *tenant); err != nil {
		return nil, err
	}

	// 3. Conditional Side-Effect: Only purge tokens if this is the Administrative Tenant
	// and signup is being closed (e.g., initial setup is complete).
	if tenant.Name == "Administrative Tenant" && !tenant.Config.AllowSignup {
		if err := s.storage.PurgeTenantSessionsAndTokens(ctx, tenant.ID); err != nil {
			return tenant, fmt.Errorf("tenant updated, but failed to purge admin bootstrap sessions: %w", err)
		}
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
	if tenant.Config.PredefinedScopes == nil {
		tenant.Config.PredefinedScopes = []string{"openid", "profile", "email", "offline_access"}
	}
	if tenant.Config.PredefinedAudiences == nil {
		tenant.Config.PredefinedAudiences = []string{}
	}
	if tenant.Config.RedirectWhitelist == nil {
		tenant.Config.RedirectWhitelist = []string{}
	}
	if tenant.Config.ACRToLevels == nil {
		tenant.Config.ACRToLevels = map[string]model.Levels{}
	}

	if err := s.storage.CreateTenant(ctx, *tenant); err != nil {
		return nil, err
	}

	return tenant, nil
}
