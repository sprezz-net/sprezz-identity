package service

import (
	"context"
	"fmt"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

type TenantService struct {
	storage      port.Storage
	adminStorage port.AdminStorage
	clock        port.Clock
	idpService   *IdentityProviderService
	appEnv       string
	adminDomain  string
}

// Explicitly assert that TenantService implements port.TenantUseCase
var _ port.TenantUseCase = (*TenantService)(nil)

// NewTenantService creates a fully initialized instance of the tenant coordinator.
func NewTenantService(
	storage port.Storage,
	adminStorage port.AdminStorage,
	cl port.Clock,
	idpService *IdentityProviderService,
	appEnv string,
	adminDomain string,
) *TenantService {
	return &TenantService{
		storage:      storage,
		adminStorage: adminStorage,
		clock:        cl,
		idpService:   idpService,
		appEnv:       appEnv,
		adminDomain:  adminDomain,
	}
}

func (s *TenantService) CreateTenant(ctx context.Context, cmd port.CreateTenantCommand) (*model.Tenant, error) {
	if cmd.TenantName == "" {
		return nil, fmt.Errorf("tenant name is required")
	}
	if cmd.DomainName == "" {
		return nil, fmt.Errorf("canonical domain is required")
	}

	scheme := model.SchemeHttps
	if s.appEnv == "local" {
		// Allow to listen on localhost for local development on non-secure port
		scheme = model.SchemeHttp
	}

	baseURL := scheme + "://" + cmd.DomainName
	newTenant := model.Tenant{
		ID:        uuid.New(),
		Name:      cmd.TenantName,
		Domain:    cmd.DomainName,
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
	if err := s.adminStorage.CreateTenant(ctx, newTenant); err != nil {
		return nil, err
	}

	// 2. Provision the administrative partition
	p2, err := s.adminStorage.CreatePartition(ctx, newTenant.ID, "Sprezz Admin", "sprezz_admin")
	if err != nil {
		return nil, fmt.Errorf("create sprezz admin partition: %w", err)
	}

	// 3. Secure the admin partition with an OIDC identity provider pointing to the root admin domain
	adminIssuerURL := scheme + s.adminDomain
	adminDiscoveryEndpoint := adminIssuerURL + "/.well-known/openid-configuration"

	idpConfig := model.IdentityProviderConfig{
		DiscoveryEndpoint: adminDiscoveryEndpoint,
		DCRMode:           model.DCRModeSoftwareStatement,
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
		Issuer:      adminIssuerURL,
		Config:      idpConfig,
	}

	// 6. Call the Identity Provider domain service to register the OIDC link safely
	_, err = s.idpService.CreateIdentityProvider(ctx, newTenant.ID, idp)
	if err != nil {
		return nil, fmt.Errorf("failed to broker secure administrative idp configuration: %w", err)
	}

	return &newTenant, nil
}

// ResolveTenantContext handles runtime domain-to-tenant verification mappings.
// It acts as the core business authority to validate if an incoming r.Host string
// belongs to an active, bootstrapped organization platform workspace.
func (s *TenantService) ResolveTenantContext(ctx context.Context, host string) (*model.Tenant, error) {
	if host == "" {
		return nil, fmt.Errorf("%w: host domain parameter cannot be empty", port.ErrInvalidRequest)
	}

	// Delegate the lookup strictly to the outbound storage port
	tenant, err := s.storage.ResolveTenantByDomain(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("tenant_service: domain %s not bootstrapped: %w", host, err)
	}

	return tenant, nil
}

func (s *TenantService) GetTenant(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
	return s.storage.ResolveTenantByUUID(ctx, id)
}

func (s *TenantService) GetAllTenants(ctx context.Context) ([]model.Tenant, error) {
	return s.adminStorage.GetAllTenants(ctx)
}

func (s *TenantService) ToggleSignup(ctx context.Context, id uuid.UUID, allow bool) (*model.Tenant, error) {
	tenant, err := s.storage.ResolveTenantByUUID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("tenant_service: toggle signup rejected, tenantID unresolvable: %w", err)
	}

	previousAllowSignup := tenant.Config.AllowSignup

	// 1. Check existing config
	if previousAllowSignup == allow {
		return tenant, nil
	}

	// 2. Toggle state within the domain boundary
	tenant.Config.AllowSignup = allow

	// 3. Force an atomic persistent database serialization update call via the outbound storage port
	if tenant, err = s.UpdateTenant(ctx, tenant.ID, "", "", tenant.Config); err != nil {
		return nil, fmt.Errorf("tenant_service: failed to commit signup registration state: %w", err)
	}

	// 4. Conditional Side-Effect: Only purge tokens if this is the Administrative Tenant
	// and signup is being closed (e.g., initial setup is complete).
	if tenant.Name == "Administrative Tenant" && previousAllowSignup && !allow {
		if err := s.storage.PurgeTenantSessionsAndTokens(ctx, tenant.ID); err != nil {
			return tenant, fmt.Errorf("tenant updated, but failed to purge admin sessions: %w", err)
		}
	}

	return tenant, nil
}

func (s *TenantService) UpdateTenant(ctx context.Context, id uuid.UUID, name, domain string, config model.TenantConfig) (*model.Tenant, error) {
	tenant, err := s.storage.ResolveTenantByUUID(ctx, id)
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

	if err := s.adminStorage.CreateTenant(ctx, *tenant); err != nil {
		return nil, err
	}

	return tenant, nil
}
