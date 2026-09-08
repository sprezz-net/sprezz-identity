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
	usernamePasswordIDPAlias = "username-password"
)

// TenantBootstrapService is the domain-level orchestration point that ensures
// the configured admin tenant domain resolves to a tenant record.
type TenantBootstrapService struct {
	storage       port.Storage
	adminStorage  port.AdminStorage
	tenantUseCase port.TenantUseCase
	clock         port.Clock
	appEnv        string
}

func NewTenantBootstrapService(
	storage port.Storage,
	adminStorage port.AdminStorage,
	tenantUseCase port.TenantUseCase,
	cl port.Clock,
	appEnv string,
) *TenantBootstrapService {
	return &TenantBootstrapService{
		storage:       storage,
		adminStorage:  adminStorage,
		tenantUseCase: tenantUseCase,
		clock:         cl,
		appEnv:        appEnv,
	}
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

	expectedRedirect := baseURL + port.RouteAdmin
	if tenant.Config.DefaultRedirectURI != expectedRedirect {
		tenant.Config.DefaultRedirectURI = expectedRedirect
		tenant.Config.RedirectWhitelist = []string{baseURL + port.RouteAdmin, baseURL + port.RouteFederationCallback}
		if err := s.adminStorage.CreateTenant(ctx, *tenant); err != nil {
			return nil, err
		}
	}

	if tenant.DefaultPartition == nil || *tenant.DefaultPartition == 0 {
		parts, err := s.storage.GetPartitions(ctx, tenant.ID)
		if err == nil && len(parts) > 0 {
			partID := parts[0].ID
			tenant.DefaultPartition = &partID
			if err := s.adminStorage.CreateTenant(ctx, *tenant); err != nil {
				return nil, err
			}
		}
	}

	if err := s.ensureDefaultIdentityProvider(ctx, tenant.ID); err != nil {
		return nil, err
	}

	if err := s.ensureAdminApplicationProfileAndGroup(ctx, tenant.ID, domain); err != nil {
		return nil, err
	}

	return tenant, nil
}

func (s *TenantBootstrapService) bootstrapNewTenant(ctx context.Context, domain string) (*model.Tenant, error) {
	cmd := port.CreateTenantCommand{
		TenantName:  "Administrative Tenant",
		DomainName:  domain,
		AllowSignup: false,
	}

	// 1. Delegate creation natively down to the TenantUseCase driving port execution path
	// This automatically persists the tenant, resolves postgres trigger partitions,
	// creates the "sprezz_admin" partition, and hooks up the "admin-sso" identity link.
	createdTenant, err := s.tenantUseCase.CreateTenant(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: failed to delegate root tenant creation sequence: %w", err)
	}

	// 2. STAGE 2: Apply master-tenant specific configurations overriding standard business ceilings [5.7]
	createdTenant.Config.AllowSignup = true
	createdTenant.Config.DefaultRedirectURI = createdTenant.GetBaseURI() + port.RouteAdmin
	createdTenant.Config.RedirectWhitelist = []string{
		createdTenant.GetBaseURI() + port.RouteAdmin,
		createdTenant.GetBaseURI() + port.RouteFederationCallback,
	}
	createdTenant.Config.DCRMode = model.DCRModeSoftwareStatement
	createdTenant.Config.PublicSoftwareStatement = model.AdminUIProfileName + ";" + model.LocalAdminUIGroupName

	// Save the administrative parameter adjustments back to storage
	if err := s.adminStorage.CreateTenant(ctx, *createdTenant); err != nil {
		return nil, fmt.Errorf("bootstrap: failed to finalize master tenant configuration: %w", err)
	}

	// 3. STAGE 3: Build local password directories inside the implicit default partition layout
	if err := s.ensureDefaultIdentityProvider(ctx, createdTenant.ID); err != nil {
		return nil, err
	}

	// 4. STAGE 4: Register client application profile entities for the platform control UI panels
	if err := s.ensureAdminApplicationProfileAndGroup(ctx, createdTenant.ID, domain); err != nil {
		return nil, err
	}

	return s.storage.ResolveTenantByUUID(ctx, createdTenant.ID)
}

func (s *TenantBootstrapService) ensureDefaultIdentityProvider(ctx context.Context, tenantID uuid.UUID) error {
	providers, err := s.storage.GetEnabledIdentityProviders(ctx, tenantID)
	if err == nil {
		for _, p := range providers {
			if p.IDPType == model.UsernamePasswordIDPType {
				return nil
			}
		}
	}

	tenant, err := s.storage.ResolveTenantByUUID(ctx, tenantID)
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
			AAL:           1,
			IAL:           1,
		},
	}
	return s.adminStorage.CreateIdentityProvider(ctx, tenantID, defaultProvider)
}

// ensureAdminApplicationGroupAndProfile provisions the multi-table profile, group, and app layers.
func (s *TenantBootstrapService) ensureAdminApplicationProfileAndGroup(ctx context.Context, tenantID uuid.UUID, domain string) error {
	// 1. Verify whether the admin client already exists within the decoupled database tables
	_, _, _, err := s.storage.GetApplicationByClientID(ctx, tenantID, "admin_ui")
	if err == nil {
		return nil
	}
	if !errors.Is(err, port.ErrApplicationNotFound) {
		return err
	}

	// 2. Load the newly provisioned Local Accounts Identity Provider to capture its UUID key
	providers, err := s.storage.GetEnabledIdentityProviders(ctx, tenantID)
	if err != nil || len(providers) == 0 {
		return fmt.Errorf("bootstrap admin group: unable to resolve default identity provider context: %w", err)
	}

	// Correctly resolve the local username-password provider and any admin-sso federated provider
	var localProviderUUID uuid.UUID
	var adminSsoProviderUUID uuid.UUID
	for _, p := range providers {
		if p.IDPType == model.UsernamePasswordIDPType {
			localProviderUUID = p.ID
		} else if p.Alias == "admin-sso" && p.IDPType == model.OpenIDConnectIDPType {
			adminSsoProviderUUID = p.ID
		}
	}

	if localProviderUUID == uuid.Nil {
		return fmt.Errorf("bootstrap admin group: local username-password identity provider not found")
	}

	scheme := model.SchemeHttps
	if s.appEnv == "local" {
		scheme = model.SchemeHttp
	}

	profileID := uuid.New()
	adminGroupID := uuid.New()
	localGroupID := uuid.New()

	// 3. Build the Global Platform Application Profile for the Admin Hub
	adminProfile := model.ApplicationProfile{
		ID:                      profileID,
		TenantID:                tenantID,
		ProfileName:             model.AdminUIProfileName,
		IsEnabled:               true,
		TokenEndpointAuthMethod: model.AuthMethodNone, // Public SPA Frontend
		GrantTypes:              []model.GrantType{model.GrantTypeAuthorizationCode, model.GrantTypeRefreshToken},
		ResponseTypes:           []model.ResponseType{model.ResponseTypeCode},
		AccessTokenLifetime:     900 * time.Second,
		IDTokenLifetime:         900 * time.Second,
		RefreshTokenLifetime:    1209600 * time.Second,
		EnforceRTR:              true,
		SigningAlgorithm:        model.AlgRS256,
	}

	// 4. Build the Federated OIDC Application Authorization Group for Dynamic Registrations
	var allowedAdminIDPs []uuid.UUID
	if adminSsoProviderUUID != uuid.Nil {
		allowedAdminIDPs = []uuid.UUID{adminSsoProviderUUID}
	}
	adminGroup := model.ApplicationGroup{
		ID:                     adminGroupID,
		TenantID:               tenantID,
		GroupName:              model.AdminUIGroupName,
		IsEnabled:              true,
		AllowedScopes:          []string{"openid", "profile", "email", "offline_access"},
		DefaultScopes:          []string{"openid", "profile", "email"},
		AllowedAudiences:       []string{},
		AllowedIDPIDs:          allowedAdminIDPs,
		DefaultIDPID:           &adminSsoProviderUUID,
		RedirectURIs:           []string{scheme + "://" + domain + port.RouteFederationCallback},
		PostLogoutRedirectURIs: []string{scheme + "://" + domain + port.RouteAdmin},
	}

	// 4.5. Build the Local Application Authorization Group for direct Admin Portal login
	localGroup := model.ApplicationGroup{
		ID:                     localGroupID,
		TenantID:               tenantID,
		GroupName:              model.LocalAdminUIGroupName,
		IsEnabled:              true,
		AllowedScopes:          []string{"openid", "profile", "email", "offline_access"},
		DefaultScopes:          []string{"openid", "profile", "email"},
		AllowedAudiences:       []string{},
		AllowedIDPIDs:          []uuid.UUID{localProviderUUID},
		DefaultIDPID:           &localProviderUUID,
		RedirectURIs:           []string{scheme + "://" + domain + port.RouteFederationCallback},
		PostLogoutRedirectURIs: []string{scheme + "://" + domain + port.RouteAdmin},
	}

	// 5. Build the core Application Instance referencing the federated OIDC group
	adminApp := model.Application{
		ID:               uuid.New(),
		TenantID:         tenantID,
		ProfileID:        profileID,
		GroupID:          adminGroupID, // Bound to the federated OIDC group (admin-sso)
		ClientID:         "admin_ui",
		ClientSecretHash: nil, // Public client mapping
		ApplicationName:  "Admin Interface",
		IsEnabled:        true,
	}

	// 6. Commit everything cleanly through the explicit tenant-bounded signatures
	if err := s.adminStorage.CreateApplicationProfile(ctx, tenantID, adminProfile); err != nil {
		return fmt.Errorf("bootstrap admin profile: %w", err)
	}

	if err := s.adminStorage.CreateApplicationGroup(ctx, tenantID, adminGroup); err != nil {
		return fmt.Errorf("bootstrap admin group: %w", err)
	}

	if err := s.adminStorage.CreateApplicationGroup(ctx, tenantID, localGroup); err != nil {
		return fmt.Errorf("bootstrap local admin group: %w", err)
	}

	if err := s.adminStorage.CreateApplication(ctx, tenantID, adminApp); err != nil {
		return fmt.Errorf("bootstrap admin application instance: %w", err)
	}

	return nil
}
