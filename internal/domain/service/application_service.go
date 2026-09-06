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

// ApplicationService implements port.AdminApplicationUseCase
type ApplicationService struct {
	storage      port.Storage
	adminStorage port.AdminStorage
	clock        port.Clock
	crypto       port.Crypto
}

// NewApplicationService creates a new instance of ApplicationService
func NewApplicationService(
	s port.Storage,
	as port.AdminStorage,
	clk port.Clock,
	cr port.Crypto,
) *ApplicationService {
	return &ApplicationService{
		storage:      s,
		adminStorage: as,
		clock:        clk,
		crypto:       cr,
	}
}

// GetApplicationDashboard retrieves multi-table summaries, security profiles, and routing groups for a tenant.
func (s *ApplicationService) GetApplicationDashboard(ctx context.Context, tenantID uuid.UUID) ([]model.ApplicationSummary, []model.ApplicationProfile, []model.ApplicationGroup, error) {
	staticSummaries, err := s.adminStorage.GetStaticApplicationsSummary(ctx, tenantID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed retrieving static applications summaries: %w", err)
	}

	dynamicSummaries, err := s.adminStorage.GetDynamicApplicationsSummary(ctx, tenantID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed retrieving dynamic applications summaries: %w", err)
	}

	allSummaries := append([]model.ApplicationSummary{}, staticSummaries...)
	allSummaries = append(allSummaries, dynamicSummaries...)

	profiles, err := s.adminStorage.GetApplicationProfiles(ctx, tenantID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed retrieving application profiles: %w", err)
	}

	groups, err := s.adminStorage.GetApplicationGroups(ctx, tenantID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed retrieving application groups: %w", err)
	}

	return allSummaries, profiles, groups, nil
}

// GetApplicationDetails resolves and aggregates a single application layout.
func (s *ApplicationService) GetApplicationDetails(ctx context.Context, tenantID uuid.UUID, clientID string) (*model.ApplicationDetailsProps, error) {
	app, profile, group, err := s.storage.GetApplicationByClientID(ctx, tenantID, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving application details: %w", err)
	}

	return &model.ApplicationDetailsProps{
		Application:        app,
		ApplicationProfile: profile,
		ApplicationGroup:   group,
	}, nil
}

// CreateApplication creates a standalone application entity linking to standalones profiles and groups.
func (s *ApplicationService) CreateApplication(ctx context.Context, cmd port.CreateApplicationCommand) (*model.Application, string, error) {
	profile, err := s.adminStorage.GetApplicationProfileByID(ctx, cmd.TenantID, cmd.ProfileID)
	if err != nil {
		return nil, "", fmt.Errorf("failed resolving application profile: %w", err)
	}

	var plaintextSecret string
	var hashedSecret *string

	if profile.TokenEndpointAuthMethod != model.AuthMethodNone {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			return nil, "", fmt.Errorf("failed to generate secure random bytes: %w", err)
		}
		plaintextSecret = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)

		hash, err := s.crypto.HashCredential(plaintextSecret)
		if err != nil {
			return nil, "", fmt.Errorf("failed to hash secure client secret: %w", err)
		}
		hashedSecret = &hash
	}

	app := model.Application{
		ID:               uuid.New(),
		TenantID:         cmd.TenantID,
		ProfileID:        cmd.ProfileID,
		GroupID:          cmd.GroupID,
		ApplicationName:  cmd.ApplicationName,
		IsEnabled:        true,
		ClientID:         cmd.ClientID,
		ClientSecretHash: hashedSecret,
		IsDynamic:        false,
		CreatedAt:        s.clock.Now(),
		UpdatedAt:        s.clock.Now(),
	}

	if err := s.adminStorage.CreateApplication(ctx, cmd.TenantID, app); err != nil {
		return nil, "", fmt.Errorf("failed persisting application metadata: %w", err)
	}

	return &app, plaintextSecret, nil
}

// UpdateApplication modifies standalone application metadata.
func (s *ApplicationService) UpdateApplication(ctx context.Context, cmd port.UpdateApplicationCommand) error {
	existingApp, _, _, err := s.storage.GetApplicationByClientID(ctx, cmd.TenantID, cmd.ClientID)
	if err != nil {
		return fmt.Errorf("failed locating existing application: %w", err)
	}

	app := model.Application{
		ID:               existingApp.ID,
		TenantID:         cmd.TenantID,
		ProfileID:        cmd.ProfileID,
		GroupID:          cmd.GroupID,
		ApplicationName:  cmd.ApplicationName,
		IsEnabled:        cmd.IsEnabled,
		ClientID:         cmd.ClientID,
		ClientSecretHash: existingApp.ClientSecretHash,
		IsDynamic:        existingApp.IsDynamic,
		UpdatedAt:        s.clock.Now(),
	}

	if err := s.adminStorage.UpdateApplication(ctx, cmd.TenantID, cmd.ClientID, app); err != nil {
		return fmt.Errorf("failed updating application: %w", err)
	}

	return nil
}

// DeleteApplication deletes a standalone application.
func (s *ApplicationService) DeleteApplication(ctx context.Context, tenantID uuid.UUID, clientID string) error {
	if err := s.adminStorage.DeleteApplication(ctx, tenantID, clientID); err != nil {
		return fmt.Errorf("failed executing application removal: %w", err)
	}
	return nil
}

// ToggleApplicationStatus toggles the IsEnabled state of an application.
func (s *ApplicationService) ToggleApplicationStatus(ctx context.Context, tenantID uuid.UUID, clientID string) (*model.Application, error) {
	app, _, _, err := s.storage.GetApplicationByClientID(ctx, tenantID, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving application for status toggle: %w", err)
	}

	app.IsEnabled = !app.IsEnabled
	app.UpdatedAt = s.clock.Now()

	if err := s.adminStorage.UpdateApplication(ctx, tenantID, clientID, *app); err != nil {
		return nil, fmt.Errorf("failed persisting application status toggle: %w", err)
	}

	return app, nil
}

// ResetApplicationSecret rotates credentials for confidential applications.
func (s *ApplicationService) ResetApplicationSecret(ctx context.Context, tenantID uuid.UUID, clientID string) (string, error) {
	app, profile, _, err := s.storage.GetApplicationByClientID(ctx, tenantID, clientID)
	if err != nil {
		return "", fmt.Errorf("failed retrieving target application: %w", err)
	}

	// Public clients (TokenEndpointAuthMethod == none) cannot have secrets
	if profile.TokenEndpointAuthMethod == model.AuthMethodNone {
		return "", fmt.Errorf("cannot reset secret of a public native application")
	}

	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure random bytes: %w", err)
	}
	plaintextSecret := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)

	hash, err := s.crypto.HashCredential(plaintextSecret)
	if err != nil {
		return "", fmt.Errorf("failed to hash generated secret: %w", err)
	}

	app.ClientSecretHash = &hash
	app.UpdatedAt = s.clock.Now()

	if err := s.adminStorage.UpdateApplication(ctx, tenantID, clientID, *app); err != nil {
		return "", fmt.Errorf("failed to persist updated application secret: %w", err)
	}

	return plaintextSecret, nil
}

// GetProfiles lists standalone security profiles.
func (s *ApplicationService) GetProfiles(ctx context.Context, tenantID uuid.UUID) ([]model.ApplicationProfile, error) {
	return s.adminStorage.GetApplicationProfiles(ctx, tenantID)
}

// GetProfile fetches a single security profile by ID.
func (s *ApplicationService) GetProfile(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.ApplicationProfile, error) {
	return s.adminStorage.GetApplicationProfileByID(ctx, tenantID, id)
}

// CreateProfile creates a standalone profile, programmatically enforcing RTR for public clients.
func (s *ApplicationService) CreateProfile(ctx context.Context, cmd port.CreateProfileCommand) error {
	enforceRTR := cmd.EnforceRTR
	if cmd.TokenEndpointAuthMethod == model.AuthMethodNone {
		enforceRTR = true
	}

	profile := model.ApplicationProfile{
		ID:                      uuid.New(),
		TenantID:                cmd.TenantID,
		ProfileName:             cmd.ProfileName,
		IsEnabled:               true,
		TokenEndpointAuthMethod: cmd.TokenEndpointAuthMethod,
		GrantTypes:              cmd.GrantTypes,
		ResponseTypes:           cmd.ResponseTypes,
		AccessTokenLifetime:     cmd.AccessTokenLifetime,
		RefreshTokenLifetime:    cmd.RefreshTokenLifetime,
		IDTokenLifetime:         cmd.IDTokenLifetime,
		EnforceRTR:              enforceRTR,
		SigningAlgorithm:        cmd.SigningAlgorithm,
		CreatedAt:               s.clock.Now(),
		UpdatedAt:               s.clock.Now(),
	}

	return s.adminStorage.CreateApplicationProfile(ctx, cmd.TenantID, profile)
}

// UpdateProfile updates an existing standalone profile, programmatically enforcing RTR for public clients.
func (s *ApplicationService) UpdateProfile(ctx context.Context, cmd port.UpdateProfileCommand) error {
	enforceRTR := cmd.EnforceRTR
	if cmd.TokenEndpointAuthMethod == model.AuthMethodNone {
		enforceRTR = true
	}

	profile := model.ApplicationProfile{
		ID:                      cmd.ID,
		TenantID:                cmd.TenantID,
		ProfileName:             cmd.ProfileName,
		IsEnabled:               true,
		TokenEndpointAuthMethod: cmd.TokenEndpointAuthMethod,
		GrantTypes:              cmd.GrantTypes,
		ResponseTypes:           cmd.ResponseTypes,
		AccessTokenLifetime:     cmd.AccessTokenLifetime,
		RefreshTokenLifetime:    cmd.RefreshTokenLifetime,
		IDTokenLifetime:         cmd.IDTokenLifetime,
		EnforceRTR:              enforceRTR,
		SigningAlgorithm:        cmd.SigningAlgorithm,
		UpdatedAt:               s.clock.Now(),
	}

	return s.adminStorage.UpdateApplicationProfile(ctx, cmd.TenantID, profile)
}

// GetGroups lists standalone routing groups.
func (s *ApplicationService) GetGroups(ctx context.Context, tenantID uuid.UUID) ([]model.ApplicationGroup, error) {
	return s.adminStorage.GetApplicationGroups(ctx, tenantID)
}

// GetGroup fetches a standalone group.
func (s *ApplicationService) GetGroup(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*model.ApplicationGroup, error) {
	return s.adminStorage.GetApplicationGroupByID(ctx, tenantID, id)
}

// CreateGroup creates a standalone routing group.
func (s *ApplicationService) CreateGroup(ctx context.Context, cmd port.CreateGroupCommand) error {
	group := model.ApplicationGroup{
		ID:                     uuid.New(),
		TenantID:               cmd.TenantID,
		GroupName:              cmd.GroupName,
		IsEnabled:              true,
		RedirectURIs:           cmd.RedirectURIs,
		PostLogoutRedirectURIs: cmd.PostLogoutRedirectURIs,
		FrontChannelLogoutURI:  cmd.FrontChannelLogoutURI,
		BackChannelLogoutURI:   cmd.BackChannelLogoutURI,
		AllowedScopes:          cmd.AllowedScopes,
		DefaultScopes:          cmd.DefaultScopes,
		AllowedAudiences:       cmd.AllowedAudiences,
		AllowedIDPIDs:          cmd.AllowedIDPIDs,
		DefaultIDPID:           cmd.DefaultIDPID,
		CreatedAt:              s.clock.Now(),
		UpdatedAt:              s.clock.Now(),
	}

	return s.adminStorage.CreateApplicationGroup(ctx, cmd.TenantID, group)
}

// UpdateGroup updates an existing standalone routing group.
func (s *ApplicationService) UpdateGroup(ctx context.Context, cmd port.UpdateGroupCommand) error {
	group := model.ApplicationGroup{
		ID:                     cmd.ID,
		TenantID:               cmd.TenantID,
		GroupName:              cmd.GroupName,
		IsEnabled:              true,
		RedirectURIs:           cmd.RedirectURIs,
		PostLogoutRedirectURIs: cmd.PostLogoutRedirectURIs,
		FrontChannelLogoutURI:  cmd.FrontChannelLogoutURI,
		BackChannelLogoutURI:   cmd.BackChannelLogoutURI,
		AllowedScopes:          cmd.AllowedScopes,
		DefaultScopes:          cmd.DefaultScopes,
		AllowedAudiences:       cmd.AllowedAudiences,
		AllowedIDPIDs:          cmd.AllowedIDPIDs,
		DefaultIDPID:           cmd.DefaultIDPID,
		UpdatedAt:              s.clock.Now(),
	}

	return s.adminStorage.UpdateApplicationGroup(ctx, cmd.TenantID, group)
}
