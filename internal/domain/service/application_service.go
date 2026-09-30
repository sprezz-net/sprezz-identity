package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"

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
func (s *ApplicationService) CreateApplication(ctx context.Context, cmd port.CreateApplicationCommand) (*model.Application, error) {
	if cmd.OnDelivery == nil {
		return nil, errors.New("application_service: delivery callback is required for application creation")
	}

	profile, err := s.adminStorage.GetApplicationProfileByID(ctx, cmd.TenantID, cmd.ProfileID)
	if err != nil {
		return nil, fmt.Errorf("failed resolving application profile: %w", err)
	}

	var plaintextSecret string
	var hashedSecret *string

	if profile.TokenEndpointAuthMethod != model.AuthMethodNone {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			return nil, fmt.Errorf("failed to generate secure random bytes: %w", err)
		}
		plaintextSecret = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)

		hash, err := s.crypto.HashCredential(plaintextSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to hash secure client secret: %w", err)
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

	// Execute within a strict outbound database transaction closure boundary pattern
	txErr := s.storage.InTransaction(ctx, func(txRepo port.Storage) error {
		// Use the transaction-scoped repository to stage records securely before committing
		txAdminStorage, ok := txRepo.(port.AdminStorage)
		if !ok {
			return fmt.Errorf("application_service: storage repository context type assertion failure")
		}

		if errSave := txAdminStorage.CreateApplication(ctx, cmd.TenantID, app); errSave != nil {
			return fmt.Errorf("failed persisting application metadata: %w", errSave)
		}

		// Transfer control temporarily over to the inbound transport boundary.
		// If socket stream delivery fails here, it returns an error and forces a hard DB ROLLBACK.
		if errDelivery := cmd.OnDelivery(plaintextSecret); errDelivery != nil {
			return fmt.Errorf("transport_layer_delivery_interrupted_enforcing_rollback: %w", errDelivery)
		}

		return nil // Staging success: transaction is finalized cleanly
	})

	if txErr != nil {
		return nil, txErr
	}

	return &app, nil
}

// UpdateApplication modifies standalone application metadata.
func (s *ApplicationService) UpdateApplication(ctx context.Context, cmd port.UpdateApplicationCommand) error {
	existingApp, _, _, err := s.storage.GetApplicationByClientID(ctx, cmd.TenantID, cmd.ClientID)
	if err != nil {
		return fmt.Errorf("failed locating existing application: %w", err)
	}
	if existingApp.IsSystem {
		return port.ErrSystemManaged
	}

	// A nil enabled flag preserves the stored state so a plain edit never re-enables a disabled application.
	isEnabled := existingApp.IsEnabled
	if cmd.IsEnabled != nil {
		isEnabled = *cmd.IsEnabled
	}

	app := model.Application{
		ID:               existingApp.ID,
		TenantID:         cmd.TenantID,
		ProfileID:        cmd.ProfileID,
		GroupID:          cmd.GroupID,
		ApplicationName:  cmd.ApplicationName,
		IsEnabled:        isEnabled,
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
	app, _, _, err := s.storage.GetApplicationByClientID(ctx, tenantID, clientID)
	if err != nil {
		return fmt.Errorf("failed locating application for removal: %w", err)
	}
	if app.IsSystem {
		return port.ErrSystemManaged
	}

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
	if app.IsSystem {
		return nil, port.ErrSystemManaged
	}

	app.IsEnabled = !app.IsEnabled
	app.UpdatedAt = s.clock.Now()

	if err := s.adminStorage.UpdateApplication(ctx, tenantID, clientID, *app); err != nil {
		return nil, fmt.Errorf("failed persisting application status toggle: %w", err)
	}

	return app, nil
}

// ResetApplicationSecret rotates credentials for confidential applications inside an open transaction loop.
func (s *ApplicationService) ResetApplicationSecret(ctx context.Context, cmd port.ResetApplicationSecretCommand) error {
	if cmd.OnDelivery == nil {
		return errors.New("application_service: delivery callback is required for secret rotation")
	}

	// 1. Interrogate core state records via the pre-compiled command properties
	app, profile, _, err := s.storage.GetApplicationByClientID(ctx, cmd.TenantID, cmd.ClientID)
	if err != nil {
		return fmt.Errorf("failed retrieving target application: %w", err)
	}
	if app.IsSystem {
		return port.ErrSystemManaged
	}

	// 2. Protocol Validation Gate: Public clients (TokenEndpointAuthMethod == none) cannot possess secrets
	if profile.TokenEndpointAuthMethod == model.AuthMethodNone {
		return fmt.Errorf("cannot reset secret of a public native application")
	}

	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Errorf("failed to generate secure random bytes: %w", err)
	}
	plaintextSecret := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)

	hash, err := s.crypto.HashCredential(plaintextSecret)
	if err != nil {
		return fmt.Errorf("failed to hash generated secret: %w", err)
	}

	app.ClientSecretHash = &hash
	app.UpdatedAt = s.clock.Now()

	// 3. Transaction Boundary: Staging state records securely before committing
	txErr := s.storage.InTransaction(ctx, func(txRepo port.Storage) error {
		txAdminStorage, ok := txRepo.(port.AdminStorage)
		if !ok {
			return fmt.Errorf("application_service: storage repository context type assertion failure")
		}

		if errUpdate := txAdminStorage.UpdateApplication(ctx, cmd.TenantID, cmd.ClientID, *app); errUpdate != nil {
			return fmt.Errorf("failed to persist updated application secret: %w", errUpdate)
		}

		// 4. THE HANDSHAKE HOOK: Transfer execution flow temporarily over to the HTTP writer pipe
		if errDelivery := cmd.OnDelivery(plaintextSecret); errDelivery != nil {
			return fmt.Errorf("transport_layer_delivery_interrupted_enforcing_rollback: %w", errDelivery)
		}

		return nil // Staging success: transaction finalized safely on disk now
	})

	if txErr != nil {
		return txErr
	}

	return nil
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
	existing, err := s.adminStorage.GetApplicationProfileByID(ctx, cmd.TenantID, cmd.ID)
	if err != nil {
		return fmt.Errorf("failed locating existing profile: %w", err)
	}
	if existing.IsSystem {
		return port.ErrSystemManaged
	}

	enforceRTR := cmd.EnforceRTR
	if cmd.TokenEndpointAuthMethod == model.AuthMethodNone {
		enforceRTR = true
	}

	profile := model.ApplicationProfile{
		ID:                      cmd.ID,
		TenantID:                cmd.TenantID,
		ProfileName:             cmd.ProfileName,
		IsEnabled:               existing.IsEnabled,
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

// CreateGroup creates a standalone routing group after validating its routing content and sign-in methods.
func (s *ApplicationService) CreateGroup(ctx context.Context, cmd port.CreateGroupCommand) error {
	content, verr := normalizeGroupContent(groupContentFromCreate(cmd))
	cmd.DefaultIDPID = normalizeDefaultIDP(cmd.DefaultIDPID)
	if verr.HasErrors() {
		return verr
	}
	if err := s.validateGroupIDPs(ctx, cmd.TenantID, cmd.AllowedIDPIDs, cmd.DefaultIDPID, false); err != nil {
		return err
	}

	group := model.ApplicationGroup{
		ID:                     uuid.New(),
		TenantID:               cmd.TenantID,
		GroupName:              strings.TrimSpace(cmd.GroupName),
		IsEnabled:              true,
		RedirectURI:            content.defaultRedirectURI,
		RedirectURIs:           content.redirectURIs,
		PostLogoutRedirectURIs: content.postLogoutRedirectURIs,
		FrontChannelLogoutURI:  content.frontChannelLogoutURI,
		BackChannelLogoutURI:   content.backChannelLogoutURI,
		AllowedScopes:          content.allowedScopes,
		DefaultScopes:          content.defaultScopes,
		AllowedAudiences:       content.allowedAudiences,
		AllowedIDPIDs:          cmd.AllowedIDPIDs,
		DefaultIDPID:           cmd.DefaultIDPID,
		CreatedAt:              s.clock.Now(),
		UpdatedAt:              s.clock.Now(),
	}

	return s.adminStorage.CreateApplicationGroup(ctx, cmd.TenantID, group)
}

// groupContentFromCreate and groupContentFromUpdate adapt the two command types to the shared validator.
func groupContentFromCreate(cmd port.CreateGroupCommand) groupContentInput {
	return groupContentInput{
		redirectURIs: cmd.RedirectURIs, defaultRedirectURI: cmd.DefaultRedirectURI, postLogoutRedirectURIs: cmd.PostLogoutRedirectURIs,
		frontChannelLogoutURI: cmd.FrontChannelLogoutURI, backChannelLogoutURI: cmd.BackChannelLogoutURI,
		allowedScopes: cmd.AllowedScopes, defaultScopes: cmd.DefaultScopes, allowedAudiences: cmd.AllowedAudiences,
	}
}

func groupContentFromUpdate(cmd port.UpdateGroupCommand) groupContentInput {
	return groupContentInput{
		redirectURIs: cmd.RedirectURIs, defaultRedirectURI: cmd.DefaultRedirectURI, postLogoutRedirectURIs: cmd.PostLogoutRedirectURIs,
		frontChannelLogoutURI: cmd.FrontChannelLogoutURI, backChannelLogoutURI: cmd.BackChannelLogoutURI,
		allowedScopes: cmd.AllowedScopes, defaultScopes: cmd.DefaultScopes, allowedAudiences: cmd.AllowedAudiences,
	}
}

// UpdateGroup updates an existing standalone routing group.
// System-managed groups are read-only, except that the federated identity providers of the
// admin UI group may be extended so external SSO can be granted administrative access.
func (s *ApplicationService) UpdateGroup(ctx context.Context, cmd port.UpdateGroupCommand) error {
	existing, err := s.adminStorage.GetApplicationGroupByID(ctx, cmd.TenantID, cmd.ID)
	if err != nil {
		return fmt.Errorf("failed locating existing group: %w", err)
	}

	cmd.DefaultIDPID = normalizeDefaultIDP(cmd.DefaultIDPID)

	if existing.IsSystem {
		return s.updateSystemGroupIDPs(ctx, existing, cmd)
	}

	content, verr := normalizeGroupContent(groupContentFromUpdate(cmd))
	if verr.HasErrors() {
		return verr
	}
	if err := s.validateGroupIDPs(ctx, cmd.TenantID, cmd.AllowedIDPIDs, cmd.DefaultIDPID, false); err != nil {
		return err
	}

	group := model.ApplicationGroup{
		ID:                     cmd.ID,
		TenantID:               cmd.TenantID,
		GroupName:              strings.TrimSpace(cmd.GroupName),
		IsEnabled:              existing.IsEnabled,
		RedirectURI:            content.defaultRedirectURI,
		RedirectURIs:           content.redirectURIs,
		PostLogoutRedirectURIs: content.postLogoutRedirectURIs,
		FrontChannelLogoutURI:  content.frontChannelLogoutURI,
		BackChannelLogoutURI:   content.backChannelLogoutURI,
		AllowedScopes:          content.allowedScopes,
		DefaultScopes:          content.defaultScopes,
		AllowedAudiences:       content.allowedAudiences,
		AllowedIDPIDs:          cmd.AllowedIDPIDs,
		DefaultIDPID:           cmd.DefaultIDPID,
		UpdatedAt:              s.clock.Now(),
	}

	return s.adminStorage.UpdateApplicationGroup(ctx, cmd.TenantID, group)
}

// updateSystemGroupIDPs applies only the sign-in method changes to the admin UI group.
// Every other system group (including the local break-glass group) stays fully locked.
func (s *ApplicationService) updateSystemGroupIDPs(ctx context.Context, existing *model.ApplicationGroup, cmd port.UpdateGroupCommand) error {
	if existing.GroupName != model.AdminUIGroupName {
		return port.ErrSystemManaged
	}

	// Local accounts are never permitted on this group: local login is served by the break-glass group.
	if err := s.validateGroupIDPs(ctx, cmd.TenantID, cmd.AllowedIDPIDs, cmd.DefaultIDPID, true); err != nil {
		return err
	}

	updated := *existing
	updated.AllowedIDPIDs = cmd.AllowedIDPIDs
	updated.DefaultIDPID = cmd.DefaultIDPID
	updated.UpdatedAt = s.clock.Now()

	return s.adminStorage.UpdateApplicationGroup(ctx, cmd.TenantID, updated)
}

// normalizeDefaultIDP drops a nil-UUID default so an unset selection is never persisted as a bogus reference.
func normalizeDefaultIDP(id *uuid.UUID) *uuid.UUID {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return id
}

// validateGroupIDPs guarantees a group always keeps at least one sign-in method, that every referenced
// identity provider exists within the tenant, and that the default is one of the allowed providers.
func (s *ApplicationService) validateGroupIDPs(ctx context.Context, tenantID uuid.UUID, allowed []uuid.UUID, def *uuid.UUID, federatedOnly bool) error {
	verr := port.NewValidationError()
	if len(allowed) == 0 {
		verr.Add("allowed_idps", "at least one sign-in method is required")
		return verr
	}

	providers, err := s.storage.GetIdentityProvidersByUUIDs(ctx, tenantID, allowed)
	if err != nil {
		return fmt.Errorf("failed resolving group identity providers: %w", err)
	}

	if msg := checkGroupProviders(allowed, providers, federatedOnly); msg != "" {
		verr.Add("allowed_idps", msg)
	}
	if def != nil && !slices.Contains(allowed, *def) {
		verr.Add("default_idp_id", "the default sign-in method must be one of the allowed sign-in methods")
	}

	if verr.HasErrors() {
		return verr
	}
	return nil
}

// checkGroupProviders returns a human-readable violation for the first invalid provider reference, or an empty string.
func checkGroupProviders(allowed []uuid.UUID, providers []model.IdentityProvider, federatedOnly bool) string {
	byID := make(map[uuid.UUID]model.IdentityProvider, len(providers))
	for _, p := range providers {
		byID[p.ID] = p
	}

	for _, id := range allowed {
		p, ok := byID[id]
		if !ok {
			return fmt.Sprintf("unknown identity provider %s", id)
		}
		if federatedOnly && p.IDPType == model.UsernamePasswordIDPType {
			return "local accounts cannot be enabled for this group"
		}
	}
	return ""
}

// GetApplication returns a single application with its profile and group for detail pages.
func (s *ApplicationService) GetApplication(ctx context.Context, tenantID uuid.UUID, clientID string) (*model.ApplicationDetailsProps, error) {
	return s.GetApplicationDetails(ctx, tenantID, clientID)
}

// DeleteGroup removes a group. System groups and groups that applications still use cannot be removed.
func (s *ApplicationService) DeleteGroup(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	group, err := s.adminStorage.GetApplicationGroupByID(ctx, tenantID, id)
	if err != nil {
		return fmt.Errorf("failed locating group for removal: %w", err)
	}
	if group.IsSystem {
		return port.ErrSystemManaged
	}

	users, err := s.adminStorage.GetApplicationsByGroup(ctx, tenantID, id)
	if err != nil {
		return fmt.Errorf("failed checking group usage: %w", err)
	}
	if len(users) > 0 {
		return fmt.Errorf("group is used by %d application(s): %w", len(users), port.ErrInUse)
	}

	// The storage layer re-checks through the foreign key, which also covers an application bound after the check above.
	return s.adminStorage.DeleteApplicationGroup(ctx, tenantID, id)
}

// DeleteProfile removes a profile with the same protections as DeleteGroup.
func (s *ApplicationService) DeleteProfile(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	profile, err := s.adminStorage.GetApplicationProfileByID(ctx, tenantID, id)
	if err != nil {
		return fmt.Errorf("failed locating profile for removal: %w", err)
	}
	if profile.IsSystem {
		return port.ErrSystemManaged
	}

	users, err := s.adminStorage.GetApplicationsByProfile(ctx, tenantID, id)
	if err != nil {
		return fmt.Errorf("failed checking profile usage: %w", err)
	}
	if len(users) > 0 {
		return fmt.Errorf("profile is used by %d application(s): %w", len(users), port.ErrInUse)
	}

	return s.adminStorage.DeleteApplicationProfile(ctx, tenantID, id)
}

// ListApplicationsByGroup lists the applications bound to a group.
func (s *ApplicationService) ListApplicationsByGroup(ctx context.Context, tenantID uuid.UUID, groupID uuid.UUID) ([]model.ApplicationSummary, error) {
	return s.adminStorage.GetApplicationsByGroup(ctx, tenantID, groupID)
}

// ListApplicationsByProfile lists the applications bound to a profile.
func (s *ApplicationService) ListApplicationsByProfile(ctx context.Context, tenantID uuid.UUID, profileID uuid.UUID) ([]model.ApplicationSummary, error) {
	return s.adminStorage.GetApplicationsByProfile(ctx, tenantID, profileID)
}
