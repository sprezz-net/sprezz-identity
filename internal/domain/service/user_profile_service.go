package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

type UserProfileService struct {
	storage      port.Storage
	adminStorage port.AdminStorage
	crypto       port.Crypto
	clock        port.Clock
}

var _ port.UserProfileUseCase = (*UserProfileService)(nil)

func NewUserProfileService(s port.Storage, as port.AdminStorage, c port.Crypto, cl port.Clock) *UserProfileService {
	return &UserProfileService{
		storage:      s,
		adminStorage: as,
		crypto:       c,
		clock:        cl,
	}
}

// CreateUserProfile coordinates the multi-table transactional initialization of a new human actor profile,
// generating Argon2id hashes and binding localized audit trail linkage nodes concurrently.
func (s *UserProfileService) CreateUserProfile(ctx context.Context, cmd port.CreateUserProfileCommand) (*model.UserProfile, error) {
	compositeName := strings.TrimSpace(cmd.FirstName + " " + cmd.LastName)

	// Without a password the user profile cannot be activated, set back to created state
	if cmd.Password == "" && cmd.LifecycleState == model.LifecycleActivated {
		cmd.LifecycleState = model.LifecycleCreated
	}

	profile := &model.UserProfile{
		ID:                uuid.New(),
		TenantID:          cmd.TenantID,
		PreferredUsername: cmd.Username,
		Name:              compositeName,
		FirstName:         cmd.FirstName,
		LastName:          cmd.LastName,
		Email:             cmd.Email,
		EmailVerified:     cmd.EmailVerified,
		PartitionID:       cmd.PartitionID,
		LifecycleState:    cmd.LifecycleState,
		CreatedAt:         cmd.CreatedAt,
		UpdatedAt:         cmd.CreatedAt,
	}

	// 1. Persist the parent user profile record within its isolated partition fence
	if err := s.storage.SaveUserProfile(ctx, cmd.TenantID, cmd.PartitionID, *profile); err != nil {
		return nil, fmt.Errorf("user_profile_service: failed saving profile matrix: %w", err)
	}

	if cmd.Password != "" {
		// 2. Derive secure cryptographic password hash using the injected crypto component
		hash, err := s.crypto.HashCredential(cmd.Password)
		if err != nil {
			return nil, fmt.Errorf("user_profile_service: password crypto mapping failed: %w", err)
		}

		cred := model.PasswordCredential{
			UserProfileID:      profile.ID,
			IdentityProviderID: cmd.IdentityProviderID,
			Argon2Hash:         hash,
			CreatedAt:          cmd.CreatedAt,
			UpdatedAt:          cmd.CreatedAt,
		}
		if err := s.storage.SavePasswordCredential(ctx, cred); err != nil {
			return nil, fmt.Errorf("user_profile_service: failed saving credentials row: %w", err)
		}

		// 3. Bind native audit tracking lines into the user_identities matrix
		identity := model.UserIdentity{
			ID:                 uuid.New(),
			UserProfileID:      profile.ID,
			IdentityProviderID: cmd.IdentityProviderID,
			ExternalIdentityID: profile.ID.String(),
			CoupledAt:          cmd.CreatedAt,
		}

		if err := s.storage.UpsertUserIdentity(ctx, cmd.TenantID, cmd.PartitionID, identity); err != nil {
			return nil, fmt.Errorf("user_profile_service: failed auto-coupling user audit tracker: %w", err)
		}
	}

	return profile, nil
}

// ChangeUserPassword extracts the localized credential directory inside the requested partition,
// preventing cross-partition token or password validation leaks.
func (s *UserProfileService) ChangeUserPassword(ctx context.Context, cmd port.ChangePasswordCommand) error {
	// 1. Structural Form Invariant Checks: Map directly onto form field elements
	valErr := port.NewValidationError()
	if strings.TrimSpace(cmd.CurrentPassword) == "" {
		valErr.Add("current_password", "Current password cannot be empty")
	}
	if strings.TrimSpace(cmd.NewPassword) == "" {
		valErr.Add("new_password", "New password cannot be empty")
	} else if len(cmd.NewPassword) > 64 {
		valErr.Add("new_password", "New password exceeds maximum permitted length of 64 characters")
	}

	if valErr.HasErrors() {
		return valErr
	}

	// 2. Target the exact username-password provider locked to this specific partition
	providers, err := s.storage.GetIdentityProvidersByTypeAndPartition(ctx, cmd.TenantID, cmd.PartitionID, model.UsernamePasswordIDPType)
	if err != nil {
		return fmt.Errorf("user_profile_service: username-password identity provider unresolvable for partition %d: %w", cmd.PartitionID, err)
	}

	// 3. Structural Validation Gate: Enforce that exactly one local IDP must exist for password trades
	if len(providers) == 0 {
		return fmt.Errorf("%w: no local username-password identity provider bootstrapped for this partition", port.ErrInvalidGrant)
	}
	idp := providers[0]

	// 4. Extract existing cryptographic password parameters from the partition sandbox
	cred, err := s.storage.GetPasswordCredentialByProfileID(ctx, cmd.TenantID, cmd.PartitionID, cmd.UserProfileID, idp.ID)
	if err != nil {
		return fmt.Errorf("%w: local account record missing or unconfigured in this partition", port.ErrInvalidGrant)
	}

	// 5. Side-Channel Protection: Assert current password validity before running mutations
	valid, err := s.crypto.CompareCredential(cred.Argon2Hash, cmd.CurrentPassword)
	if err != nil || !valid {
		return fmt.Errorf("%w: invalid current password provided", port.ErrInvalidGrant)
	}

	// 6. Drive fresh Argon2id key generation over the new password string
	newHash, err := s.crypto.HashCredential(cmd.NewPassword)
	if err != nil {
		return fmt.Errorf("user_profile_service: failed computing cryptographic hash: %w", err)
	}

	now := s.clock.Now()
	updatedCredential := model.PasswordCredential{
		UserProfileID:      cmd.UserProfileID,
		IdentityProviderID: idp.ID,
		Argon2Hash:         newHash,
		CreatedAt:          cred.CreatedAt,
		UpdatedAt:          now,
	}

	if err := s.storage.SavePasswordCredential(ctx, updatedCredential); err != nil {
		return fmt.Errorf("user_profile_service: failed saving new credentials to partition: %w", err)
	}

	return nil
}

// ChangeUserEmail executes partition-confined uniqueness checks to avoid cross-tenant index scans.
func (s *UserProfileService) ChangeUserEmail(ctx context.Context, cmd port.ChangeEmailCommand) error {
	cleanedEmail := strings.TrimSpace(cmd.NewEmail)

	// 1. Structural Form Invariant Checks: Map directly onto respective form field elements
	valErr := port.NewValidationError()
	if strings.TrimSpace(cmd.CurrentPassword) == "" {
		valErr.Add("current_password", "Current password is required to change email")
	}
	if cleanedEmail == "" {
		valErr.Add("new_email", "New email address cannot be empty")
	}

	// 2. Intercept and throw early if structural validations fail before invoking database checks
	if valErr.HasErrors() {
		return valErr
	}

	// 3. Target provider strictly bound to the operational partition
	providers, err := s.storage.GetIdentityProvidersByTypeAndPartition(ctx, cmd.TenantID, cmd.PartitionID, model.UsernamePasswordIDPType)
	if err != nil {
		return fmt.Errorf("user_profile_service: username-password identity provider unresolvable for partition %d: %w", cmd.PartitionID, err)
	}

	// 4. Structural Validation Gate: Enforce that exactly one local IDP must exist for password trades
	if len(providers) == 0 {
		return fmt.Errorf("%w: no local username-password identity provider bootstrapped for this partition", port.ErrInvalidGrant)
	}
	idp := providers[0]

	cred, err := s.storage.GetPasswordCredentialByProfileID(ctx, cmd.TenantID, cmd.PartitionID, cmd.UserProfileID, idp.ID)
	if err != nil {
		return fmt.Errorf("%w: local account verification required to change email", port.ErrInvalidGrant)
	}

	// 5. Side-Channel Protection: Target the 'current_password' field element directly if password comparison fails
	valid, err := s.crypto.CompareCredential(cred.Argon2Hash, cmd.CurrentPassword)
	if err != nil || !valid {
		valErr.Add("current_password", "Invalid current password provided")
		return valErr
	}

	// 6. Partition-Isolated Uniqueness Fence: Target the 'new_email' field element directly on index collision
	existing, err := s.storage.FindProfileByEmail(ctx, cmd.TenantID, cmd.PartitionID, cleanedEmail)
	if err == nil && existing != nil && existing.ID != cmd.UserProfileID {
		valErr.Add("new_email", "This email address is already bound to another profile in this partition")
		return valErr
	}

	partition, err := s.storage.GetPartitionByID(ctx, cmd.TenantID, cmd.PartitionID)
	if err != nil {
		return fmt.Errorf("user_profile_service: failed resolving partition properties: %w", err)
	}

	userProfile, err := s.storage.GetUserProfileByIDAndPartitionAlias(ctx, cmd.TenantID, partition.AliasName, cmd.UserProfileID)
	if err != nil {
		return fmt.Errorf("user_profile_service: target user profile record missing from workspace: %w", err)
	}

	userProfile.Email = cleanedEmail
	userProfile.EmailVerified = false

	// 7. Use UpdateUserProfile to persist changes over existing records safely without key-collision faults
	if err := s.adminStorage.UpdateUserProfile(ctx, cmd.TenantID, cmd.PartitionID, *userProfile); err != nil {
		return fmt.Errorf("user_profile_service: failed persisting email change: %w", err)
	}

	return nil
}

// ChangeUserName modifies the text name using direct partition alias resolution.
func (s *UserProfileService) ChangeUserName(ctx context.Context, cmd port.ChangeNameCommand) error {
	cleanedName := strings.TrimSpace(cmd.NewName)

	// 1. Structural Form Invariant Checks: Map directly onto the 'new_name' field element
	valErr := port.NewValidationError()
	if cleanedName == "" {
		valErr.Add("new_name", "New name parameter string cannot be empty")
	}
	if len(cleanedName) > 64 {
		valErr.Add("new_name", "Display name exceeds maximum permitted length of 64 characters")
	}

	// Intercept and throw if any domain boundary validations failed
	if valErr.HasErrors() {
		return valErr
	}

	partition, err := s.storage.GetPartitionByID(ctx, cmd.TenantID, cmd.PartitionID)
	if err != nil {
		return fmt.Errorf("user_profile_service: failed resolving partition properties: %w", err)
	}

	userProfile, err := s.storage.GetUserProfileByIDAndPartitionAlias(ctx, cmd.TenantID, partition.AliasName, cmd.UserProfileID)
	if err != nil {
		return fmt.Errorf("user_profile_service: target user profile record missing from workspace: %w", err)
	}

	userProfile.Name = cleanedName

	// 2. Use UpdateUserProfile to persist changes over existing records safely without key-collision faults
	if err := s.adminStorage.UpdateUserProfile(ctx, cmd.TenantID, cmd.PartitionID, *userProfile); err != nil {
		return fmt.Errorf("user_profile_service: failed committing display name change: %w", err)
	}

	return nil
}

// DecoupleUserIdentity disconnects a federated account while protecting the profile from becoming un-routable.
func (s *UserProfileService) DecoupleUserIdentity(ctx context.Context, cmd port.DecoupleIdentityCommand) error {
	// 1. Gather active identities strictly within this isolated partition boundary
	identities, err := s.storage.GetUserIdentitiesByProfileID(ctx, cmd.TenantID, cmd.PartitionID, cmd.UserProfileID)
	if err != nil {
		return fmt.Errorf("user_profile_service: failed gathering active identity associations: %w", err)
	}

	if len(identities) <= 1 {
		return errors.New("user_profile_service: cannot decouple identity: a profile must retain at least one active connection link")
	}

	var targetLinkExists bool
	for _, ident := range identities {
		if ident.IdentityProviderID == cmd.IdentityProviderID {
			targetLinkExists = true
			break
		}
	}

	if !targetLinkExists {
		return fmt.Errorf("%w: target identity mapping link is not coupled to this profile", port.ErrInvalidRequest)
	}

	idp, err := s.storage.GetIdentityProviderByUUID(ctx, cmd.TenantID, cmd.IdentityProviderID)
	if err != nil {
		return fmt.Errorf("user_profile_service: identity provider lookup failed: %w", err)
	}

	if idp.IDPType == model.UsernamePasswordIDPType && !idp.Config.AllowDecoupling {
		return errors.New("user_profile_service: administrative policy blocks decoupling this partition's local password directory")
	}

	// 2. Perform a targeted revocation strictly limited to the user-to-IDP connection string
	return s.storage.RevokeSession(ctx, cmd.TenantID, cmd.UserProfileID.String(), idp.ID.String())
}

func (s *UserProfileService) GetUserProfile(ctx context.Context, cmd port.GetUserProfileCommand) (*model.UserProfile, error) {
	partition, err := s.storage.GetPartitionByID(ctx, cmd.TenantID, cmd.PartitionID)
	if err != nil {
		return nil, fmt.Errorf("user_profile_service: failed resolving partition properties: %w", err)
	}

	userProfile, err := s.storage.GetUserProfileByIDAndPartitionAlias(ctx, cmd.TenantID, partition.AliasName, cmd.UserProfileID)
	if err != nil {
		return nil, fmt.Errorf("user_profile_service: target user profile record missing from workspace: %w", err)
	}

	return userProfile, nil
}

func (s *UserProfileService) GetUserProfileDashboard(ctx context.Context, cmd port.GetUserProfileDashboardCommand) (*port.GetUserProfileDashboardResponse, error) {
	userProfile, err := s.GetUserProfile(ctx, port.GetUserProfileCommand(cmd))
	if err != nil {
		return nil, err
	}

	identities, err := s.storage.GetUserIdentitiesByProfileID(ctx, cmd.TenantID, cmd.PartitionID, userProfile.ID)
	if err != nil {
		return nil, fmt.Errorf("user_profile_service: failed gathering active identity associations: %w", err)
	}

	allProviders, err := s.storage.GetEnabledIdentityProviders(ctx, cmd.TenantID)
	if err != nil {
		return nil, fmt.Errorf("user_profile_service: failed gathering enabled identity providers: %w", err)
	}

	var providers []model.IdentityProvider
	var hasPasswordIDP bool
	for _, p := range allProviders {
		if p.PartitionID == cmd.PartitionID {
			providers = append(providers, p)
			if p.IDPType == model.UsernamePasswordIDPType {
				hasPasswordIDP = true
			}
		}
	}

	return &port.GetUserProfileDashboardResponse{
		UserProfile:    *userProfile,
		Identities:     identities,
		Providers:      providers,
		HasPasswordIDP: hasPasswordIDP,
	}, nil
}
