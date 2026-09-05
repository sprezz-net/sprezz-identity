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
	storage port.Storage
	crypto  port.Crypto
	clock   port.Clock
}

var _ port.UserProfileUseCase = (*UserProfileService)(nil)

func NewUserProfileService(s port.Storage, c port.Crypto, cl port.Clock) *UserProfileService {
	return &UserProfileService{
		storage: s,
		crypto:  c,
		clock:   cl,
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
	if cmd.CurrentPassword == "" || cmd.NewPassword == "" {
		return fmt.Errorf("%w: password parameters cannot be empty values", port.ErrInvalidRequest)
	}

	// 1. Target the exact username-password provider locked to this specific partition
	providers, err := s.storage.GetIdentityProvidersByTypeAndPartition(ctx, cmd.TenantID, cmd.PartitionID, model.UsernamePasswordIDPType)
	if err != nil {
		return fmt.Errorf("user_profile_service: username-password identity provider unresolvable for partition %d: %w", cmd.PartitionID, err)
	}

	// Structural Validation Gate: Enforce that exactly one local IDP must exist for password trades
	if len(providers) == 0 {
		return fmt.Errorf("%w: no local username-password identity provider bootstrapped for this partition", port.ErrInvalidGrant)
	}
	idp := providers[0]

	// 2. Extract existing cryptographic password parameters from the partition sandbox
	cred, err := s.storage.GetPasswordCredentialByProfileID(ctx, cmd.TenantID, cmd.PartitionID, cmd.UserProfileID, idp.ID)
	if err != nil {
		return fmt.Errorf("%w: local account record missing or unconfigured in this partition", port.ErrInvalidGrant)
	}

	// 3. Side-Channel Protection: Assert current password validity before running mutations
	valid, err := s.crypto.CompareCredential(cred.Argon2Hash, cmd.CurrentPassword)
	if err != nil || !valid {
		return fmt.Errorf("%w: invalid current password provided", port.ErrInvalidGrant)
	}

	// 4. Drive fresh Argon2id key generation over the new password string
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
		return fmt.Errorf("user_profile_service: failed saving new credentials to partition ledger: %w", err)
	}

	return nil
}

// ChangeUserEmail executes partition-confined uniqueness checks to avoid cross-tenant index scans.
func (s *UserProfileService) ChangeUserEmail(ctx context.Context, cmd port.ChangeEmailCommand) error {
	if cmd.CurrentPassword == "" || cmd.NewEmail == "" {
		return fmt.Errorf("%w: parameter values cannot be empty blocks", port.ErrInvalidRequest)
	}

	// 1. Target provider strictly bound to the operational partition
	providers, err := s.storage.GetIdentityProvidersByTypeAndPartition(ctx, cmd.TenantID, cmd.PartitionID, model.UsernamePasswordIDPType)
	if err != nil {
		return fmt.Errorf("user_profile_service: username-password identity provider unresolvable for partition %d: %w", cmd.PartitionID, err)
	}

	// Structural Validation Gate: Enforce that exactly one local IDP must exist for password trades
	if len(providers) == 0 {
		return fmt.Errorf("%w: no local username-password identity provider bootstrapped for this partition", port.ErrInvalidGrant)
	}
	idp := providers[0]

	cred, err := s.storage.GetPasswordCredentialByProfileID(ctx, cmd.TenantID, cmd.PartitionID, cmd.UserProfileID, idp.ID)
	if err != nil {
		return fmt.Errorf("%w: local account verification required to change email", port.ErrInvalidGrant)
	}

	valid, err := s.crypto.CompareCredential(cred.Argon2Hash, cmd.CurrentPassword)
	if err != nil || !valid {
		return fmt.Errorf("%w: authentication failed: invalid current password", port.ErrInvalidGrant)
	}

	// 2. Partition-Isolated Uniqueness Fence: Enforce email rules strictly within the partition bounds
	existing, err := s.storage.FindProfileByEmail(ctx, cmd.PartitionID, cmd.NewEmail)
	if err == nil && existing != nil && existing.ID != cmd.UserProfileID {
		return fmt.Errorf("%w: target email address is already bound to another profile in this partition", port.ErrInvalidRequest)
	}

	partition, err := s.storage.GetPartitionByID(ctx, cmd.TenantID, cmd.PartitionID)
	if err != nil {
		return fmt.Errorf("user_profile_service: failed resolving partition properties: %w", err)
	}

	userProfile, err := s.storage.GetUserProfileByIDAndPartitionAlias(ctx, cmd.TenantID, partition.AliasName, cmd.UserProfileID)
	if err != nil {
		return fmt.Errorf("user_profile_service: target user profile record missing from workspace: %w", err)
	}

	userProfile.Email = cmd.NewEmail
	userProfile.EmailVerified = false

	if err := s.storage.SaveUserProfile(ctx, cmd.TenantID, cmd.PartitionID, *userProfile); err != nil {
		return fmt.Errorf("user_profile_service: failed committing email change down-funnel: %w", err)
	}

	return nil
}

// ChangeUserName modifies the text name using direct partition alias resolution.
func (s *UserProfileService) ChangeUserName(ctx context.Context, cmd port.ChangeNameCommand) error {
	if cmd.NewName == "" {
		return fmt.Errorf("%w: new name parameter string cannot be empty", port.ErrInvalidRequest)
	}

	partition, err := s.storage.GetPartitionByID(ctx, cmd.TenantID, cmd.PartitionID)
	if err != nil {
		return fmt.Errorf("user_profile_service: failed resolving partition properties: %w", err)
	}

	userProfile, err := s.storage.GetUserProfileByIDAndPartitionAlias(ctx, cmd.TenantID, partition.AliasName, cmd.UserProfileID)
	if err != nil {
		return fmt.Errorf("user_profile_service: target user profile record missing from workspace: %w", err)
	}

	userProfile.Name = cmd.NewName

	if err := s.storage.SaveUserProfile(ctx, cmd.TenantID, cmd.PartitionID, *userProfile); err != nil {
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
