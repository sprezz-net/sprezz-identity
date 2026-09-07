package service

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

// Structural constraints matching Section 5.3 data protection parameters [5.3]
var strictUsernameFilter = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\@]+$`)

type UserRegistrationService struct {
	storage            port.Storage
	userProfileUseCase port.UserProfileUseCase
	clock              port.Clock
}

func NewUserRegistrationService(s port.Storage, upuc port.UserProfileUseCase, cl port.Clock) *UserRegistrationService {
	return &UserRegistrationService{
		storage:            s,
		userProfileUseCase: upuc,
		clock:              cl,
	}
}

func (s *UserRegistrationService) RegisterUser(ctx context.Context, cmd port.RegisterUserCommand) (*model.UserProfile, error) {
	// 1. Load the explicit identity provider passed down from the target login flow context [5.7]
	provider, err := s.storage.GetIdentityProviderByUUID(ctx, cmd.TenantID, cmd.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("registration: target identity provider context unresolvable: %w", err)
	}

	// Safety Gate: Ensure the provider is a local username/password directory and is active [5.7]
	if provider.IDPType != model.UsernamePasswordIDPType || !provider.Enabled {
		return nil, port.ErrRegistrationDisabled
	}

	// 2. Section 5.3 Sanitization: Enforce space trimming and strict byte constraint filters [5.3]
	username := strings.TrimSpace(cmd.Username)
	email := strings.TrimSpace(cmd.Email)
	firstName := strings.TrimSpace(cmd.FirstName)
	lastName := strings.TrimSpace(cmd.LastName)

	if len(firstName) > 64 || len(lastName) > 64 {
		return nil, port.ErrInputTooLong
	}
	if len(username) > 64 || len(email) > 255 {
		return nil, port.ErrInputTooLong
	}

	if !strictUsernameFilter.MatchString(username) {
		return nil, port.ErrInvalidCharacters
	}

	if len(cmd.Password) < 8 {
		return nil, port.ErrPasswordTooShort
	}

	if provider.Config.UsernameField == "email" {
		username = email
	}

	now := s.clock.Now()

	// 3. DELEGATION: Route execution via the profile use-case border, passing the definitive CreatedAt clock tick
	profile, err := s.userProfileUseCase.CreateUserProfile(ctx, port.CreateUserProfileCommand{
		TenantID:           cmd.TenantID,
		PartitionID:        provider.PartitionID,
		IdentityProviderID: provider.ID,
		Username:           username,
		Email:              email,
		FirstName:          firstName,
		LastName:           lastName,
		Password:           cmd.Password,
		LifecycleState:     model.LifecycleActivated, // Defaults cleanly to activated on standard signups
		CreatedAt:          now,
	})
	if err != nil {
		return nil, fmt.Errorf("registration: database transaction failed: %w", err)
	}

	return profile, nil
}

// ApproveUserRequest advances a pending profile from REQUESTED to ACTIVATED state [5.7].
func (s *UserRegistrationService) ApproveUserRequest(ctx context.Context, cmd port.ApproveUserCommand) error {
	// 1. Fetch the user profile safely locked under the correct multi-tenant partition key
	profile, err := s.storage.GetUserProfileByID(ctx, cmd.TenantID, cmd.PartitionID, cmd.ProfileID)
	if err != nil {
		return fmt.Errorf("approval: failed loading targeted profile: %w", err)
	}

	if profile.LifecycleState != model.LifecycleRequested {
		return fmt.Errorf("approval: profile %s is not in a pending request state", cmd.ProfileID)
	}

	// 2. Advance the state properties
	profile.LifecycleState = model.LifecycleActivated
	profile.UpdatedAt = s.clock.Now()

	// 3. Save the modified profile back to the partition table
	if err := s.storage.SaveUserProfile(ctx, cmd.TenantID, cmd.PartitionID, *profile); err != nil {
		return fmt.Errorf("approval: failed committing profile activation state: %w", err)
	}

	return nil
}

func (s *UserRegistrationService) GetSignupContext(ctx context.Context, cmd port.GetSignupContextCommand) (*port.SignupContextResponse, error) {
	var interactionSession *model.InteractionSession
	var partitionID int64
	var isDirectAccess = true

	if cmd.InteractionID != "" {
		sessionUUID, err := uuid.Parse(cmd.InteractionID)
		if err == nil {
			var session *model.InteractionSession
			var sessionErr error
			if cmd.ConsumeSession {
				session, sessionErr = s.storage.GetAndConsumeInteractionSession(ctx, cmd.TenantID, sessionUUID)
			} else {
				session, sessionErr = s.storage.GetInteractionSession(ctx, cmd.TenantID, sessionUUID)
			}
			if sessionErr == nil && session != nil {
				interactionSession = session
				isDirectAccess = false
				partitionID = session.PartitionID
			}
		}
	}

	resolvedPartitionID := partitionID
	if isDirectAccess {
		tenant, tenantErr := s.storage.ResolveTenantByUUID(ctx, cmd.TenantID)
		if tenantErr == nil {
			if tenant.DefaultPartition != nil && *tenant.DefaultPartition != 0 {
				resolvedPartitionID = *tenant.DefaultPartition
			} else {
				parts, err := s.storage.GetPartitions(ctx, cmd.TenantID)
				if err == nil && len(parts) > 0 {
					resolvedPartitionID = parts[0].ID
				}
			}
		}
	}

	// Fetch partition-confined username-password providers
	providers, err := s.storage.GetIdentityProvidersByTypeAndPartition(ctx, cmd.TenantID, resolvedPartitionID, model.UsernamePasswordIDPType)
	if err != nil || len(providers) == 0 {
		allProviders, fallbackErr := s.storage.GetEnabledIdentityProviders(ctx, cmd.TenantID)
		if fallbackErr == nil {
			for _, p := range allProviders {
				if p.IDPType == model.UsernamePasswordIDPType {
					providers = append(providers, p)
					break
				}
			}
		}
	}

	var provider *model.IdentityProvider
	if len(providers) > 0 {
		provider = &providers[0]
	}

	return &port.SignupContextResponse{
		Provider:           provider,
		InteractionSession: interactionSession,
	}, nil
}
