package service

import (
	"context"
	"fmt"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

// CreateUser adds a user to a partition. The partition must have a local accounts provider, because that is where
// the password and the first sign-in method live.
func (s *AdminUserService) CreateUser(ctx context.Context, cmd port.CreateUserCommand) (*model.UserProfile, error) {
	profile := model.UserProfile{
		TenantID: cmd.TenantID, PartitionID: cmd.PartitionID,
		PreferredUsername: strings.TrimSpace(cmd.Username),
		FirstName:         strings.TrimSpace(cmd.FirstName), LastName: strings.TrimSpace(cmd.LastName),
		Email: strings.TrimSpace(cmd.Email),
	}
	verr := validateUserProfile(profile)
	if cmd.Password != "" {
		for field, msg := range validateNewPassword(cmd.Password).Fields {
			verr.Add(field, msg)
		}
	}
	if verr.HasErrors() {
		return nil, verr
	}

	providers, err := s.storage.GetIdentityProviders(ctx, cmd.TenantID)
	if err != nil {
		return nil, fmt.Errorf("admin_user_service: failed reading providers: %w", err)
	}
	local := localProviderOf(providers, cmd.PartitionID)
	if local == nil {
		verr.Add("partition_id", "this partition has no local accounts provider")
		return nil, verr
	}
	if err := s.checkUnique(ctx, profile); err != nil {
		return nil, err
	}

	state := model.LifecycleActivated
	if cmd.Password == "" {
		state = model.LifecycleCreated
	}
	created, err := s.profiles.CreateUserProfile(ctx, port.CreateUserProfileCommand{
		TenantID: cmd.TenantID, PartitionID: cmd.PartitionID, IdentityProviderID: local.ID,
		Username: profile.PreferredUsername, Email: profile.Email, EmailVerified: cmd.EmailVerified,
		FirstName: profile.FirstName, LastName: profile.LastName, Password: cmd.Password,
		LifecycleState: state, CreatedAt: s.clock.Now(),
	})
	if err != nil {
		return nil, fmt.Errorf("admin_user_service: failed creating user: %w", err)
	}
	return created, nil
}
