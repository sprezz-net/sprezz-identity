package service

import (
	"context"
	"errors"
	"fmt"

	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

// UnlockUser clears the failed-password counters and the temporary lockout.
func (s *AdminUserService) UnlockUser(ctx context.Context, tenantID uuid.UUID, partitionID int64, id uuid.UUID) error {
	if _, err := s.storage.GetUserProfileByID(ctx, tenantID, partitionID, id); err != nil {
		return err
	}
	providers, err := s.storage.GetIdentityProviders(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("admin_user_service: failed reading providers: %w", err)
	}
	local := localProviderOf(providers, partitionID)
	if local == nil {
		return nil
	}
	if err := s.storage.ResetPasswordCounters(ctx, tenantID, partitionID, id, local.ID); err != nil {
		return fmt.Errorf("admin_user_service: failed unlocking user: %w", err)
	}
	return nil
}

// UnlinkIdentity removes one sign-in method. The last remaining method can never be removed.
func (s *AdminUserService) UnlinkIdentity(ctx context.Context, cmd port.UnlinkIdentityCommand) error {
	if _, err := s.storage.GetUserProfileByID(ctx, cmd.TenantID, cmd.PartitionID, cmd.UserID); err != nil {
		return err
	}
	identities, err := s.storage.GetUserIdentitiesByProfileID(ctx, cmd.TenantID, cmd.PartitionID, cmd.UserID)
	if err != nil {
		return fmt.Errorf("admin_user_service: failed reading sign-in methods: %w", err)
	}

	linked := false
	for _, ident := range identities {
		linked = linked || ident.IdentityProviderID == cmd.IdentityProviderID
	}
	if !linked {
		return port.ErrIdentityNotFound
	}
	if len(identities) <= 1 {
		return port.ErrLastSignInMethod
	}
	if err := s.adminStorage.DecoupleIdentity(ctx, cmd.UserID, cmd.IdentityProviderID); err != nil {
		return fmt.Errorf("admin_user_service: failed removing sign-in method: %w", err)
	}
	return nil
}

// DeleteUser removes a user after the typed username matches. An administrator can never delete their own
// account or the last administrator who can sign in.
func (s *AdminUserService) DeleteUser(ctx context.Context, cmd port.DeleteUserCommand) error {
	user, err := s.storage.GetUserProfileByID(ctx, cmd.TenantID, cmd.PartitionID, cmd.ID)
	if err != nil {
		return err
	}
	if cmd.Confirmation != user.PreferredUsername {
		verr := port.NewValidationError()
		verr.Add("confirmation", "type the username exactly to confirm deletion")
		return verr
	}
	if user.ID == cmd.ActingUserID {
		return port.ErrOwnAccount
	}
	if err := s.guardLosingAccess(ctx, user, nil, cmd.ActingUserID); err != nil {
		return err
	}
	if err := s.adminStorage.DeleteUserProfile(ctx, cmd.TenantID, cmd.PartitionID, cmd.ID); err != nil {
		if errors.Is(err, port.ErrUserProfileNotFound) {
			return err
		}
		return fmt.Errorf("admin_user_service: failed deleting user: %w", err)
	}
	return nil
}
