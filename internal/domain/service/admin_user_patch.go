package service

import (
	"context"
	"fmt"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

// PatchUser saves one section. The stored user is re-read and only the submitted section is overlaid, so a save
// from one card can never overwrite what another card shows. The user is always loaded by ID, so a save can only
// change the user it names.
func (s *AdminUserService) PatchUser(ctx context.Context, cmd port.PatchUserCommand) error {
	user, err := s.storage.GetUserProfileByID(ctx, cmd.TenantID, cmd.PartitionID, cmd.ID)
	if err != nil {
		return err
	}
	if cmd.Section == port.UserSectionPassword {
		return s.resetPassword(ctx, user, cmd)
	}

	updated := *user
	var verr *port.ValidationError
	switch cmd.Section {
	case port.UserSectionProfile:
		verr = overlayUserProfile(&updated, cmd)
	case port.UserSectionStatus:
		overlayUserStatus(&updated, cmd)
		verr = validateUserStatus(updated)
	default:
		verr = port.NewValidationError()
		verr.Add("section", "unknown user section")
	}
	if verr.HasErrors() {
		return verr
	}
	if cmd.Section == port.UserSectionStatus {
		if err := s.guardLosingAccess(ctx, user, &updated, cmd.ActingUserID); err != nil {
			return err
		}
	}
	return s.saveUser(ctx, updated)
}

func overlayUserProfile(u *model.UserProfile, cmd port.PatchUserCommand) *port.ValidationError {
	u.PreferredUsername = strings.TrimSpace(cmd.Username)
	u.FirstName, u.LastName = strings.TrimSpace(cmd.FirstName), strings.TrimSpace(cmd.LastName)
	u.Email = strings.TrimSpace(cmd.Email)
	u.Name = strings.TrimSpace(u.FirstName + " " + u.LastName)
	return validateUserProfile(*u)
}

func overlayUserStatus(u *model.UserProfile, cmd port.PatchUserCommand) {
	u.EmailVerified, u.Blocked, u.LifecycleState = cmd.EmailVerified, cmd.Blocked, cmd.Lifecycle
}

// saveUser writes the profile and turns a uniqueness conflict into a message for the field that caused it.
func (s *AdminUserService) saveUser(ctx context.Context, u model.UserProfile) error {
	u.UpdatedAt = s.clock.Now()
	if err := s.checkUnique(ctx, u); err != nil {
		return err
	}
	if err := s.adminStorage.UpdateUserProfile(ctx, u.TenantID, u.PartitionID, u); err != nil {
		return fmt.Errorf("admin_user_service: failed saving user: %w", err)
	}
	return nil
}

// checkUnique makes sure another user of the partition does not already hold the username or email address.
func (s *AdminUserService) checkUnique(ctx context.Context, u model.UserProfile) error {
	verr := port.NewValidationError()
	if other, err := s.storage.GetUserProfileByPreferredUsername(ctx, u.TenantID, u.PartitionID, u.PreferredUsername); err == nil && other.ID != u.ID {
		verr.Add("username", port.ErrUsernameAlreadyExists.Error())
	}
	if other, err := s.storage.FindProfileByEmail(ctx, u.TenantID, u.PartitionID, u.Email); err == nil && other.ID != u.ID {
		verr.Add("email", port.ErrEmailAlreadyExists.Error())
	}
	if verr.HasErrors() {
		return verr
	}
	return nil
}

// resetPassword sets a new password for the user's local account. A failed save is reported, never swallowed.
func (s *AdminUserService) resetPassword(ctx context.Context, user *model.UserProfile, cmd port.PatchUserCommand) error {
	if verr := validateNewPassword(cmd.NewPassword); verr.HasErrors() {
		return verr
	}
	providers, err := s.storage.GetIdentityProviders(ctx, cmd.TenantID)
	if err != nil {
		return fmt.Errorf("admin_user_service: failed reading providers: %w", err)
	}
	local := localProviderOf(providers, user.PartitionID)
	if local == nil {
		verr := port.NewValidationError()
		verr.Add("new_password", "this partition has no local accounts provider, so there is no password to set")
		return verr
	}

	hash, err := s.crypto.HashCredential(cmd.NewPassword)
	if err != nil {
		return fmt.Errorf("admin_user_service: failed hashing password: %w", err)
	}
	now := s.clock.Now()
	cred := model.PasswordCredential{UserProfileID: user.ID, IdentityProviderID: local.ID, Argon2Hash: hash, CreatedAt: now, UpdatedAt: now}
	if err := s.storage.SavePasswordCredential(ctx, cred); err != nil {
		return fmt.Errorf("admin_user_service: failed saving password: %w", err)
	}
	// A reset also ends an existing lockout, otherwise the user could still not sign in with the new password.
	if err := s.storage.ResetPasswordCounters(ctx, cmd.TenantID, user.PartitionID, user.ID, local.ID); err != nil {
		return fmt.Errorf("admin_user_service: failed clearing lockout: %w", err)
	}
	return nil
}
