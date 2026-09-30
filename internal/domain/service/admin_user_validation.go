package service

import (
	"net/mail"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

const (
	minPasswordLength = 8
	maxPasswordLength = 64
	maxUsernameLength = 64
	maxNameLength     = 64
	maxEmailLength    = 255
)

// validLifecycleStates are the states an administrator may move a user between.
var validLifecycleStates = map[model.ProfileLifecycleState]bool{
	model.LifecycleCreated:     true,
	model.LifecycleInvited:     true,
	model.LifecycleRequested:   true,
	model.LifecycleActivated:   true,
	model.LifecycleDeactivated: true,
}

// validateUserProfile checks the editable identity fields of a user and returns every problem by field name.
func validateUserProfile(u model.UserProfile) *port.ValidationError {
	verr := port.NewValidationError()

	switch {
	case u.PreferredUsername == "":
		verr.Add("username", "a username is required")
	case len(u.PreferredUsername) > maxUsernameLength:
		verr.Add("username", "the username must be at most 64 characters")
	case !strictUsernameFilter.MatchString(u.PreferredUsername):
		verr.Add("username", "the username contains characters that are not allowed")
	}

	if len(u.FirstName) > maxNameLength {
		verr.Add("first_name", "the first name must be at most 64 characters")
	}
	if len(u.LastName) > maxNameLength {
		verr.Add("last_name", "the last name must be at most 64 characters")
	}

	switch {
	case u.Email == "":
		verr.Add("email", "an email address is required")
	case len(u.Email) > maxEmailLength:
		verr.Add("email", "the email address must be at most 255 characters")
	default:
		if addr, err := mail.ParseAddress(u.Email); err != nil || addr.Address != u.Email {
			verr.Add("email", "enter a valid email address")
		}
	}
	return verr
}

// validateUserStatus checks the lifecycle state of a user.
func validateUserStatus(u model.UserProfile) *port.ValidationError {
	verr := port.NewValidationError()
	if !validLifecycleStates[u.LifecycleState] {
		verr.Add("lifecycle", "choose a valid account state")
	}
	return verr
}

// validateNewPassword applies the same length policy as registration and self-service changes.
func validateNewPassword(password string) *port.ValidationError {
	verr := port.NewValidationError()
	switch {
	case strings.TrimSpace(password) == "":
		verr.Add("new_password", "a new password is required")
	case len(password) < minPasswordLength:
		verr.Add("new_password", "the password must be at least 8 characters long")
	case len(password) > maxPasswordLength:
		verr.Add("new_password", "the password must be at most 64 characters long")
	}
	return verr
}
