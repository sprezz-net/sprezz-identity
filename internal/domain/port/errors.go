package port

import (
	"errors"
	"fmt"
	"strings"
)

// ValidationError represents a collection of field-specific domain validation failures.
// It maps the frontend input form element name directly to a human-readable constraint violation.
type ValidationError struct {
	Fields map[string]string
}

// Compile-time type assertion to guarantee full standard error interface compliance.
var _ error = (*ValidationError)(nil)

// NewValidationError initializes an empty field-specific error envelope.
func NewValidationError() *ValidationError {
	return &ValidationError{
		Fields: make(map[string]string),
	}
}

// Add appends a localized field validation violation to the envelope tracking pool.
func (e *ValidationError) Add(field, message string) {
	e.Fields[field] = message
}

// HasErrors returns true if the envelope contains one or more constraint violations.
func (e *ValidationError) HasErrors() bool {
	return len(e.Fields) > 0
}

// Error complies with the standard Go error contract by joining all localized faults.
func (e *ValidationError) Error() string {
	var errMsgs []string
	for field, msg := range e.Fields {
		errMsgs = append(errMsgs, fmt.Sprintf("%s: %s", field, msg))
	}
	return fmt.Sprintf("domain validation failed: %s", strings.Join(errMsgs, "; "))
}

var (
	// Standard Spec-Compliant OAuth 2.0 / OIDC Core Protocol Errors (RFC 6749 Section 5.2) [5.7]
	ErrInvalidGrant         = errors.New("invalid_grant")
	ErrInvalidRequest       = errors.New("invalid_request")
	ErrUnsupportedGrantType = errors.New("unsupported_grant_type")
	ErrInvalidClient        = errors.New("invalid_client")

	// Local User Registration Specific Use-Case Errors
	ErrPasswordTooShort     = errors.New("password must be at least 8 characters long")
	ErrRegistrationDisabled = errors.New("registration is disabled for this identity provider context")
	ErrInputTooLong         = errors.New("registration input parameter exceeds maximum permitted length")
	ErrInvalidCharacters    = errors.New("registration input contains unauthorized character profiles")

	// Pre-existing System Boundary Errors
	ErrTenantNotFound             = errors.New("tenant not found")
	ErrApplicationNotFound        = errors.New("application not found")
	ErrGroupNotFound              = errors.New("application group not found")
	ErrProfileNotFound            = errors.New("application profile not found")
	ErrSessionNotFound            = errors.New("session not found")
	ErrUserProfileNotFound        = errors.New("user profile not found")
	ErrPasswordCredentialNotFound = errors.New("password credential not found")
	ErrIdentityNotFound           = errors.New("identity not found")
	ErrInteractionSessionNotFound = errors.New("interaction session not found")
	ErrPartitionNotFound          = errors.New("partition not found")
	ErrIdentityProviderNotFound   = errors.New("identity provider not found")
	ErrUserProfileAlreadyExists   = errors.New("user profile with this identifier already exists")
	ErrEmailAlreadyExists         = errors.New("email address already in use")
	ErrUsernameAlreadyExists      = errors.New("username already in use")
	ErrExternalEmailNotVerified   = errors.New("external email not verified")

	// Administrative Console Errors
	// ErrSystemManaged is returned when an operation targets an object provisioned and protected by the bootstrap service.
	ErrSystemManaged = errors.New("this object is managed by the system and cannot be modified this way")
	// ErrTenantInactive is returned when a sign-in, token or session operation targets a tenant an administrator has
	// deactivated. Every entry point of the domain services checks it, not only the HTTP edge.
	ErrTenantInactive = errors.New("this tenant is not active")
	// ErrForbidden is returned when the acting administrator may not touch the object, for example another tenant.
	ErrForbidden = errors.New("you are not allowed to do this")
	// ErrLastAdministrator is returned when an action would leave the admin console without a usable administrator.
	ErrLastAdministrator = errors.New("this would remove the last administrator who can sign in")
	// ErrOwnAccount is returned when an administrator tries to block, deactivate or delete their own account.
	ErrOwnAccount = errors.New("you cannot do this to your own account")
	// ErrLastSignInMethod is returned when removing a link would leave a user without any way to sign in.
	ErrLastSignInMethod = errors.New("a user must keep at least one sign-in method")
	// ErrInUse is returned when an object cannot be removed because other objects still reference it.
	ErrInUse = errors.New("object is still in use by other objects")
	// ErrAlreadyExists is returned when a unique name or identifier is already taken.
	ErrAlreadyExists = errors.New("an object with this name already exists")
)
