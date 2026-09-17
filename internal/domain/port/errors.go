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
)
