package port

import (
	"errors"
)

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
