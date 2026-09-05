package port

import (
	"context"
	"errors"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

// Common operational errors mapped straight to HTTP status presentation layers
var (
	ErrInvalidCredentials       = errors.New("invalid credentials provided")
	ErrAccountTemporarilyLocked = errors.New("this authentication channel is temporarily locked")
	ErrAccountBlocked           = errors.New("this account is administratively blocked")
	ErrActivationRequired       = errors.New("account activation sequence is required")
)

type LocalLoginCommand struct {
	TenantID          uuid.UUID
	PartitionID       int64
	ProviderID        uuid.UUID
	Identifier        string // Can be clean Username or email string
	PlaintextPassword string
}

type LocalLoginResponse struct {
	UserProfileID uuid.UUID
	PartitionID   int64
	SessionID     string
	Subject       string
}

type GetLoginContextCommand struct {
	TenantID      uuid.UUID
	InteractionID string // Optional UUID string
	IDPHintQuery  string // Optional query parameter
}

type LoginContextResponse struct {
	AllowSignup              bool
	Providers                []model.IdentityProvider
	ShowUsernamePasswordForm bool
	PartitionID              int64
	InteractionSession       *model.InteractionSession
	TriggerAutoFederatedIDP  *model.IdentityProvider
	TenantBaseURI            string
}

// LocalAuthUseCase defines the driving port (inbound interface) for local credential login and password checks.
type LocalAuthUseCase interface {
	// AuthenticateLocalCredentials verifies native username/password entries and handles lockout states.
	AuthenticateLocalCredentials(ctx context.Context, cmd LocalLoginCommand) (*LocalLoginResponse, error)
	GetLoginContext(ctx context.Context, cmd GetLoginContextCommand) (*LoginContextResponse, error)
	GetInteractionSession(ctx context.Context, tenantID uuid.UUID, interactionID string) (*model.InteractionSession, error)
}
