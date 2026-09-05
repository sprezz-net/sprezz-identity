package port

import (
	"context"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

type RegisterUserCommand struct {
	TenantID   uuid.UUID
	ProviderID uuid.UUID
	FirstName  string
	LastName   string
	Username   string
	Email      string
	Password   string
}

type ApproveUserCommand struct {
	TenantID    uuid.UUID
	PartitionID int64
	ProfileID   uuid.UUID
}

type GetSignupContextCommand struct {
	TenantID       uuid.UUID
	InteractionID  string
	ConsumeSession bool
}

type SignupContextResponse struct {
	Provider           *model.IdentityProvider
	InteractionSession *model.InteractionSession
}

// UserRegistrationUseCase coordinates Use Case 1.0 to provision native user directories safely.
type UserRegistrationUseCase interface {
	RegisterUser(ctx context.Context, cmd RegisterUserCommand) (*model.UserProfile, error)
	ApproveUserRequest(ctx context.Context, cmd ApproveUserCommand) error
	GetSignupContext(ctx context.Context, cmd GetSignupContextCommand) (*SignupContextResponse, error)
}
