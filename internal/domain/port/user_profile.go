package port

import (
	"context"
	"time"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

type CreateUserProfileCommand struct {
	TenantID           uuid.UUID
	PartitionID        int64
	IdentityProviderID uuid.UUID
	Username           string
	Email              string
	EmailVerified      bool
	FirstName          string
	LastName           string
	Password           string
	LifecycleState     model.ProfileLifecycleState
	CreatedAt          time.Time
}

type ChangePasswordCommand struct {
	TenantID        uuid.UUID
	PartitionID     int64
	UserProfileID   uuid.UUID
	CurrentPassword string
	NewPassword     string
}

type ChangeEmailCommand struct {
	TenantID        uuid.UUID
	PartitionID     int64
	UserProfileID   uuid.UUID
	CurrentPassword string
	NewEmail        string
}

type ChangeNameCommand struct {
	TenantID      uuid.UUID
	PartitionID   int64
	UserProfileID uuid.UUID
	NewName       string
}

type DecoupleIdentityCommand struct {
	TenantID           uuid.UUID
	PartitionID        int64
	UserProfileID      uuid.UUID
	IdentityProviderID uuid.UUID
}

type GetUserProfileCommand struct {
	TenantID      uuid.UUID
	PartitionID   int64
	UserProfileID uuid.UUID
}

type GetUserProfileDashboardCommand struct {
	TenantID      uuid.UUID
	PartitionID   int64
	UserProfileID uuid.UUID
}

type GetUserProfileDashboardResponse struct {
	UserProfile    model.UserProfile
	Identities     []model.UserIdentity
	Providers      []model.IdentityProvider
	HasPasswordIDP bool
}

type UserProfileUseCase interface {
	CreateUserProfile(ctx context.Context, cmd CreateUserProfileCommand) (*model.UserProfile, error)
	ChangeUserPassword(ctx context.Context, cmd ChangePasswordCommand) error
	ChangeUserEmail(ctx context.Context, cmd ChangeEmailCommand) error
	ChangeUserName(ctx context.Context, cmd ChangeNameCommand) error
	DecoupleUserIdentity(ctx context.Context, cmd DecoupleIdentityCommand) error
	GetUserProfile(ctx context.Context, cmd GetUserProfileCommand) (*model.UserProfile, error)
	GetUserProfileDashboard(ctx context.Context, cmd GetUserProfileDashboardCommand) (*GetUserProfileDashboardResponse, error)
}
