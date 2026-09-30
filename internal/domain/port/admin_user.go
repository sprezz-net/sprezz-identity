package port

import (
	"context"
	"time"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

// UserSection names one independently saved part of the user page.
type UserSection string

const (
	UserSectionProfile  UserSection = "profile"
	UserSectionStatus   UserSection = "status"
	UserSectionPassword UserSection = "password"
)

// PatchUserCommand saves one section of a user. Only the fields of Section are read.
type PatchUserCommand struct {
	TenantID     uuid.UUID
	PartitionID  int64
	ID           uuid.UUID
	ActingUserID uuid.UUID
	Section      UserSection

	// Profile
	Username  string
	FirstName string
	LastName  string
	Email     string

	// Status
	EmailVerified bool
	Blocked       bool
	Lifecycle     model.ProfileLifecycleState

	// Password. An admin sets a new password; the current one is never needed or shown.
	NewPassword string
}

// DeleteUserCommand removes a user after the typed username matches.
type DeleteUserCommand struct {
	TenantID     uuid.UUID
	PartitionID  int64
	ID           uuid.UUID
	ActingUserID uuid.UUID
	Confirmation string
}

// UnlinkIdentityCommand removes one sign-in method from a user.
type UnlinkIdentityCommand struct {
	TenantID           uuid.UUID
	PartitionID        int64
	UserID             uuid.UUID
	IdentityProviderID uuid.UUID
}

// UserLink is one sign-in method of a user together with the provider it belongs to.
type UserLink struct {
	Identity      model.UserIdentity
	ProviderName  string
	ProviderAlias string
	ProviderType  string
}

// UserDetail is everything the user page shows.
type UserDetail struct {
	User         model.UserProfile
	Links        []UserLink
	HasPassword  bool
	Locked       bool
	BlockedUntil *time.Time
}

// AdminUserUseCase defines the driving port for managing users from the admin console.
type AdminUserUseCase interface {
	// ListUsers returns the users of one partition, or of every partition when partitionID is zero, in a stable order.
	ListUsers(ctx context.Context, tenantID uuid.UUID, partitionID int64) ([]model.UserProfile, error)
	GetUser(ctx context.Context, tenantID uuid.UUID, partitionID int64, id uuid.UUID) (*UserDetail, error)
	PatchUser(ctx context.Context, cmd PatchUserCommand) error
	// UnlockUser clears the failed-password counters and the temporary lockout of a user.
	UnlockUser(ctx context.Context, tenantID uuid.UUID, partitionID int64, id uuid.UUID) error
	UnlinkIdentity(ctx context.Context, cmd UnlinkIdentityCommand) error
	DeleteUser(ctx context.Context, cmd DeleteUserCommand) error
}
