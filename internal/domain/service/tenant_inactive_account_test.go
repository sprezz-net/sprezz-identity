package service

import (
	"context"

	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

// inactiveAccountCases are the self-service operations of a signed-in user.
func inactiveAccountCases() []inactiveCase {
	return []inactiveCase{
		{"create user profile", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.profiles.CreateUserProfile(ctx, port.CreateUserProfileCommand{TenantID: e.tenantID, PartitionID: inactivePartition, Username: "u"})
			return err
		}},
		{"change own password", func(ctx context.Context, e *inactiveEnv) error {
			return e.profiles.ChangeUserPassword(ctx, port.ChangePasswordCommand{TenantID: e.tenantID, PartitionID: inactivePartition, UserProfileID: uuid.New(), CurrentPassword: "a", NewPassword: "b"})
		}},
		{"change own email", func(ctx context.Context, e *inactiveEnv) error {
			return e.profiles.ChangeUserEmail(ctx, port.ChangeEmailCommand{TenantID: e.tenantID, PartitionID: inactivePartition, UserProfileID: uuid.New(), CurrentPassword: "a", NewEmail: "a@example.com"})
		}},
		{"change own name", func(ctx context.Context, e *inactiveEnv) error {
			return e.profiles.ChangeUserName(ctx, port.ChangeNameCommand{TenantID: e.tenantID, PartitionID: inactivePartition, UserProfileID: uuid.New(), NewName: "n"})
		}},
		{"unlink own identity", func(ctx context.Context, e *inactiveEnv) error {
			return e.profiles.DecoupleUserIdentity(ctx, port.DecoupleIdentityCommand{TenantID: e.tenantID, PartitionID: inactivePartition, UserProfileID: uuid.New(), IdentityProviderID: uuid.New()})
		}},
		{"read own profile", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.profiles.GetUserProfile(ctx, port.GetUserProfileCommand{TenantID: e.tenantID, PartitionID: inactivePartition, UserProfileID: uuid.New()})
			return err
		}},
		{"own profile dashboard", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.profiles.GetUserProfileDashboard(ctx, port.GetUserProfileDashboardCommand{TenantID: e.tenantID, PartitionID: inactivePartition, UserProfileID: uuid.New()})
			return err
		}},
	}
}
