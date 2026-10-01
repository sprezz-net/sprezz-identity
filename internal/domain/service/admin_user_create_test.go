package service_test

import (
	"context"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateUser_UsesTheLocalProviderAndActivatesOnlyWithAPassword(t *testing.T) {
	cases := map[string]struct {
		password string
		state    model.ProfileLifecycleState
	}{
		"with a password":    {"a-good-password", model.LifecycleActivated},
		"without a password": {"", model.LifecycleCreated},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newUserFixture(t)
			local := f.stubLocalProvider()
			f.noConflicts()
			var got port.CreateUserProfileCommand
			f.profiles.CreateUserProfileMock.Set(func(ctx context.Context, cmd port.CreateUserProfileCommand) (*model.UserProfile, error) {
				got = cmd
				return &model.UserProfile{ID: f.user("x", userTestPartition).ID}, nil
			})

			_, err := f.svc.CreateUser(context.Background(), port.CreateUserCommand{
				TenantID: f.tenantID, PartitionID: userTestPartition, Username: " dee ", Email: "dee@example.com", Password: tc.password,
			})

			require.NoError(t, err)
			assert.Equal(t, local.ID, got.IdentityProviderID)
			assert.Equal(t, "dee", got.Username, "input is trimmed")
			assert.Equal(t, tc.state, got.LifecycleState)
		})
	}
}

func TestCreateUser_Refusals(t *testing.T) {
	t.Run("invalid input is reported per field", func(t *testing.T) {
		f := newUserFixture(t)
		f.profiles.CreateUserProfileMock.Optional().Set(func(ctx context.Context, cmd port.CreateUserProfileCommand) (*model.UserProfile, error) {
			t.Error("invalid input must not create a user")
			return nil, nil
		})

		_, err := f.svc.CreateUser(context.Background(), port.CreateUserCommand{
			TenantID: f.tenantID, PartitionID: userTestPartition, Username: "a b", Email: "nope", Password: "short",
		})
		var verr *port.ValidationError
		require.ErrorAs(t, err, &verr)
		assert.Contains(t, verr.Fields, "username")
		assert.Contains(t, verr.Fields, "email")
		assert.Contains(t, verr.Fields, "new_password")
	})

	t.Run("a partition without local accounts", func(t *testing.T) {
		f := newUserFixture(t)
		f.storage.GetIdentityProvidersMock.Return(nil, nil)

		_, err := f.svc.CreateUser(context.Background(), port.CreateUserCommand{
			TenantID: f.tenantID, PartitionID: userTestPartition, Username: "dee", Email: "dee@example.com",
		})
		var verr *port.ValidationError
		require.ErrorAs(t, err, &verr)
		assert.Contains(t, verr.Fields, "partition_id")
	})

	t.Run("a taken username", func(t *testing.T) {
		f := newUserFixture(t)
		f.stubLocalProvider()
		other := f.user("dee", userTestPartition)
		f.storage.GetUserProfileByPreferredUsernameMock.Return(&other, nil)
		f.storage.FindProfileByEmailMock.Return(nil, errNotFound)

		_, err := f.svc.CreateUser(context.Background(), port.CreateUserCommand{
			TenantID: f.tenantID, PartitionID: userTestPartition, Username: "dee", Email: "dee@example.com",
		})
		var verr *port.ValidationError
		require.ErrorAs(t, err, &verr)
		assert.Contains(t, verr.Fields, "username")
	})
}
