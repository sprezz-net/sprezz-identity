package service_test

import (
	"context"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPatchUserProfile_OnlyTheNamedUserChanges(t *testing.T) {
	f := newUserFixture(t)
	alice, bob := f.user("alice", userTestPartition), f.user("bob", userTestPartition)
	f.stubUsers(alice, bob)
	f.noConflicts()
	var savedID uuid.UUID
	var saved model.UserProfile
	f.admin.UpdateUserProfileMock.Set(func(ctx context.Context, tID uuid.UUID, part int64, p model.UserProfile) error {
		savedID, saved = p.ID, p
		return nil
	})

	require.NoError(t, f.svc.PatchUser(context.Background(), port.PatchUserCommand{
		TenantID: f.tenantID, PartitionID: userTestPartition, ID: bob.ID, Section: port.UserSectionProfile,
		Username: "bobby", FirstName: " Bob ", LastName: "Builder", Email: "bobby@example.com",
	}))

	assert.Equal(t, bob.ID, savedID, "the user named in the request is the one written")
	assert.Equal(t, "bobby", saved.PreferredUsername)
	assert.Equal(t, "Bob Builder", saved.Name, "the display name is recomputed from the parts")
	assert.Equal(t, model.LifecycleActivated, saved.LifecycleState, "sections that were not posted keep their values")
	assert.False(t, saved.Blocked)
}

func TestPatchUserProfile_Validation(t *testing.T) {
	cases := map[string]struct {
		cmd   port.PatchUserCommand
		field string
	}{
		"empty username":    {port.PatchUserCommand{Username: "", Email: "a@example.com"}, "username"},
		"bad characters":    {port.PatchUserCommand{Username: "a b", Email: "a@example.com"}, "username"},
		"long username":     {port.PatchUserCommand{Username: string(make([]byte, 65)), Email: "a@example.com"}, "username"},
		"missing email":     {port.PatchUserCommand{Username: "alice"}, "email"},
		"malformed email":   {port.PatchUserCommand{Username: "alice", Email: "not-an-email"}, "email"},
		"display name form": {port.PatchUserCommand{Username: "alice", Email: "A <a@example.com>"}, "email"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newUserFixture(t)
			alice := f.user("alice", userTestPartition)
			f.stubUsers(alice)
			f.forbidWrites(t)

			tc.cmd.TenantID, tc.cmd.PartitionID, tc.cmd.ID, tc.cmd.Section = f.tenantID, userTestPartition, alice.ID, port.UserSectionProfile
			var verr *port.ValidationError
			require.ErrorAs(t, f.svc.PatchUser(context.Background(), tc.cmd), &verr)
			assert.Contains(t, verr.Fields, tc.field)
		})
	}
}

func TestPatchUserProfile_TakenUsernameOrEmailIsReportedPerField(t *testing.T) {
	f := newUserFixture(t)
	alice, bob := f.user("alice", userTestPartition), f.user("bob", userTestPartition)
	f.stubUsers(alice, bob)
	f.forbidWrites(t)
	f.storage.GetUserProfileByPreferredUsernameMock.Return(&alice, nil)
	f.storage.FindProfileByEmailMock.Return(&alice, nil)

	err := f.svc.PatchUser(context.Background(), port.PatchUserCommand{
		TenantID: f.tenantID, PartitionID: userTestPartition, ID: bob.ID, Section: port.UserSectionProfile,
		Username: "alice", Email: "alice@example.com",
	})

	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr.Fields, "username")
	assert.Contains(t, verr.Fields, "email")
}

func TestPatchUserStatus_RejectsUnknownLifecycle(t *testing.T) {
	f := newUserFixture(t)
	alice := f.user("alice", userTestPartition)
	f.stubUsers(alice)
	f.forbidWrites(t)

	err := f.svc.PatchUser(context.Background(), port.PatchUserCommand{
		TenantID: f.tenantID, PartitionID: userTestPartition, ID: alice.ID, Section: port.UserSectionStatus, Lifecycle: "HACKED",
	})
	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr.Fields, "lifecycle")
}

func TestPatchUser_UnknownSectionAndUnknownUser(t *testing.T) {
	f := newUserFixture(t)
	alice := f.user("alice", userTestPartition)
	f.stubUsers(alice)

	var verr *port.ValidationError
	require.ErrorAs(t, f.svc.PatchUser(context.Background(), port.PatchUserCommand{TenantID: f.tenantID, PartitionID: userTestPartition, ID: alice.ID, Section: "bogus"}), &verr)

	err := f.svc.PatchUser(context.Background(), port.PatchUserCommand{TenantID: f.tenantID, PartitionID: userTestPartition, ID: uuid.New(), Section: port.UserSectionProfile})
	assert.ErrorIs(t, err, port.ErrUserProfileNotFound)
}
