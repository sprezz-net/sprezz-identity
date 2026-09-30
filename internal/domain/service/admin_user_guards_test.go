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

func (f *userFixture) forbidWrites(t *testing.T) {
	t.Helper()
	f.admin.UpdateUserProfileMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, part int64, p model.UserProfile) error {
		t.Error("a refused change must not be written")
		return nil
	})
	f.admin.DeleteUserProfileMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, part int64, id uuid.UUID) error {
		t.Error("a refused deletion must not reach storage")
		return nil
	})
}

func TestDeleteUser_RequiresTheTypedUsername(t *testing.T) {
	f := newUserFixture(t)
	alice := f.user("alice", userTestPartition)
	f.stubUsers(alice)
	f.forbidWrites(t)

	err := f.svc.DeleteUser(context.Background(), port.DeleteUserCommand{
		TenantID: f.tenantID, PartitionID: userTestPartition, ID: alice.ID, ActingUserID: uuid.New(), Confirmation: "bob",
	})

	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr.Fields, "confirmation")
}

func TestDeleteUser_OrdinaryUserIsDeleted(t *testing.T) {
	f := newUserFixture(t)
	alice := f.user("alice", userTestPartition)
	f.stubUsers(alice)
	f.admin.DeleteUserProfileMock.Return(nil)

	require.NoError(t, f.svc.DeleteUser(context.Background(), port.DeleteUserCommand{
		TenantID: f.tenantID, PartitionID: userTestPartition, ID: alice.ID, ActingUserID: uuid.New(), Confirmation: "alice",
	}))
}

func TestDeleteUser_AdministratorsAreProtected(t *testing.T) {
	t.Run("never their own account", func(t *testing.T) {
		f := newUserFixture(t)
		root := f.user("root", userTestAdminPartition)
		other := f.user("other", userTestAdminPartition)
		f.stubUsers(root, other)
		f.forbidWrites(t)

		err := f.svc.DeleteUser(context.Background(), port.DeleteUserCommand{
			TenantID: f.tenantID, PartitionID: userTestAdminPartition, ID: root.ID, ActingUserID: root.ID, Confirmation: "root",
		})
		assert.ErrorIs(t, err, port.ErrOwnAccount)
	})

	t.Run("never the last administrator who can sign in", func(t *testing.T) {
		f := newUserFixture(t)
		last := f.user("last", userTestAdminPartition)
		blocked := f.user("blocked", userTestAdminPartition)
		blocked.Blocked = true
		f.stubUsers(last, blocked)
		f.forbidWrites(t)

		err := f.svc.DeleteUser(context.Background(), port.DeleteUserCommand{
			TenantID: f.tenantID, PartitionID: userTestAdminPartition, ID: last.ID, ActingUserID: uuid.New(), Confirmation: "last",
		})
		assert.ErrorIs(t, err, port.ErrLastAdministrator, "a blocked administrator does not count as a remaining one")
	})

	t.Run("another administrator may be deleted while a second one remains", func(t *testing.T) {
		f := newUserFixture(t)
		a, b := f.user("a", userTestAdminPartition), f.user("b", userTestAdminPartition)
		f.stubUsers(a, b)
		f.admin.DeleteUserProfileMock.Return(nil)

		require.NoError(t, f.svc.DeleteUser(context.Background(), port.DeleteUserCommand{
			TenantID: f.tenantID, PartitionID: userTestAdminPartition, ID: b.ID, ActingUserID: a.ID, Confirmation: "b",
		}))
	})
}

func TestDeleteUser_UnknownUser(t *testing.T) {
	f := newUserFixture(t)
	f.stubUsers()

	err := f.svc.DeleteUser(context.Background(), port.DeleteUserCommand{TenantID: f.tenantID, PartitionID: userTestPartition, ID: uuid.New(), Confirmation: "x"})
	assert.ErrorIs(t, err, port.ErrUserProfileNotFound)
}

func TestPatchUserStatus_BlockingAdministratorsIsGuarded(t *testing.T) {
	block := func(f *userFixture, target, acting model.UserProfile) error {
		return f.svc.PatchUser(context.Background(), port.PatchUserCommand{
			TenantID: f.tenantID, PartitionID: target.PartitionID, ID: target.ID, ActingUserID: acting.ID,
			Section: port.UserSectionStatus, Blocked: true, Lifecycle: model.LifecycleActivated,
		})
	}

	t.Run("not yourself", func(t *testing.T) {
		f := newUserFixture(t)
		me, other := f.user("me", userTestAdminPartition), f.user("other", userTestAdminPartition)
		f.stubUsers(me, other)
		f.forbidWrites(t)
		assert.ErrorIs(t, block(f, me, me), port.ErrOwnAccount)
	})

	t.Run("not the last one", func(t *testing.T) {
		f := newUserFixture(t)
		only := f.user("only", userTestAdminPartition)
		f.stubUsers(only)
		f.forbidWrites(t)
		assert.ErrorIs(t, block(f, only, f.user("someone", userTestAdminPartition)), port.ErrLastAdministrator)
	})

	t.Run("an ordinary user can be blocked", func(t *testing.T) {
		f := newUserFixture(t)
		alice := f.user("alice", userTestPartition)
		f.stubUsers(alice)
		f.noConflicts()
		saved := f.captureUpdate()

		require.NoError(t, block(f, alice, f.user("admin", userTestAdminPartition)))
		assert.True(t, saved.Blocked)
	})

	t.Run("deactivating an administrator is guarded like blocking", func(t *testing.T) {
		f := newUserFixture(t)
		me, other := f.user("me", userTestAdminPartition), f.user("other", userTestAdminPartition)
		f.stubUsers(me, other)
		f.forbidWrites(t)

		err := f.svc.PatchUser(context.Background(), port.PatchUserCommand{
			TenantID: f.tenantID, PartitionID: me.PartitionID, ID: me.ID, ActingUserID: me.ID,
			Section: port.UserSectionStatus, Lifecycle: model.LifecycleDeactivated,
		})
		assert.ErrorIs(t, err, port.ErrOwnAccount)
	})
}
