package service_test

import (
	"context"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnlinkIdentity_KeepsTheLastSignInMethod(t *testing.T) {
	f := newUserFixture(t)
	alice := f.user("alice", userTestPartition)
	f.stubUsers(alice)
	sso, local := uuid.New(), uuid.New()
	f.admin.DecoupleIdentityMock.Optional().Set(func(ctx context.Context, u, p uuid.UUID) error {
		t.Error("the last sign-in method must not be removed")
		return nil
	})

	f.storage.GetUserIdentitiesByProfileIDMock.Return([]model.UserIdentity{{IdentityProviderID: sso}}, nil)
	cmd := port.UnlinkIdentityCommand{TenantID: f.tenantID, PartitionID: userTestPartition, UserID: alice.ID, IdentityProviderID: sso}
	assert.ErrorIs(t, f.svc.UnlinkIdentity(context.Background(), cmd), port.ErrLastSignInMethod)

	f.storage.GetUserIdentitiesByProfileIDMock.Return([]model.UserIdentity{{IdentityProviderID: sso}, {IdentityProviderID: local}}, nil)
	cmd.IdentityProviderID = uuid.New()
	assert.ErrorIs(t, f.svc.UnlinkIdentity(context.Background(), cmd), port.ErrIdentityNotFound, "a method the user does not have")
}

func TestUnlinkIdentity_RemovesOneOfSeveral(t *testing.T) {
	f := newUserFixture(t)
	alice := f.user("alice", userTestPartition)
	f.stubUsers(alice)
	sso, local := uuid.New(), uuid.New()
	f.storage.GetUserIdentitiesByProfileIDMock.Return([]model.UserIdentity{{IdentityProviderID: sso}, {IdentityProviderID: local}}, nil)
	f.admin.DecoupleIdentityMock.Expect(context.Background(), alice.ID, sso).Return(nil)

	require.NoError(t, f.svc.UnlinkIdentity(context.Background(), port.UnlinkIdentityCommand{
		TenantID: f.tenantID, PartitionID: userTestPartition, UserID: alice.ID, IdentityProviderID: sso,
	}))
}

func TestGetUser_ReportsLinksAndLockout(t *testing.T) {
	f := newUserFixture(t)
	alice := f.user("alice", userTestPartition)
	f.stubUsers(alice)
	local := f.stubLocalProvider()
	until := time.Now().Add(time.Hour)
	f.storage.GetUserIdentitiesByProfileIDMock.Return([]model.UserIdentity{{IdentityProviderID: local.ID}}, nil)
	f.storage.GetPasswordCredentialByProfileIDMock.Return(&model.PasswordCredential{BlockedUntil: &until}, nil)

	detail, err := f.svc.GetUser(context.Background(), f.tenantID, userTestPartition, alice.ID)
	require.NoError(t, err)
	require.Len(t, detail.Links, 1)
	assert.Equal(t, "Local", detail.Links[0].ProviderName)
	assert.True(t, detail.HasPassword)
	assert.True(t, detail.Locked)
}

func TestListUsers_AcrossPartitionsIsDeterministic(t *testing.T) {
	f := newUserFixture(t)
	f.stubUsers(f.user("zoe", userTestPartition), f.user("Adam", userTestAdminPartition), f.user("bea", userTestPartition))

	users, err := f.svc.ListUsers(context.Background(), f.tenantID, 0)
	require.NoError(t, err)
	names := []string{}
	for _, u := range users {
		names = append(names, u.PreferredUsername)
	}
	assert.Equal(t, []string{"Adam", "bea", "zoe"}, names, "sorted by username regardless of partition order")
}

func TestUnlockUser_ClearsTheLocalLockout(t *testing.T) {
	f := newUserFixture(t)
	alice := f.user("alice", userTestPartition)
	f.stubUsers(alice)
	local := f.stubLocalProvider()
	f.storage.ResetPasswordCountersMock.Expect(context.Background(), f.tenantID, userTestPartition, alice.ID, local.ID).Return(nil)

	require.NoError(t, f.svc.UnlockUser(context.Background(), f.tenantID, userTestPartition, alice.ID))
}
