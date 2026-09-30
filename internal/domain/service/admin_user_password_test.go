package service_test

import (
	"context"
	"errors"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (f *userFixture) stubLocalProvider() model.IdentityProvider {
	local := model.IdentityProvider{ID: uuid.New(), IDPType: model.UsernamePasswordIDPType, PartitionID: userTestPartition, Alias: "username-password", Name: "Local"}
	f.storage.GetIdentityProvidersMock.Optional().Return([]model.IdentityProvider{local}, nil)
	return local
}

func TestPatchUserPassword_HashesSavesAndEndsTheLockout(t *testing.T) {
	f := newUserFixture(t)
	alice := f.user("alice", userTestPartition)
	f.stubUsers(alice)
	local := f.stubLocalProvider()
	f.crypto.HashCredentialMock.Expect("a-new-password").Return("hashed", nil)
	var saved model.PasswordCredential
	f.storage.SavePasswordCredentialMock.Set(func(ctx context.Context, c model.PasswordCredential) error {
		saved = c
		return nil
	})
	f.storage.ResetPasswordCountersMock.Expect(context.Background(), f.tenantID, userTestPartition, alice.ID, local.ID).Return(nil)

	require.NoError(t, f.svc.PatchUser(context.Background(), port.PatchUserCommand{
		TenantID: f.tenantID, PartitionID: userTestPartition, ID: alice.ID, Section: port.UserSectionPassword, NewPassword: "a-new-password",
	}))
	assert.Equal(t, "hashed", saved.Argon2Hash)
	assert.Equal(t, alice.ID, saved.UserProfileID)
	assert.Equal(t, local.ID, saved.IdentityProviderID)
}

// The old handler ignored the error of the credential save, so a failed reset still reported success.
func TestPatchUserPassword_AFailedSaveIsReported(t *testing.T) {
	f := newUserFixture(t)
	alice := f.user("alice", userTestPartition)
	f.stubUsers(alice)
	f.stubLocalProvider()
	f.crypto.HashCredentialMock.Return("hashed", nil)
	f.storage.SavePasswordCredentialMock.Return(errors.New("connection reset"))

	err := f.svc.PatchUser(context.Background(), port.PatchUserCommand{
		TenantID: f.tenantID, PartitionID: userTestPartition, ID: alice.ID, Section: port.UserSectionPassword, NewPassword: "a-new-password",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed saving password")
}

func TestPatchUserPassword_PolicyIsEnforced(t *testing.T) {
	for name, password := range map[string]string{"empty": "", "blank": "        ", "short": "short", "long": string(make([]byte, 65))} {
		t.Run(name, func(t *testing.T) {
			f := newUserFixture(t)
			alice := f.user("alice", userTestPartition)
			f.stubUsers(alice)
			f.storage.SavePasswordCredentialMock.Optional().Set(func(ctx context.Context, c model.PasswordCredential) error {
				t.Error("a rejected password must not be stored")
				return nil
			})

			err := f.svc.PatchUser(context.Background(), port.PatchUserCommand{
				TenantID: f.tenantID, PartitionID: userTestPartition, ID: alice.ID, Section: port.UserSectionPassword, NewPassword: password,
			})
			var verr *port.ValidationError
			require.ErrorAs(t, err, &verr)
			assert.Contains(t, verr.Fields, "new_password")
		})
	}
}

func TestPatchUserPassword_PartitionWithoutLocalProvider(t *testing.T) {
	f := newUserFixture(t)
	alice := f.user("alice", userTestPartition)
	f.stubUsers(alice)
	f.storage.GetIdentityProvidersMock.Return(nil, nil)

	err := f.svc.PatchUser(context.Background(), port.PatchUserCommand{
		TenantID: f.tenantID, PartitionID: userTestPartition, ID: alice.ID, Section: port.UserSectionPassword, NewPassword: "a-new-password",
	})
	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr.Fields["new_password"], "no local accounts provider")
}
