package postgres

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

func seedUser(t *testing.T, s *PostgresStorage, tn seededTenant, username string) model.UserProfile {
	t.Helper()
	u := model.UserProfile{
		ID: uuid.New(), TenantID: tn.id, PartitionID: tn.partition, PreferredUsername: username,
		FirstName: username, Name: username, Email: username + "@example.com",
		LifecycleState: model.LifecycleActivated, CreatedAt: time.Now(),
	}
	require.NoError(t, s.SaveUserProfile(context.Background(), tn.id, tn.partition, u))
	return u
}

// The original query filtered on tenant and partition only and returned the first row, so every lookup returned
// the same user no matter which ID was asked for.
func TestIntegration_GetUserProfileByIDReturnsTheRequestedUser(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "users.example.com", false)
	alice, bob := seedUser(t, s, tn, "alice"), seedUser(t, s, tn, "bob")

	got, err := s.GetUserProfileByID(ctx, tn.id, tn.partition, bob.ID)
	require.NoError(t, err)
	assert.Equal(t, bob.ID, got.ID)
	assert.Equal(t, "bob", got.PreferredUsername)

	got, err = s.GetUserProfileByID(ctx, tn.id, tn.partition, alice.ID)
	require.NoError(t, err)
	assert.Equal(t, alice.ID, got.ID)
	assert.False(t, got.CreatedAt.IsZero(), "timestamps are returned too")
}

func TestIntegration_GetUserProfileByIDUnknownOrForeignUser(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	a := seedTenant(t, s, "a.users.example.com", false)
	b := seedTenant(t, s, "b.users.example.com", false)
	alice := seedUser(t, s, a, "alice")

	_, err := s.GetUserProfileByID(ctx, a.id, a.partition, uuid.New())
	assert.ErrorIs(t, err, port.ErrUserProfileNotFound)

	_, err = s.GetUserProfileByID(ctx, b.id, b.partition, alice.ID)
	assert.ErrorIs(t, err, port.ErrUserProfileNotFound, "another tenant cannot read this user")

	_, err = s.GetUserProfileByID(ctx, a.id, a.partition+999, alice.ID)
	assert.ErrorIs(t, err, port.ErrUserProfileNotFound, "the partition is part of the lookup")
}

func TestIntegration_DeleteUserProfileReportsNotFoundAndStaysInsideTheTenant(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	a := seedTenant(t, s, "a.del.example.com", false)
	b := seedTenant(t, s, "b.del.example.com", false)
	alice := seedUser(t, s, a, "alice")

	assert.ErrorIs(t, s.DeleteUserProfile(ctx, b.id, b.partition, alice.ID), port.ErrUserProfileNotFound, "a foreign tenant deletes nothing")
	_, err := s.GetUserProfileByID(ctx, a.id, a.partition, alice.ID)
	require.NoError(t, err, "the user is still there")

	require.NoError(t, s.DeleteUserProfile(ctx, a.id, a.partition, alice.ID))
	assert.ErrorIs(t, s.DeleteUserProfile(ctx, a.id, a.partition, alice.ID), port.ErrUserProfileNotFound, "deleting twice reports not found")
}
