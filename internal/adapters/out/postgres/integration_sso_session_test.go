package postgres

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hashOf(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func newTestSSOSession(tn seededTenant, userID uuid.UUID, now time.Time) model.SSOSession {
	return model.SSOSession{
		ID: uuid.New(), TenantID: tn.id, PartitionID: tn.partition, UserProfileID: userID,
		IdentityProviderID: tn.localIDP, ACR: "aal1", AMR: []string{"pwd"},
		AuthTime: now, CreatedAt: now, LastSeenAt: now,
		ExpiresAt: now.Add(24 * time.Hour), IdleExpiresAt: now.Add(8 * time.Hour),
	}
}

func TestIntegration_SSOSessionRoundTrips(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "sessions.example.com", false)
	user := seedUser(t, s, tn, "alice")
	now := time.Now().UTC().Truncate(time.Second)
	session := newTestSSOSession(tn, user.ID, now)

	require.NoError(t, s.SaveSSOSession(ctx, session, hashOf("secret-1")))

	got, err := s.GetActiveSSOSession(ctx, tn.id, hashOf("secret-1"), now)
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)
	assert.Equal(t, tn.id, got.TenantID)
	assert.Equal(t, tn.partition, got.PartitionID)
	assert.Equal(t, user.ID, got.UserProfileID)
	assert.Equal(t, tn.localIDP, got.IdentityProviderID)
	assert.Equal(t, "aal1", got.ACR)
	assert.Equal(t, []string{"pwd"}, got.AMR)
	assert.True(t, now.Equal(got.AuthTime))
	assert.True(t, session.ExpiresAt.Equal(got.ExpiresAt))
	assert.True(t, session.IdleExpiresAt.Equal(got.IdleExpiresAt))
}

func TestIntegration_SSOSessionWithoutProviderOrMethodsIsStored(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "bare.sessions.example.com", false)
	user := seedUser(t, s, tn, "alice")
	now := time.Now().UTC()
	session := newTestSSOSession(tn, user.ID, now)
	session.IdentityProviderID = uuid.Nil
	session.AMR = nil // would become NULL in a NOT NULL column if it were passed on as nil

	require.NoError(t, s.SaveSSOSession(ctx, session, hashOf("bare")))

	got, err := s.GetActiveSSOSession(ctx, tn.id, hashOf("bare"), now)
	require.NoError(t, err)
	assert.Equal(t, uuid.Nil, got.IdentityProviderID)
	assert.Empty(t, got.AMR)
}

func TestIntegration_SSOSessionIsInvisibleOnceExpiredOrIdle(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "expiry.sessions.example.com", false)
	user := seedUser(t, s, tn, "alice")
	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, s.SaveSSOSession(ctx, newTestSSOSession(tn, user.ID, now), hashOf("s")))

	_, err := s.GetActiveSSOSession(ctx, tn.id, hashOf("s"), now.Add(8*time.Hour-time.Second))
	require.NoError(t, err, "just before the idle deadline")

	_, err = s.GetActiveSSOSession(ctx, tn.id, hashOf("s"), now.Add(8*time.Hour))
	require.ErrorIs(t, err, port.ErrSessionNotFound, "idle deadline reached")

	// Keeping the session busy moves the idle deadline, but never past the absolute one.
	require.NoError(t, s.TouchSSOSession(ctx, tn.id, hashOf("s"), now.Add(7*time.Hour), now.Add(25*time.Hour)))
	_, err = s.GetActiveSSOSession(ctx, tn.id, hashOf("s"), now.Add(24*time.Hour-time.Second))
	require.NoError(t, err, "the touch extended the idle deadline")
	_, err = s.GetActiveSSOSession(ctx, tn.id, hashOf("s"), now.Add(24*time.Hour))
	require.ErrorIs(t, err, port.ErrSessionNotFound, "the absolute lifetime still wins")
}

func TestIntegration_SSOSessionIsBoundToItsTenant(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	a := seedTenant(t, s, "a.sessions.example.com", false)
	b := seedTenant(t, s, "b.sessions.example.com", false)
	now := time.Now().UTC()
	require.NoError(t, s.SaveSSOSession(ctx, newTestSSOSession(a, seedUser(t, s, a, "alice").ID, now), hashOf("a-secret")))

	_, err := s.GetActiveSSOSession(ctx, b.id, hashOf("a-secret"), now)

	require.ErrorIs(t, err, port.ErrSessionNotFound, "a valid secret of tenant A must not open tenant B")
}

func TestIntegration_SSOSessionUnknownSecretIsNotFound(t *testing.T) {
	s := newIntegrationStorage(t)
	tn := seedTenant(t, s, "unknown.sessions.example.com", false)

	_, err := s.GetActiveSSOSession(context.Background(), tn.id, hashOf("never-issued"), time.Now())

	require.ErrorIs(t, err, port.ErrSessionNotFound)
}

func TestIntegration_SSOSessionTouchIsScopedToItsTenant(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	a := seedTenant(t, s, "a.touch.example.com", false)
	b := seedTenant(t, s, "b.touch.example.com", false)
	now := time.Now().UTC().Truncate(time.Second)
	session := newTestSSOSession(a, seedUser(t, s, a, "alice").ID, now)
	require.NoError(t, s.SaveSSOSession(ctx, session, hashOf("a")))

	require.NoError(t, s.TouchSSOSession(ctx, b.id, hashOf("a"), now.Add(time.Hour), now.Add(23*time.Hour)))

	got, err := s.GetActiveSSOSession(ctx, a.id, hashOf("a"), now)
	require.NoError(t, err)
	assert.True(t, session.IdleExpiresAt.Equal(got.IdleExpiresAt), "another tenant cannot move the deadline")
}

func TestIntegration_DeletingASessionEndsOnlyThatSession(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "delete.sessions.example.com", false)
	other := seedTenant(t, s, "other.sessions.example.com", false)
	user := seedUser(t, s, tn, "alice")
	now := time.Now().UTC()
	first, second := newTestSSOSession(tn, user.ID, now), newTestSSOSession(tn, user.ID, now)
	require.NoError(t, s.SaveSSOSession(ctx, first, hashOf("one")))
	require.NoError(t, s.SaveSSOSession(ctx, second, hashOf("two")))

	require.NoError(t, s.DeleteSSOSession(ctx, other.id, first.ID), "another tenant's delete is a no-op")
	_, err := s.GetActiveSSOSession(ctx, tn.id, hashOf("one"), now)
	require.NoError(t, err)

	require.NoError(t, s.DeleteSSOSession(ctx, tn.id, first.ID))
	_, err = s.GetActiveSSOSession(ctx, tn.id, hashOf("one"), now)
	require.ErrorIs(t, err, port.ErrSessionNotFound)
	_, err = s.GetActiveSSOSession(ctx, tn.id, hashOf("two"), now)
	require.NoError(t, err, "the user's other session stays")

	require.NoError(t, s.DeleteSSOSession(ctx, tn.id, uuid.New()), "deleting an unknown session is not an error")
}

func TestIntegration_DeletingAUsersSessionsLeavesOtherUsers(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "everywhere.sessions.example.com", false)
	alice, bob := seedUser(t, s, tn, "alice"), seedUser(t, s, tn, "bob")
	now := time.Now().UTC()
	require.NoError(t, s.SaveSSOSession(ctx, newTestSSOSession(tn, alice.ID, now), hashOf("alice-laptop")))
	require.NoError(t, s.SaveSSOSession(ctx, newTestSSOSession(tn, alice.ID, now), hashOf("alice-phone")))
	require.NoError(t, s.SaveSSOSession(ctx, newTestSSOSession(tn, bob.ID, now), hashOf("bob")))

	require.NoError(t, s.DeleteSSOSessionsByUser(ctx, tn.id, alice.ID))

	for _, secret := range []string{"alice-laptop", "alice-phone"} {
		_, err := s.GetActiveSSOSession(ctx, tn.id, hashOf(secret), now)
		require.ErrorIs(t, err, port.ErrSessionNotFound)
	}
	_, err := s.GetActiveSSOSession(ctx, tn.id, hashOf("bob"), now)
	require.NoError(t, err)
}

func TestIntegration_PurgeEndsTheSSOSessionsOfOnlyTheDeactivatedTenant(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	a := seedTenant(t, s, "a.purge.sessions.example.com", false)
	b := seedTenant(t, s, "b.purge.sessions.example.com", false)
	now := time.Now().UTC()
	require.NoError(t, s.SaveSSOSession(ctx, newTestSSOSession(a, seedUser(t, s, a, "alice").ID, now), hashOf("a")))
	require.NoError(t, s.SaveSSOSession(ctx, newTestSSOSession(b, seedUser(t, s, b, "bob").ID, now), hashOf("b")))

	require.NoError(t, s.PurgeTenantSessionsAndTokens(ctx, a.id))

	_, err := s.GetActiveSSOSession(ctx, a.id, hashOf("a"), now)
	require.ErrorIs(t, err, port.ErrSessionNotFound)
	_, err = s.GetActiveSSOSession(ctx, b.id, hashOf("b"), now)
	require.NoError(t, err)
}

func TestIntegration_PruningRemovesOnlyDeadSSOSessions(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "prune.sessions.example.com", false)
	user := seedUser(t, s, tn, "alice")
	now := time.Now().UTC()

	live := newTestSSOSession(tn, user.ID, now)
	expired := newTestSSOSession(tn, user.ID, now.Add(-48*time.Hour))
	idle := newTestSSOSession(tn, user.ID, now.Add(-9*time.Hour))
	require.NoError(t, s.SaveSSOSession(ctx, live, hashOf("live")))
	require.NoError(t, s.SaveSSOSession(ctx, expired, hashOf("expired")))
	require.NoError(t, s.SaveSSOSession(ctx, idle, hashOf("idle")))

	require.NoError(t, s.PruneExpiredTokens(ctx))

	var count int
	require.NoError(t, s.pool.QueryRow(ctx, `SELECT count(*) FROM sso_sessions`).Scan(&count))
	assert.Equal(t, 1, count, "only the live session is left")
	_, err := s.GetActiveSSOSession(ctx, tn.id, hashOf("live"), now)
	require.NoError(t, err)
}

func TestIntegration_SSOSessionsDisappearWithTheirUserAndTenant(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "cascade.sessions.example.com", false)
	user := seedUser(t, s, tn, "alice")
	now := time.Now().UTC()
	require.NoError(t, s.SaveSSOSession(ctx, newTestSSOSession(tn, user.ID, now), hashOf("c")))

	require.NoError(t, s.DeleteTenant(ctx, tn.id))

	var count int
	require.NoError(t, s.pool.QueryRow(ctx, `SELECT count(*) FROM sso_sessions`).Scan(&count))
	assert.Zero(t, count, "deleting a tenant cascades to its sessions")
}

func TestIntegration_SSOSessionTokenHashMustBe32Bytes(t *testing.T) {
	s := newIntegrationStorage(t)
	tn := seedTenant(t, s, "hash.sessions.example.com", false)
	now := time.Now().UTC()

	err := s.SaveSSOSession(context.Background(), newTestSSOSession(tn, seedUser(t, s, tn, "alice").ID, now), []byte("short"))

	require.Error(t, err, "only a SHA-256 hash is accepted, never a raw value")
}
