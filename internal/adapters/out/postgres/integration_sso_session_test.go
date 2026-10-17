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
		ID: uuid.New(), TenantID: tn.id, PartitionID: tn.partition, State: model.SSOSessionActive, UserProfileID: userID,
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

	got, err := s.GetLiveSSOSession(ctx, tn.id, hashOf("secret-1"), now)
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

	got, err := s.GetLiveSSOSession(ctx, tn.id, hashOf("bare"), now)
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

	_, err := s.GetLiveSSOSession(ctx, tn.id, hashOf("s"), now.Add(8*time.Hour-time.Second))
	require.NoError(t, err, "just before the idle deadline")

	_, err = s.GetLiveSSOSession(ctx, tn.id, hashOf("s"), now.Add(8*time.Hour))
	require.ErrorIs(t, err, port.ErrSessionNotFound, "idle deadline reached")

	// Keeping the session busy moves the idle deadline, but never past the absolute one.
	require.NoError(t, s.TouchSSOSession(ctx, tn.id, hashOf("s"), now.Add(7*time.Hour), now.Add(25*time.Hour)))
	_, err = s.GetLiveSSOSession(ctx, tn.id, hashOf("s"), now.Add(24*time.Hour-time.Second))
	require.NoError(t, err, "the touch extended the idle deadline")
	_, err = s.GetLiveSSOSession(ctx, tn.id, hashOf("s"), now.Add(24*time.Hour))
	require.ErrorIs(t, err, port.ErrSessionNotFound, "the absolute lifetime still wins")
}

func TestIntegration_SSOSessionIsBoundToItsTenant(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	a := seedTenant(t, s, "a.sessions.example.com", false)
	b := seedTenant(t, s, "b.sessions.example.com", false)
	now := time.Now().UTC()
	require.NoError(t, s.SaveSSOSession(ctx, newTestSSOSession(a, seedUser(t, s, a, "alice").ID, now), hashOf("a-secret")))

	_, err := s.GetLiveSSOSession(ctx, b.id, hashOf("a-secret"), now)

	require.ErrorIs(t, err, port.ErrSessionNotFound, "a valid secret of tenant A must not open tenant B")
}

func TestIntegration_SSOSessionUnknownSecretIsNotFound(t *testing.T) {
	s := newIntegrationStorage(t)
	tn := seedTenant(t, s, "unknown.sessions.example.com", false)

	_, err := s.GetLiveSSOSession(context.Background(), tn.id, hashOf("never-issued"), time.Now())

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

	got, err := s.GetLiveSSOSession(ctx, a.id, hashOf("a"), now)
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
	_, err := s.GetLiveSSOSession(ctx, tn.id, hashOf("one"), now)
	require.NoError(t, err)

	require.NoError(t, s.DeleteSSOSession(ctx, tn.id, first.ID))
	_, err = s.GetLiveSSOSession(ctx, tn.id, hashOf("one"), now)
	require.ErrorIs(t, err, port.ErrSessionNotFound)
	_, err = s.GetLiveSSOSession(ctx, tn.id, hashOf("two"), now)
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
		_, err := s.GetLiveSSOSession(ctx, tn.id, hashOf(secret), now)
		require.ErrorIs(t, err, port.ErrSessionNotFound)
	}
	_, err := s.GetLiveSSOSession(ctx, tn.id, hashOf("bob"), now)
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

	_, err := s.GetLiveSSOSession(ctx, a.id, hashOf("a"), now)
	require.ErrorIs(t, err, port.ErrSessionNotFound)
	_, err = s.GetLiveSSOSession(ctx, b.id, hashOf("b"), now)
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
	_, err := s.GetLiveSSOSession(ctx, tn.id, hashOf("live"), now)
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

// ---- sign-in in progress: pending sessions, promotion and the flow binding ----

func newPendingSSOSession(tn seededTenant, now time.Time) model.SSOSession {
	return model.SSOSession{
		ID: uuid.New(), TenantID: tn.id, PartitionID: tn.partition, State: model.SSOSessionPending,
		AuthTime: now, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(15 * time.Minute), IdleExpiresAt: now.Add(15 * time.Minute),
	}
}

func TestIntegration_APendingSessionNamesNoUser(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "pending.sessions.example.com", false)
	now := time.Now().UTC().Truncate(time.Second)
	pending := newPendingSSOSession(tn, now)

	require.NoError(t, s.SaveSSOSession(ctx, pending, hashOf("pending")))

	got, err := s.GetLiveSSOSession(ctx, tn.id, hashOf("pending"), now)
	require.NoError(t, err)
	assert.Equal(t, model.SSOSessionPending, got.State)
	assert.Equal(t, uuid.Nil, got.UserProfileID)
}

func TestIntegration_TheDatabaseRefusesAPendingSessionWithAUserAndAnActiveOneWithout(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "constraint.sessions.example.com", false)
	now := time.Now().UTC()
	user := seedUser(t, s, tn, "alice")

	pendingWithUser := newPendingSSOSession(tn, now)
	pendingWithUser.UserProfileID = user.ID
	require.Error(t, s.SaveSSOSession(ctx, pendingWithUser, hashOf("a")), "a pending session must not name a user")

	activeWithoutUser := newPendingSSOSession(tn, now)
	activeWithoutUser.State = model.SSOSessionActive
	require.Error(t, s.SaveSSOSession(ctx, activeWithoutUser, hashOf("b")), "an active session must name a user")
}

func promoted(session model.SSOSession, user uuid.UUID, now time.Time) model.SSOSession {
	session.State = model.SSOSessionActive
	session.UserProfileID = user
	session.AuthTime, session.LastSeenAt = now, now
	session.ExpiresAt, session.IdleExpiresAt = now.Add(24*time.Hour), now.Add(8*time.Hour)
	return session
}

func TestIntegration_PromotingASessionKeepsItsIDAndReplacesTheSecret(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "promote.sessions.example.com", false)
	user := seedUser(t, s, tn, "alice")
	now := time.Now().UTC().Truncate(time.Second)
	pending := newPendingSSOSession(tn, now)
	require.NoError(t, s.SaveSSOSession(ctx, pending, hashOf("old-secret")))

	require.NoError(t, s.PromoteSSOSession(ctx, promoted(pending, user.ID, now), hashOf("new-secret"), now))

	_, err := s.GetLiveSSOSession(ctx, tn.id, hashOf("old-secret"), now)
	require.ErrorIs(t, err, port.ErrSessionNotFound, "the secret of the flow no longer opens anything")
	got, err := s.GetLiveSSOSession(ctx, tn.id, hashOf("new-secret"), now)
	require.NoError(t, err)
	assert.Equal(t, pending.ID, got.ID)
	assert.Equal(t, model.SSOSessionActive, got.State)
	assert.Equal(t, user.ID, got.UserProfileID)
	assert.True(t, now.Add(24*time.Hour).Equal(got.ExpiresAt), "the full lifetime starts at sign-in")
}

func TestIntegration_AnActiveSessionCannotBePromotedAgain(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "twice.sessions.example.com", false)
	user, other := seedUser(t, s, tn, "alice"), seedUser(t, s, tn, "mallory")
	now := time.Now().UTC()
	pending := newPendingSSOSession(tn, now)
	require.NoError(t, s.SaveSSOSession(ctx, pending, hashOf("p")))
	require.NoError(t, s.PromoteSSOSession(ctx, promoted(pending, user.ID, now), hashOf("first"), now))

	err := s.PromoteSSOSession(ctx, promoted(pending, other.ID, now), hashOf("second"), now)

	require.ErrorIs(t, err, port.ErrSessionNotFound, "a double submit or a replay signs in once; the session never changes hands")
	got, err := s.GetLiveSSOSession(ctx, tn.id, hashOf("first"), now)
	require.NoError(t, err)
	assert.Equal(t, user.ID, got.UserProfileID)
}

func TestIntegration_PromotionRefusesAnotherTenantPartitionOrExpiry(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	a := seedTenant(t, s, "a.promote.example.com", false)
	b := seedTenant(t, s, "b.promote.example.com", false)
	user := seedUser(t, s, a, "alice")
	now := time.Now().UTC()
	pending := newPendingSSOSession(a, now)
	require.NoError(t, s.SaveSSOSession(ctx, pending, hashOf("p")))

	otherTenant := promoted(pending, user.ID, now)
	otherTenant.TenantID = b.id
	require.ErrorIs(t, s.PromoteSSOSession(ctx, otherTenant, hashOf("x"), now), port.ErrSessionNotFound)

	otherPartition := promoted(pending, user.ID, now)
	otherPartition.PartitionID = a.partition + 1000
	require.ErrorIs(t, s.PromoteSSOSession(ctx, otherPartition, hashOf("y"), now), port.ErrSessionNotFound)

	require.ErrorIs(t, s.PromoteSSOSession(ctx, promoted(pending, user.ID, now), hashOf("z"), now.Add(16*time.Minute)), port.ErrSessionNotFound, "expired")

	_, err := s.GetLiveSSOSession(ctx, a.id, hashOf("p"), now)
	require.NoError(t, err, "every refused promotion leaves the pending session as it was")
}

func TestIntegration_TouchOnlyMovesTheIdleDeadlineOfAnActiveSession(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "touch.pending.example.com", false)
	now := time.Now().UTC().Truncate(time.Second)
	pending := newPendingSSOSession(tn, now)
	require.NoError(t, s.SaveSSOSession(ctx, pending, hashOf("p")))

	require.NoError(t, s.TouchSSOSession(ctx, tn.id, hashOf("p"), now.Add(time.Minute), now.Add(time.Hour)))

	got, err := s.GetLiveSSOSession(ctx, tn.id, hashOf("p"), now)
	require.NoError(t, err)
	assert.True(t, pending.IdleExpiresAt.Equal(got.IdleExpiresAt), "a sign-in in progress cannot be kept alive")
}

func seedFlow(t *testing.T, s *PostgresStorage, tn seededTenant, session model.SSOSession, state string) {
	t.Helper()
	require.NoError(t, s.SaveOutboundHandshake(context.Background(), model.OutboundHandshakeSession{
		ID: state, TenantID: tn.id, PartitionID: tn.partition, IdentityProviderID: tn.ssoIDP, ClientID: "c",
		CodeVerifier: "v", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Minute),
		CallbackURI: "https://cb", TargetURI: "https://target", SessionID: session.ID,
	}))
}

func TestIntegration_AHandshakeStateOnlyRedeemsForTheBrowserThatStartedIt(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "handshake.sessions.example.com", false)
	now := time.Now().UTC()
	mine, theirs := newPendingSSOSession(tn, now), newPendingSSOSession(tn, now)
	require.NoError(t, s.SaveSSOSession(ctx, mine, hashOf("mine")))
	require.NoError(t, s.SaveSSOSession(ctx, theirs, hashOf("theirs")))
	seedFlow(t, s, tn, mine, "state-1")

	_, err := s.GetAndConsumeOutboundHandshake(ctx, tn.id, "state-1", []uuid.UUID{theirs.ID})
	require.ErrorIs(t, err, port.ErrSessionNotFound, "a callback URL sent to another browser is refused")

	_, err = s.GetAndConsumeOutboundHandshake(ctx, tn.id, "state-1", nil)
	require.ErrorIs(t, err, port.ErrSessionNotFound, "no cookie, no redemption")

	_, err = s.GetAndConsumeOutboundHandshake(ctx, tn.id, "state-1", []uuid.UUID{})
	require.ErrorIs(t, err, port.ErrSessionNotFound)

	got, err := s.GetAndConsumeOutboundHandshake(ctx, tn.id, "state-1", []uuid.UUID{theirs.ID, mine.ID})
	require.NoError(t, err, "the refused attempts did not consume the state")
	assert.Equal(t, mine.ID, got.SessionID)
	assert.Equal(t, "https://target", got.TargetURI)

	_, err = s.GetAndConsumeOutboundHandshake(ctx, tn.id, "state-1", []uuid.UUID{mine.ID})
	require.ErrorIs(t, err, port.ErrSessionNotFound, "a state redeems once")
}

func TestIntegration_AnInteractionSessionKeepsItsBindingAndPartition(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "interaction.sessions.example.com", false)
	now := time.Now().UTC()
	pending := newPendingSSOSession(tn, now)
	require.NoError(t, s.SaveSSOSession(ctx, pending, hashOf("p")))
	interaction := model.InteractionSession{
		ID: uuid.New(), TenantID: tn.id, PartitionID: tn.partition, ClientID: "c", RedirectURI: "https://cb",
		ExpiresAt: now.Add(10 * time.Minute), State: "s", Nonce: "n", SessionID: pending.ID,
	}
	require.NoError(t, s.SaveInteractionSession(ctx, interaction))

	got, err := s.GetInteractionSession(ctx, tn.id, interaction.ID)
	require.NoError(t, err)
	assert.Equal(t, pending.ID, got.SessionID)
	assert.Equal(t, tn.partition, got.PartitionID, "the partition used to be lost on every read")

	consumed, err := s.GetAndConsumeInteractionSession(ctx, tn.id, interaction.ID)
	require.NoError(t, err)
	assert.Equal(t, pending.ID, consumed.SessionID)
	assert.Equal(t, tn.partition, consumed.PartitionID)
}

func TestIntegration_AnInteractionWithoutABindingReadsBackAsUnbound(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "unbound.sessions.example.com", false)
	interaction := model.InteractionSession{
		ID: uuid.New(), TenantID: tn.id, PartitionID: tn.partition, ClientID: "c", RedirectURI: "https://cb",
		ExpiresAt: time.Now().Add(time.Minute), State: "s", Nonce: "n",
	}
	require.NoError(t, s.SaveInteractionSession(ctx, interaction))

	got, err := s.GetInteractionSession(ctx, tn.id, interaction.ID)
	require.NoError(t, err)
	assert.Equal(t, uuid.Nil, got.SessionID, "flows from before the binding cannot be completed by anybody")
}

func TestIntegration_DeletingASessionEndsTheFlowsBoundToIt(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "cascade.flows.example.com", false)
	now := time.Now().UTC()
	pending := newPendingSSOSession(tn, now)
	require.NoError(t, s.SaveSSOSession(ctx, pending, hashOf("p")))
	seedFlow(t, s, tn, pending, "state-9")
	interaction := model.InteractionSession{
		ID: uuid.New(), TenantID: tn.id, PartitionID: tn.partition, ClientID: "c", RedirectURI: "https://cb",
		ExpiresAt: now.Add(time.Minute), State: "s", Nonce: "n", SessionID: pending.ID,
	}
	require.NoError(t, s.SaveInteractionSession(ctx, interaction))

	require.NoError(t, s.DeleteSSOSession(ctx, tn.id, pending.ID))

	_, err := s.GetInteractionSession(ctx, tn.id, interaction.ID)
	require.ErrorIs(t, err, port.ErrInteractionSessionNotFound)
	_, err = s.GetAndConsumeOutboundHandshake(ctx, tn.id, "state-9", []uuid.UUID{pending.ID})
	require.ErrorIs(t, err, port.ErrSessionNotFound)
}

func TestIntegration_PruningAnExpiredPendingSessionTakesItsFlowsWithIt(t *testing.T) {
	s := newIntegrationStorage(t)
	ctx := context.Background()
	tn := seedTenant(t, s, "prune.flows.example.com", false)
	longAgo := time.Now().UTC().Add(-time.Hour)
	expired := newPendingSSOSession(tn, longAgo)
	require.NoError(t, s.SaveSSOSession(ctx, expired, hashOf("old")))
	seedFlow(t, s, tn, expired, "state-old")

	require.NoError(t, s.PruneExpiredTokens(ctx))

	var sessions, handshakes int
	require.NoError(t, s.pool.QueryRow(ctx, `SELECT count(*) FROM sso_sessions`).Scan(&sessions))
	require.NoError(t, s.pool.QueryRow(ctx, `SELECT count(*) FROM outbound_handshake_sessions`).Scan(&handshakes))
	assert.Zero(t, sessions)
	assert.Zero(t, handshakes)
}
