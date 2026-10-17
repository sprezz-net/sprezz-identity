package service

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"sprezz-identity/internal/adapters/out/memory"
	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// flowFixture runs the session service against the in-memory store, so the flow scenarios (start, bind, promote,
// replay, revoke) exercise the real lifecycle instead of canned answers.
type flowFixture struct {
	svc       *SSOSessionService
	storage   *memory.Storage
	clock     *portmock.MockClock
	tenantID  uuid.UUID
	partition model.Partition
	admin     model.Partition
}

func newFlowFixture(t *testing.T) *flowFixture {
	t.Helper()
	f := &flowFixture{
		storage:  memory.NewStorage("production"),
		clock:    portmock.NewMockClock(time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)),
		tenantID: uuid.New(),
	}
	require.NoError(t, f.storage.CreateTenant(context.Background(), model.Tenant{ID: f.tenantID, Domain: "flow.example.com", IsActive: true}))

	defaultPart, err := f.storage.CreatePartition(context.Background(), f.tenantID, "Customers", "customers")
	require.NoError(t, err)
	adminPart, err := f.storage.CreatePartition(context.Background(), f.tenantID, "Admin", model.AdminPartitionAliasName)
	require.NoError(t, err)
	f.partition, f.admin = *defaultPart, *adminPart

	f.svc = NewSSOSessionService(f.storage, f.clock, "production", SSOSessionPolicy{})
	return f
}

// cookies is what a browser sends: the partition cookie with the given value.
func (f *flowFixture) cookies(partition model.Partition, value string) map[string]string {
	return map[string]string{"__Host-spz_session_" + partition.AliasName: value}
}

// start is a browser starting a sign-in, with the cookies it already holds.
func (f *flowFixture) start(t *testing.T, partition model.Partition, held map[string]string) *port.StartedFlow {
	t.Helper()
	flow, err := f.svc.StartFlow(context.Background(), port.StartFlowCommand{TenantID: f.tenantID, PartitionID: partition.ID, Cookies: held})
	require.NoError(t, err)
	return flow
}

func (f *flowFixture) promote(partition model.Partition, sessionID uuid.UUID) (*port.CreatedSession, error) {
	return f.svc.PromoteSession(context.Background(), port.PromoteSessionCommand{
		TenantID: f.tenantID, SessionID: sessionID, PartitionID: partition.ID, UserProfileID: uuid.New(),
	})
}

func TestSSOSessionService_BuildSessionCookie_NamesAndEvictsThePartitionCookie(t *testing.T) {
	f := newFlowFixture(t)

	resp, err := f.svc.BuildSessionCookie(context.Background(), port.CookieIntentCommand{
		TenantID: f.tenantID, PartitionID: f.partition.ID, LifecycleStage: "clear",
	})

	require.NoError(t, err)
	assert.Equal(t, "__Host-spz_session_customers", resp.CookieName)
	assert.Equal(t, -1, resp.MaxAge)
	assert.True(t, resp.Secure)
}

func TestSSOSessionService_BuildSessionCookie_LocalEnvironmentUsesPlainNameAndHttp(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	storage.GetPartitionByIDMock.Return(&model.Partition{ID: 42, AliasName: "test_part"}, nil)
	svc := NewSSOSessionService(storage, portmock.NewMockClock(time.Now()), "local", SSOSessionPolicy{})

	resp, err := svc.BuildSessionCookie(context.Background(), port.CookieIntentCommand{TenantID: uuid.New(), PartitionID: 42, LifecycleStage: "clear"})

	require.NoError(t, err)
	assert.Equal(t, "spz_session_test_part", resp.CookieName)
	assert.False(t, resp.Secure)
}

func TestSSOSessionService_BuildSessionCookie_ZeroPartitionFallsBackToTheDefault(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	svc := NewSSOSessionService(storage, portmock.NewMockClock(time.Now()), "production", SSOSessionPolicy{})
	tenantID, defaultPartID := uuid.New(), int64(100)
	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantID).Return(&model.Tenant{ID: tenantID, DefaultPartition: &defaultPartID, IsActive: true}, nil)
	storage.GetPartitionByIDMock.Expect(minimock.AnyContext, tenantID, defaultPartID).Return(&model.Partition{ID: defaultPartID, AliasName: "default"}, nil)

	resp, err := svc.BuildSessionCookie(context.Background(), port.CookieIntentCommand{TenantID: tenantID, LifecycleStage: "clear"})

	require.NoError(t, err)
	assert.Equal(t, "__Host-spz_session_default", resp.CookieName)
}

func TestSSOSessionService_BuildSessionCookie_OnlyEvicts(t *testing.T) {
	f := newFlowFixture(t)

	for _, stage := range []string{"handshake", "bearer", ""} {
		_, err := f.svc.BuildSessionCookie(context.Background(), port.CookieIntentCommand{
			TenantID: f.tenantID, PartitionID: f.partition.ID, LifecycleStage: stage,
		})
		require.Errorf(t, err, "stage %q must not issue a cookie", stage)
	}
}

// ---- starting a sign-in ----

func TestStartFlow_CreatesAPendingSessionThatNamesNoUser(t *testing.T) {
	f := newFlowFixture(t)

	flow := f.start(t, f.partition, nil)

	require.NotNil(t, flow.Cookie, "a browser without a session gets a cookie")
	assert.Equal(t, model.SSOSessionPending, flow.Session.State)
	assert.Equal(t, uuid.Nil, flow.Session.UserProfileID)
	assert.Equal(t, f.clock.Now().Add(15*time.Minute), flow.Session.ExpiresAt, "a sign-in has 15 minutes")
	assert.Equal(t, 900, flow.Cookie.MaxAge)
	assert.Equal(t, "__Host-spz_session_customers", flow.Cookie.CookieName)

	raw, err := base64.RawURLEncoding.DecodeString(flow.Cookie.CookieValue)
	require.NoError(t, err)
	assert.Len(t, raw, 32, "the same 256-bit secret as a signed-in session")
}

func TestStartFlow_ABrowserThatAlreadyHasAPendingSessionKeepsIt(t *testing.T) {
	f := newFlowFixture(t)
	first := f.start(t, f.partition, nil)

	second := f.start(t, f.partition, f.cookies(f.partition, first.Cookie.CookieValue))

	assert.Equal(t, first.Session.ID, second.Session.ID, "a second tab shares the binding of the first")
	assert.Nil(t, second.Cookie, "no new cookie is needed")
}

func TestStartFlow_ACookieThatIsNotLiveGetsAFreshSession(t *testing.T) {
	f := newFlowFixture(t)
	first := f.start(t, f.partition, nil)
	f.clock.Advance(16 * time.Minute) // the pending session has expired

	second := f.start(t, f.partition, f.cookies(f.partition, first.Cookie.CookieValue))

	assert.NotEqual(t, first.Session.ID, second.Session.ID)
	require.NotNil(t, second.Cookie)
}

func TestStartFlow_ACookieOfAnotherPartitionIsNotReused(t *testing.T) {
	f := newFlowFixture(t)
	other := f.start(t, f.admin, nil)

	// The admin pending cookie presented under the customers cookie name must not bind a customers flow.
	flow := f.start(t, f.partition, f.cookies(f.partition, other.Cookie.CookieValue))

	assert.NotEqual(t, other.Session.ID, flow.Session.ID)
	assert.Equal(t, f.partition.ID, flow.Session.PartitionID)
}

func TestStartFlow_ASignedInBrowserKeepsItsSession(t *testing.T) {
	f := newFlowFixture(t)
	pending := f.start(t, f.partition, nil)
	signedIn, err := f.promote(f.partition, pending.Session.ID)
	require.NoError(t, err)

	flow := f.start(t, f.partition, f.cookies(f.partition, signedIn.Token))

	assert.Equal(t, model.SSOSessionActive, flow.Session.State, "starting another flow never signs anybody out")
	assert.Equal(t, signedIn.Session.ID, flow.Session.ID)
}

func TestStartFlow_RefusesAnInactiveTenant(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl) // strict: nothing is stored
	storage.ResolveTenantByUUIDMock.Return(&model.Tenant{IsActive: false}, nil)
	svc := NewSSOSessionService(storage, portmock.NewMockClock(time.Now()), "production", SSOSessionPolicy{})

	_, err := svc.StartFlow(context.Background(), port.StartFlowCommand{TenantID: uuid.New(), PartitionID: 1})

	require.ErrorIs(t, err, port.ErrTenantInactive)
}

// ---- a pending session never authenticates ----

func TestPendingSession_NeverAuthenticatesAnything(t *testing.T) {
	f := newFlowFixture(t)
	flow := f.start(t, f.partition, nil)

	_, err := f.svc.ResolveSession(context.Background(), f.tenantID, flow.Cookie.CookieValue)
	require.ErrorIs(t, err, port.ErrSessionNotFound, "ResolveSession only ever returns signed-in sessions")

	_, err = f.svc.ResolvePartitionSession(context.Background(), f.tenantID, f.partition.ID, f.cookies(f.partition, flow.Cookie.CookieValue))
	require.ErrorIs(t, err, port.ErrSessionNotFound)
}

func TestPendingSession_IsNotTouchedByIdleSliding(t *testing.T) {
	f := newFlowFixture(t)
	flow := f.start(t, f.partition, nil)

	f.clock.Advance(14 * time.Minute)
	_, _ = f.svc.ResolveSession(context.Background(), f.tenantID, flow.Cookie.CookieValue)

	f.clock.Advance(2 * time.Minute) // 16 minutes after the start
	_, err := f.svc.ResolveDirectFlowSession(context.Background(), f.tenantID, f.partition.ID, f.cookies(f.partition, flow.Cookie.CookieValue))
	require.ErrorIs(t, err, port.ErrSessionNotFound, "a sign-in cannot be kept alive for ever")
}

// ---- binding a flow to its browser ----

func TestResolveFlowSession_OnlyTheBrowserThatStartedTheFlowMatches(t *testing.T) {
	f := newFlowFixture(t)
	mine := f.start(t, f.partition, nil)
	theirs := f.start(t, f.partition, nil) // another browser, no cookies

	got, err := f.svc.ResolveFlowSession(context.Background(), f.tenantID, f.partition.ID, f.cookies(f.partition, mine.Cookie.CookieValue), mine.Session.ID)
	require.NoError(t, err)
	assert.Equal(t, mine.Session.ID, got.ID)

	_, err = f.svc.ResolveFlowSession(context.Background(), f.tenantID, f.partition.ID, f.cookies(f.partition, theirs.Cookie.CookieValue), mine.Session.ID)
	require.ErrorIs(t, err, port.ErrSessionNotFound, "another browser's cookie does not open this flow")

	_, err = f.svc.ResolveFlowSession(context.Background(), f.tenantID, f.partition.ID, map[string]string{}, mine.Session.ID)
	require.ErrorIs(t, err, port.ErrSessionNotFound, "no cookie, no flow")

	_, err = f.svc.ResolveFlowSession(context.Background(), f.tenantID, f.partition.ID, f.cookies(f.partition, "not-a-secret"), mine.Session.ID)
	require.ErrorIs(t, err, port.ErrSessionNotFound, "garbage")
}

func TestResolveFlowSession_AFlowWithoutABindingNeverMatches(t *testing.T) {
	f := newFlowFixture(t)
	mine := f.start(t, f.partition, nil)

	// A flow created before the binding existed carries uuid.Nil and cannot be completed by anybody.
	_, err := f.svc.ResolveFlowSession(context.Background(), f.tenantID, f.partition.ID, f.cookies(f.partition, mine.Cookie.CookieValue), uuid.Nil)

	require.ErrorIs(t, err, port.ErrSessionNotFound)
}

func TestResolveFlowSession_TheCookieOfAnotherPartitionDoesNotMatch(t *testing.T) {
	f := newFlowFixture(t)
	adminFlow := f.start(t, f.admin, nil)

	_, err := f.svc.ResolveFlowSession(context.Background(), f.tenantID, f.partition.ID, f.cookies(f.partition, adminFlow.Cookie.CookieValue), adminFlow.Session.ID)

	require.ErrorIs(t, err, port.ErrSessionNotFound)
}

func TestResolveFlowSession_AnExpiredFlowIsRefused(t *testing.T) {
	f := newFlowFixture(t)
	mine := f.start(t, f.partition, nil)
	f.clock.Advance(15 * time.Minute)

	_, err := f.svc.ResolveFlowSession(context.Background(), f.tenantID, f.partition.ID, f.cookies(f.partition, mine.Cookie.CookieValue), mine.Session.ID)

	require.ErrorIs(t, err, port.ErrSessionNotFound)
}

func TestResolveFlowSessionIDs_OffersOnlyThePendingSessionsOfTheBrowser(t *testing.T) {
	f := newFlowFixture(t)
	pending := f.start(t, f.partition, nil)
	adminFlow := f.start(t, f.admin, nil)
	signedIn := f.start(t, f.partition, nil)
	active, err := f.promote(f.partition, signedIn.Session.ID)
	require.NoError(t, err)

	cookies := map[string]string{
		"__Host-spz_session_customers":                        pending.Cookie.CookieValue,
		"__Host-spz_session_" + model.AdminPartitionAliasName: adminFlow.Cookie.CookieValue,
		"__Host-spz_session_other":                            active.Token, // a signed-in session is not a flow
		"unrelated":                                           pending.Cookie.CookieValue,
		"__Host-spz_session_garbage":                          "garbage",
	}

	ids, err := f.svc.ResolveFlowSessionIDs(context.Background(), f.tenantID, cookies)

	require.NoError(t, err)
	assert.ElementsMatch(t, []uuid.UUID{pending.Session.ID, adminFlow.Session.ID}, ids)
}

func TestResolveFlowSessionIDs_BoundsTheLookupsOfOneRequest(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	allowTenant(storage)
	var lookups int
	storage.GetLiveSSOSessionMock.Set(func(context.Context, uuid.UUID, []byte, time.Time) (*model.SSOSession, error) {
		lookups++
		return nil, port.ErrSessionNotFound
	})
	svc := NewSSOSessionService(storage, portmock.NewMockClock(time.Now()), "production", SSOSessionPolicy{})

	cookies := map[string]string{}
	for i := 0; i < 50; i++ {
		token, _, err := newSessionSecret()
		require.NoError(t, err)
		cookies["__Host-spz_session_p"+string(rune('a'+i%26))+string(rune('a'+i/26))] = token
	}

	_, err := svc.ResolveFlowSessionIDs(context.Background(), uuid.New(), cookies)

	require.NoError(t, err)
	assert.LessOrEqual(t, lookups, maxFlowCookies, "a request cannot make the server do unbounded lookups")
}

func TestResolveDirectFlowSession_ReturnsThePendingOrActiveSessionOfThePartition(t *testing.T) {
	f := newFlowFixture(t)
	pending := f.start(t, f.partition, nil)

	got, err := f.svc.ResolveDirectFlowSession(context.Background(), f.tenantID, f.partition.ID, f.cookies(f.partition, pending.Cookie.CookieValue))
	require.NoError(t, err)
	assert.Equal(t, model.SSOSessionPending, got.State)

	signedIn, err := f.promote(f.partition, pending.Session.ID)
	require.NoError(t, err)
	got, err = f.svc.ResolveDirectFlowSession(context.Background(), f.tenantID, f.partition.ID, f.cookies(f.partition, signedIn.Token))
	require.NoError(t, err)
	assert.Equal(t, model.SSOSessionActive, got.State)

	_, err = f.svc.ResolveDirectFlowSession(context.Background(), f.tenantID, f.admin.ID, f.cookies(f.admin, signedIn.Token))
	require.ErrorIs(t, err, port.ErrSessionNotFound, "a session of another partition")
}

// ---- signing in: promotion ----

func TestPromoteSession_KeepsTheSessionIDAndReplacesTheSecret(t *testing.T) {
	f := newFlowFixture(t)
	pending := f.start(t, f.partition, nil)

	signedIn, err := f.promote(f.partition, pending.Session.ID)

	require.NoError(t, err)
	assert.Equal(t, pending.Session.ID, signedIn.Session.ID, "other tabs of this browser stay bound")
	assert.NotEqual(t, pending.Cookie.CookieValue, signedIn.Token, "the secret of the flow is replaced")
	assert.Equal(t, model.SSOSessionActive, signedIn.Session.State)
	assert.Equal(t, f.clock.Now().Add(24*time.Hour), signedIn.Session.ExpiresAt, "the full lifetime starts at sign-in")
	assert.Equal(t, 86400, signedIn.Cookie.MaxAge)

	_, err = f.svc.ResolveFlowSession(context.Background(), f.tenantID, f.partition.ID, f.cookies(f.partition, pending.Cookie.CookieValue), pending.Session.ID)
	require.ErrorIs(t, err, port.ErrSessionNotFound, "the old cookie is dead: a planted cookie never becomes a session (no fixation)")

	got, err := f.svc.ResolveSession(context.Background(), f.tenantID, signedIn.Token)
	require.NoError(t, err)
	assert.Equal(t, signedIn.Session.UserProfileID, got.UserProfileID)
}

func TestPromoteSession_AppliesTheLimitsOfThePartition(t *testing.T) {
	f := newFlowFixture(t)
	pending := f.start(t, f.admin, nil)

	signedIn, err := f.promote(f.admin, pending.Session.ID)

	require.NoError(t, err)
	assert.Equal(t, f.clock.Now().Add(8*time.Hour), signedIn.Session.ExpiresAt)
	assert.Equal(t, f.clock.Now().Add(time.Hour), signedIn.Session.IdleExpiresAt)
}

func TestPromoteSession_CanOnlyHappenOnce(t *testing.T) {
	f := newFlowFixture(t)
	pending := f.start(t, f.partition, nil)
	_, err := f.promote(f.partition, pending.Session.ID)
	require.NoError(t, err)

	_, err = f.promote(f.partition, pending.Session.ID)

	require.ErrorIs(t, err, port.ErrSessionNotFound, "a double submit or a replayed callback signs in once")
}

func TestPromoteSession_RefusesWhatIsNotAPendingSessionOfThePartition(t *testing.T) {
	f := newFlowFixture(t)
	pending := f.start(t, f.partition, nil)

	_, err := f.promote(f.admin, pending.Session.ID)
	require.ErrorIs(t, err, port.ErrSessionNotFound, "another partition")

	_, err = f.promote(f.partition, uuid.New())
	require.ErrorIs(t, err, port.ErrSessionNotFound, "unknown session")

	f.clock.Advance(16 * time.Minute)
	_, err = f.promote(f.partition, pending.Session.ID)
	require.ErrorIs(t, err, port.ErrSessionNotFound, "expired sign-in")
}

func TestPromoteSession_RefusesAnInactiveTenant(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl) // strict: nothing is promoted
	storage.ResolveTenantByUUIDMock.Return(&model.Tenant{IsActive: false}, nil)
	svc := NewSSOSessionService(storage, portmock.NewMockClock(time.Now()), "production", SSOSessionPolicy{})

	_, err := svc.PromoteSession(context.Background(), port.PromoteSessionCommand{TenantID: uuid.New(), PartitionID: 1, SessionID: uuid.New()})

	require.ErrorIs(t, err, port.ErrTenantInactive)
}

// ---- opening a session in one step ----

type sessionFixture struct {
	svc      *SSOSessionService
	storage  *portmock.StorageMock
	clock    *portmock.MockClock
	tenantID uuid.UUID
	saved    *model.SSOSession
	hash     []byte
}

func newSessionFixture(t *testing.T, partitionAlias string) *sessionFixture {
	t.Helper()
	f := &sessionFixture{
		storage:  portmock.NewStorageMock(minimock.NewController(t)),
		clock:    portmock.NewMockClock(time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)),
		tenantID: uuid.New(),
	}
	f.svc = NewSSOSessionService(f.storage, f.clock, "production", SSOSessionPolicy{})
	allowTenant(f.storage)
	f.storage.GetPartitionByIDMock.Optional().Return(&model.Partition{ID: 7, AliasName: partitionAlias}, nil)
	f.storage.SaveSSOSessionMock.Optional().Set(func(_ context.Context, s model.SSOSession, hash []byte) error {
		f.saved = &s
		f.hash = hash
		return nil
	})
	return f
}

func (f *sessionFixture) create(t *testing.T) *port.CreatedSession {
	t.Helper()
	created, err := f.svc.CreateSession(context.Background(), port.CreateSessionCommand{
		TenantID: f.tenantID, PartitionID: 7, UserProfileID: uuid.New(),
	})
	require.NoError(t, err)
	return created
}

func TestSSOSessionService_CreateSession_IssuesAnOpaqueSecretAndStoresOnlyItsHash(t *testing.T) {
	f := newSessionFixture(t, "default")
	created := f.create(t)

	raw, err := base64.RawURLEncoding.DecodeString(created.Token)
	require.NoError(t, err)
	assert.Len(t, raw, 32, "256 bits of randomness")
	assert.Equal(t, created.Token, created.Cookie.CookieValue)
	assert.Equal(t, "__Host-spz_session_default", created.Cookie.CookieName)
	assert.True(t, created.Cookie.Secure)

	require.NotNil(t, f.saved)
	assert.Equal(t, model.SSOSessionActive, f.saved.State)
	assert.Len(t, f.hash, 32)
	assert.NotEqual(t, []byte(created.Token), f.hash, "the stored value is a hash, not the secret")
	assert.NotEqual(t, created.Token, f.saved.ID.String(), "the public session id is not the secret")
	assert.NotNil(t, f.saved.AMR, "a nil slice would be stored as NULL")
}

func TestSSOSessionService_CreateSession_EverySessionGetsAFreshSecret(t *testing.T) {
	f := newSessionFixture(t, "default")

	first := f.create(t)
	second := f.create(t)

	assert.NotEqual(t, first.Token, second.Token, "signing in again must never reuse or accept a planted value")
	assert.NotEqual(t, first.Session.ID, second.Session.ID)
}

func TestSSOSessionService_CreateSession_AppliesTheLimitsOfThePartition(t *testing.T) {
	cases := map[string]struct{ absolute, idle time.Duration }{
		"default":                     {24 * time.Hour, 8 * time.Hour},
		model.AdminPartitionAliasName: {8 * time.Hour, time.Hour},
	}
	for alias, want := range cases {
		t.Run(alias, func(t *testing.T) {
			f := newSessionFixture(t, alias)
			created := f.create(t)

			now := f.clock.Now()
			assert.Equal(t, now.Add(want.absolute), created.Session.ExpiresAt)
			assert.Equal(t, now.Add(want.idle), created.Session.IdleExpiresAt)
			assert.Equal(t, int(want.absolute/time.Second), created.Cookie.MaxAge)
			assert.Equal(t, now, created.Session.AuthTime)
		})
	}
}

func TestSSOSessionService_CreateSession_RefusesAnInactiveTenant(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	storage.ResolveTenantByUUIDMock.Return(&model.Tenant{IsActive: false}, nil)
	svc := NewSSOSessionService(storage, portmock.NewMockClock(time.Now()), "production", SSOSessionPolicy{})

	_, err := svc.CreateSession(context.Background(), port.CreateSessionCommand{TenantID: uuid.New(), PartitionID: 7})

	require.ErrorIs(t, err, port.ErrTenantInactive)
}

func TestSSOSessionService_CreateSession_ReportsAStorageFailure(t *testing.T) {
	f := newSessionFixture(t, "default")
	boom := errors.New("db down")
	f.storage.SaveSSOSessionMock.Set(func(context.Context, model.SSOSession, []byte) error { return boom })

	_, err := f.svc.CreateSession(context.Background(), port.CreateSessionCommand{TenantID: f.tenantID, PartitionID: 7})

	require.ErrorIs(t, err, boom)
}

// ---- resolving a signed-in session ----

func TestSSOSessionService_ResolveSession_RejectsValuesThatCannotBeOurSecrets(t *testing.T) {
	// The storage mock is strict: a malformed value must be refused before the database is asked.
	f := newSessionFixture(t, "default")

	for name, value := range map[string]string{
		"empty":         "",
		"old format":    "bearer:6f1c0d1e-0000-0000-0000-000000000000:1",
		"old handshake": "handshake:6f1c0d1e-0000-0000-0000-000000000000",
		"a user id":     uuid.NewString(),
		"too short":     base64.RawURLEncoding.EncodeToString([]byte("short")),
		"not base64":    "!!!!",
		"too long":      base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		"padded base64": base64.URLEncoding.EncodeToString(make([]byte, 32)),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.svc.ResolveSession(context.Background(), f.tenantID, value)
			require.ErrorIs(t, err, port.ErrSessionNotFound)
		})
	}
}

func TestSSOSessionService_ResolveSession_LooksUpByTheHashOfTheSecret(t *testing.T) {
	f := newSessionFixture(t, "default")
	created := f.create(t)

	var lookedUp []byte
	f.storage.GetLiveSSOSessionMock.Set(func(_ context.Context, tenantID uuid.UUID, hash []byte, now time.Time) (*model.SSOSession, error) {
		lookedUp = hash
		assert.Equal(t, f.tenantID, tenantID)
		assert.Equal(t, f.clock.Now(), now)
		return f.saved, nil
	})

	got, err := f.svc.ResolveSession(context.Background(), f.tenantID, created.Token)

	require.NoError(t, err)
	assert.Equal(t, created.Session.ID, got.ID)
	assert.Equal(t, f.hash, lookedUp, "the same hash that was stored at sign-in")
}

func TestSSOSessionService_ResolveSession_UnknownOrExpiredIsNotASession(t *testing.T) {
	f := newSessionFixture(t, "default")
	created := f.create(t)
	f.storage.GetLiveSSOSessionMock.Return(nil, port.ErrSessionNotFound)

	_, err := f.svc.ResolveSession(context.Background(), f.tenantID, created.Token)

	require.ErrorIs(t, err, port.ErrSessionNotFound)
}

func TestSSOSessionService_ResolveSession_RefusesAnInactiveTenant(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl) // strict: no session lookup is allowed
	storage.ResolveTenantByUUIDMock.Return(&model.Tenant{IsActive: false}, nil)
	svc := NewSSOSessionService(storage, portmock.NewMockClock(time.Now()), "production", SSOSessionPolicy{})

	token, _, err := newSessionSecret()
	require.NoError(t, err)

	_, err = svc.ResolveSession(context.Background(), uuid.New(), token)

	require.ErrorIs(t, err, port.ErrTenantInactive)
}

func TestSSOSessionService_ResolveSession_ThrottlesTheIdleExtension(t *testing.T) {
	f := newSessionFixture(t, "default")
	created := f.create(t)
	f.storage.GetLiveSSOSessionMock.Set(func(context.Context, uuid.UUID, []byte, time.Time) (*model.SSOSession, error) {
		s := *f.saved
		return &s, nil
	})
	var touches int
	var touchedIdle time.Time
	f.storage.TouchSSOSessionMock.Set(func(_ context.Context, _ uuid.UUID, hash []byte, lastSeen, idle time.Time) error {
		touches++
		touchedIdle = idle
		assert.Equal(t, f.hash, hash)
		assert.Equal(t, f.clock.Now(), lastSeen)
		return nil
	})

	_, err := f.svc.ResolveSession(context.Background(), f.tenantID, created.Token)
	require.NoError(t, err)
	assert.Zero(t, touches, "a request right after sign-in does not write")

	f.clock.Advance(30 * time.Second)
	_, err = f.svc.ResolveSession(context.Background(), f.tenantID, created.Token)
	require.NoError(t, err)
	assert.Zero(t, touches, "still inside the touch interval")

	f.clock.Advance(time.Minute)
	_, err = f.svc.ResolveSession(context.Background(), f.tenantID, created.Token)
	require.NoError(t, err)
	assert.Equal(t, 1, touches)
	assert.Equal(t, f.clock.Now().Add(8*time.Hour), touchedIdle, "the idle deadline keeps its length")
}

func TestSSOSessionService_ResolveSession_TouchKeepsThePartitionIdleLength(t *testing.T) {
	f := newSessionFixture(t, model.AdminPartitionAliasName)
	created := f.create(t)
	f.storage.GetLiveSSOSessionMock.Set(func(context.Context, uuid.UUID, []byte, time.Time) (*model.SSOSession, error) {
		s := *f.saved
		return &s, nil
	})
	var touchedIdle time.Time
	f.storage.TouchSSOSessionMock.Set(func(_ context.Context, _ uuid.UUID, _ []byte, _, idle time.Time) error {
		touchedIdle = idle
		return nil
	})

	f.clock.Advance(2 * time.Minute)
	_, err := f.svc.ResolveSession(context.Background(), f.tenantID, created.Token)

	require.NoError(t, err)
	assert.Equal(t, f.clock.Now().Add(time.Hour), touchedIdle, "the administrative idle timeout is one hour")
}

func TestSSOSessionService_ResolveSession_AFailedTouchDoesNotFailTheRequest(t *testing.T) {
	f := newSessionFixture(t, "default")
	created := f.create(t)
	f.storage.GetLiveSSOSessionMock.Set(func(context.Context, uuid.UUID, []byte, time.Time) (*model.SSOSession, error) {
		s := *f.saved
		return &s, nil
	})
	f.storage.TouchSSOSessionMock.Return(errors.New("db busy"))

	f.clock.Advance(5 * time.Minute)
	got, err := f.svc.ResolveSession(context.Background(), f.tenantID, created.Token)

	require.NoError(t, err)
	assert.Equal(t, created.Session.ID, got.ID)
}

// ---- signing out ----

func TestSSOSessionService_Revoke_WorksForAnInactiveTenant(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl) // strict: no tenant lookup is allowed
	svc := NewSSOSessionService(storage, portmock.NewMockClock(time.Now()), "production", SSOSessionPolicy{})
	tenantID, sessionID, userID := uuid.New(), uuid.New(), uuid.New()
	storage.DeleteSSOSessionMock.Expect(minimock.AnyContext, tenantID, sessionID).Return(nil)
	storage.DeleteSSOSessionsByUserMock.Expect(minimock.AnyContext, tenantID, userID).Return(nil)

	require.NoError(t, svc.RevokeSession(context.Background(), tenantID, sessionID), "signing out only reduces access")
	require.NoError(t, svc.RevokeUserSessions(context.Background(), tenantID, userID))
}

func TestSSOSessionService_RevokeEndsTheSessionAndEverythingBoundToIt(t *testing.T) {
	f := newFlowFixture(t)
	pending := f.start(t, f.partition, nil)
	signedIn, err := f.promote(f.partition, pending.Session.ID)
	require.NoError(t, err)

	require.NoError(t, f.svc.RevokeSession(context.Background(), f.tenantID, signedIn.Session.ID))

	_, err = f.svc.ResolveSession(context.Background(), f.tenantID, signedIn.Token)
	require.ErrorIs(t, err, port.ErrSessionNotFound)
}

func TestSSOSessionPolicy_ZeroValuesFallBackToTheDefaults(t *testing.T) {
	got := SSOSessionPolicy{AbsoluteLifetime: time.Hour}.withDefaults()

	assert.Equal(t, time.Hour, got.AbsoluteLifetime)
	assert.Equal(t, DefaultSSOSessionPolicy().IdleTimeout, got.IdleTimeout, "never an unbounded session")
	assert.Equal(t, DefaultSSOSessionPolicy().AdminIdleTimeout, got.AdminIdleTimeout)
	assert.Equal(t, DefaultSSOSessionPolicy().PendingLifetime, got.PendingLifetime)
	assert.Equal(t, DefaultSSOSessionPolicy().TouchInterval, got.TouchInterval)
}
