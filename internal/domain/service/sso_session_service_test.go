package service

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSOSessionService_BuildSessionCookie_ExplicitPartition(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)

	allowTenant(storage)
	svc := NewSSOSessionService(storage, portmock.NewMockClock(time.Now()), "local", SSOSessionPolicy{})

	tenantID := uuid.New()
	partitionID := int64(42)

	storage.GetPartitionByIDMock.Expect(minimock.AnyContext, tenantID, partitionID).Return(&model.Partition{
		ID:        partitionID,
		Name:      "test-partition",
		AliasName: "test_part",
	}, nil)

	resp, err := svc.BuildSessionCookie(context.Background(), port.CookieIntentCommand{
		TenantID:       tenantID,
		PartitionID:    partitionID,
		LifecycleStage: "handshake",
		PayloadValue:   "some-state-token",
		RequestHost:    "localhost",
	})
	require.NoError(t, err)

	assert.Equal(t, "spz_session_test_part", resp.CookieName)
	assert.Equal(t, "handshake:some-state-token", resp.CookieValue)
	assert.Equal(t, 300, resp.MaxAge)
	assert.False(t, resp.Secure, "local env may use plain http")
}

func TestSSOSessionService_BuildSessionCookie_ZeroPartition_Fallback(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	svc := NewSSOSessionService(storage, portmock.NewMockClock(time.Now()), "production", SSOSessionPolicy{})

	tenantID := uuid.New()
	defaultPartID := int64(100)

	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantID).Return(&model.Tenant{
		ID:               tenantID,
		DefaultPartition: &defaultPartID,
		IsActive:         true,
	}, nil)
	storage.GetPartitionByIDMock.Expect(minimock.AnyContext, tenantID, defaultPartID).Return(&model.Partition{
		ID:        defaultPartID,
		Name:      "default-partition",
		AliasName: "default",
	}, nil)

	resp, err := svc.BuildSessionCookie(context.Background(), port.CookieIntentCommand{
		TenantID:       tenantID,
		PartitionID:    0, // Trigger fallback
		LifecycleStage: "handshake",
		PayloadValue:   "state",
		RequestHost:    "login.sprezz.com",
	})
	require.NoError(t, err)

	assert.Equal(t, "__Host-spz_session_default", resp.CookieName)
	assert.True(t, resp.Secure)
}

func TestSSOSessionService_BuildSessionCookie_RefusesToIssueASignedInValue(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	allowTenant(storage)
	svc := NewSSOSessionService(storage, portmock.NewMockClock(time.Now()), "local", SSOSessionPolicy{})
	storage.GetPartitionByIDMock.Optional().Return(&model.Partition{ID: 1, AliasName: "default"}, nil)

	// "bearer" used to carry an unsigned user ID. Signed-in cookies now only come from CreateSession.
	_, err := svc.BuildSessionCookie(context.Background(), port.CookieIntentCommand{
		TenantID: uuid.New(), PartitionID: 1, LifecycleStage: "bearer", PayloadValue: "anything",
	})
	require.Error(t, err)
}

func TestSSOSessionService_ParseSessionCookie(t *testing.T) {
	svc := NewSSOSessionService(nil, nil, "local", SSOSessionPolicy{})

	tests := []struct {
		name      string
		value     string
		wantStage string
		wantPay   string
		wantErr   bool
	}{
		{name: "Valid handshake", value: "handshake:my-payload", wantStage: "handshake", wantPay: "my-payload"},
		{name: "Payload may contain a colon", value: "handshake:a:b", wantStage: "handshake", wantPay: "a:b"},
		{name: "Old bearer value is not accepted", value: "bearer:user-uuid:1", wantErr: true},
		{name: "Empty cookie", value: "", wantErr: true},
		{name: "No separator", value: "invalidcookievalue", wantErr: true},
		{name: "Invalid lifecycle stage", value: "unknown:payload", wantErr: true},
		{name: "Empty payload", value: "handshake:", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stage, payload, err := svc.ParseSessionCookie(context.Background(), tt.value)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantStage, stage)
			assert.Equal(t, tt.wantPay, payload)
		})
	}
}

// sessionFixture wires the service to an in-memory style storage mock that records the saved session.
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

func TestSSOSessionService_ResolveSession_RejectsValuesThatCannotBeOurSecrets(t *testing.T) {
	// The storage mock is strict: a malformed value must be refused before the database is asked.
	f := newSessionFixture(t, "default")

	for name, value := range map[string]string{
		"empty":         "",
		"old format":    "bearer:6f1c0d1e-0000-0000-0000-000000000000:1",
		"a user id":     uuid.NewString(),
		"too short":     base64.RawURLEncoding.EncodeToString([]byte("short")),
		"not base64":    "!!!!",
		"too long":      base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		"padded base64": base64.URLEncoding.EncodeToString(make([]byte, 32)),
		"standard b64":  base64.StdEncoding.EncodeToString([]byte{0xfb, 0xff, 0xbf, 0xfb, 0xff, 0xbf, 0xfb, 0xff, 0xbf, 0xfb, 0xff, 0xbf, 0xfb, 0xff, 0xbf, 0xfb, 0xff, 0xbf, 0xfb, 0xff, 0xbf, 0xfb, 0xff, 0xbf, 0xfb, 0xff, 0xbf, 0xfb, 0xff, 0xbf, 0xfb, 0xff}),
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
	f.storage.GetActiveSSOSessionMock.Set(func(_ context.Context, tenantID uuid.UUID, hash []byte, now time.Time) (*model.SSOSession, error) {
		lookedUp = hash
		assert.Equal(t, f.tenantID, tenantID)
		assert.Equal(t, f.clock.Now(), now)
		s := f.saved
		return s, nil
	})

	got, err := f.svc.ResolveSession(context.Background(), f.tenantID, created.Token)

	require.NoError(t, err)
	assert.Equal(t, created.Session.ID, got.ID)
	assert.Equal(t, f.hash, lookedUp, "the same hash that was stored at sign-in")
}

func TestSSOSessionService_ResolveSession_UnknownOrExpiredIsNotASession(t *testing.T) {
	f := newSessionFixture(t, "default")
	created := f.create(t)
	f.storage.GetActiveSSOSessionMock.Return(nil, port.ErrSessionNotFound)

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
	f.storage.GetActiveSSOSessionMock.Set(func(context.Context, uuid.UUID, []byte, time.Time) (*model.SSOSession, error) {
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
	f.storage.GetActiveSSOSessionMock.Set(func(context.Context, uuid.UUID, []byte, time.Time) (*model.SSOSession, error) {
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
	f.storage.GetActiveSSOSessionMock.Set(func(context.Context, uuid.UUID, []byte, time.Time) (*model.SSOSession, error) {
		s := *f.saved
		return &s, nil
	})
	f.storage.TouchSSOSessionMock.Return(errors.New("db busy"))

	f.clock.Advance(5 * time.Minute)
	got, err := f.svc.ResolveSession(context.Background(), f.tenantID, created.Token)

	require.NoError(t, err)
	assert.Equal(t, created.Session.ID, got.ID)
}

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

func TestSSOSessionPolicy_ZeroValuesFallBackToTheDefaults(t *testing.T) {
	got := SSOSessionPolicy{AbsoluteLifetime: time.Hour}.withDefaults()

	assert.Equal(t, time.Hour, got.AbsoluteLifetime)
	assert.Equal(t, DefaultSSOSessionPolicy().IdleTimeout, got.IdleTimeout, "never an unbounded session")
	assert.Equal(t, DefaultSSOSessionPolicy().AdminIdleTimeout, got.AdminIdleTimeout)
	assert.Equal(t, DefaultSSOSessionPolicy().TouchInterval, got.TouchInterval)
}
