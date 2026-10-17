package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

// sessionTokenBytes is the size of the random cookie secret: 256 bits.
const sessionTokenBytes = 32

// SSOSessionPolicy sets how long a browser session lives. The administrative partition gets its own, shorter limits.
type SSOSessionPolicy struct {
	AbsoluteLifetime      time.Duration // hard limit from sign-in
	IdleTimeout           time.Duration // sign out after this long without a request
	AdminAbsoluteLifetime time.Duration
	AdminIdleTimeout      time.Duration
	// PendingLifetime is how long a sign-in in progress may take. It does not slide.
	PendingLifetime time.Duration
	// TouchInterval limits how often "last seen" is written, so a busy session does not cause a write per request.
	TouchInterval time.Duration
}

// DefaultSSOSessionPolicy returns the limits used when nothing is configured.
func DefaultSSOSessionPolicy() SSOSessionPolicy {
	return SSOSessionPolicy{
		AbsoluteLifetime:      24 * time.Hour,
		IdleTimeout:           8 * time.Hour,
		AdminAbsoluteLifetime: 8 * time.Hour,
		AdminIdleTimeout:      time.Hour,
		PendingLifetime:       15 * time.Minute,
		TouchInterval:         time.Minute,
	}
}

// withDefaults fills zero values, so a partially configured policy never yields a session that never expires.
func (p SSOSessionPolicy) withDefaults() SSOSessionPolicy {
	d := DefaultSSOSessionPolicy()
	if p.AbsoluteLifetime <= 0 {
		p.AbsoluteLifetime = d.AbsoluteLifetime
	}
	if p.IdleTimeout <= 0 {
		p.IdleTimeout = d.IdleTimeout
	}
	if p.AdminAbsoluteLifetime <= 0 {
		p.AdminAbsoluteLifetime = d.AdminAbsoluteLifetime
	}
	if p.AdminIdleTimeout <= 0 {
		p.AdminIdleTimeout = d.AdminIdleTimeout
	}
	if p.PendingLifetime <= 0 {
		p.PendingLifetime = d.PendingLifetime
	}
	if p.TouchInterval <= 0 {
		p.TouchInterval = d.TouchInterval
	}
	return p
}

// limitsFor returns the absolute and idle limits of a partition.
func (p SSOSessionPolicy) limitsFor(partitionAlias string) (time.Duration, time.Duration) {
	if partitionAlias == model.AdminPartitionAliasName {
		return p.AdminAbsoluteLifetime, p.AdminIdleTimeout
	}
	return p.AbsoluteLifetime, p.IdleTimeout
}

type SSOSessionService struct {
	storage port.Storage
	clock   port.Clock
	appEnv  string
	policy  SSOSessionPolicy
}

func NewSSOSessionService(s port.Storage, clock port.Clock, appEnv string, policy SSOSessionPolicy) *SSOSessionService {
	return &SSOSessionService{storage: s, clock: clock, appEnv: appEnv, policy: policy.withDefaults()}
}

// cookieTarget is the name and transport flags of the partition cookie.
type cookieTarget struct {
	name           string
	secure         bool
	partitionAlias string
	partitionID    int64
}

// resolveCookieTarget enforces partition namespacing and the environment security prefix [8.3, 8.3.1, 8.3.2].
func (s *SSOSessionService) resolveCookieTarget(ctx context.Context, tenantID uuid.UUID, partitionID int64) (*cookieTarget, error) {
	if partitionID == 0 {
		tenant, err := s.storage.ResolveTenantByUUID(ctx, tenantID)
		if err == nil && tenant.DefaultPartition != nil {
			partitionID = *tenant.DefaultPartition
		}
	}

	partition, err := s.storage.GetPartitionByID(ctx, tenantID, partitionID)
	if err != nil {
		return nil, port.ErrPartitionNotFound
	}

	target := &cookieTarget{
		name:           "spz_session_" + partition.AliasName,
		secure:         true,
		partitionAlias: partition.AliasName,
		partitionID:    partitionID,
	}
	if s.appEnv == "local" {
		target.secure = false // Local unencrypted debugging loop permitted [8.3]
	} else {
		target.name = "__Host-" + target.name
	}
	return target, nil
}

// BuildSessionCookie resolves the name and flags of the partition cookie. Signed-in sessions are issued by
// CreateSession and PromoteSession, pending ones by StartFlow; this is only for reading or evicting the cookie.
func (s *SSOSessionService) BuildSessionCookie(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
	if cmd.LifecycleStage != "clear" {
		return nil, errors.New("sso_cookie_service: invalid token lifecycle stage identifier")
	}

	// Clearing a cookie never needs an active tenant, so people can always sign out.
	target, err := s.resolveCookieTarget(ctx, cmd.TenantID, cmd.PartitionID)
	if err != nil {
		return nil, err
	}
	return &port.CookieIntentResponse{CookieName: target.name, Secure: target.secure, MaxAge: -1}, nil
}

// StartFlow returns the session of the browser that is starting a sign-in in a partition, or creates a pending one.
// A browser that already has a live session cookie for the partition keeps it: a second tab shares the binding of
// the first, and a signed-in browser is never signed out by starting another flow. Only a client that sends no
// cookie creates a row per request, which needs rate limiting.
func (s *SSOSessionService) StartFlow(ctx context.Context, cmd port.StartFlowCommand) (*port.StartedFlow, error) {
	if _, err := ensureTenantActive(ctx, s.storage, cmd.TenantID); err != nil {
		return nil, err
	}

	target, err := s.resolveCookieTarget(ctx, cmd.TenantID, cmd.PartitionID)
	if err != nil {
		return nil, err
	}

	if existing := s.liveSessionOfPartition(ctx, cmd, target); existing != nil {
		return &port.StartedFlow{Session: *existing}, nil
	}

	token, hash, err := newSessionSecret()
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	session := model.SSOSession{
		ID:            uuid.New(),
		TenantID:      cmd.TenantID,
		PartitionID:   target.partitionID,
		State:         model.SSOSessionPending,
		AMR:           []string{},
		AuthTime:      now,
		CreatedAt:     now,
		LastSeenAt:    now,
		ExpiresAt:     now.Add(s.policy.PendingLifetime),
		IdleExpiresAt: now.Add(s.policy.PendingLifetime),
	}
	if err := s.storage.SaveSSOSession(ctx, session, hash); err != nil {
		return nil, fmt.Errorf("sso_session_service: failed to store pending session: %w", err)
	}

	return &port.StartedFlow{
		Session: session,
		Cookie: &port.CookieIntentResponse{
			CookieName:  target.name,
			CookieValue: token,
			MaxAge:      int(s.policy.PendingLifetime / time.Second),
			Secure:      target.secure,
		},
	}, nil
}

// liveSessionOfPartition resolves the session behind the cookie this browser sent for the partition.
func (s *SSOSessionService) liveSessionOfPartition(ctx context.Context, cmd port.StartFlowCommand, target *cookieTarget) *model.SSOSession {
	hash, ok := hashSessionSecret(cmd.Cookies[target.name])
	if !ok {
		return nil
	}
	session, err := s.storage.GetLiveSSOSession(ctx, cmd.TenantID, hash, s.clock.Now())
	if err != nil || session.PartitionID != target.partitionID {
		return nil
	}
	return session
}

// ResolveFlowSession returns the session behind the cookie of the partition when it is the one the flow was started
// with. A flow without a binding never matches, so flows created before the binding existed cannot be completed.
func (s *SSOSessionService) ResolveFlowSession(ctx context.Context, tenantID uuid.UUID, partitionID int64, cookies map[string]string, flowSessionID uuid.UUID) (*model.SSOSession, error) {
	if flowSessionID == uuid.Nil {
		return nil, port.ErrSessionNotFound
	}
	if _, err := ensureTenantActive(ctx, s.storage, tenantID); err != nil {
		return nil, err
	}
	target, err := s.resolveCookieTarget(ctx, tenantID, partitionID)
	if err != nil {
		return nil, err
	}
	hash, ok := hashSessionSecret(cookies[target.name])
	if !ok {
		return nil, port.ErrSessionNotFound
	}
	session, err := s.storage.GetLiveSSOSession(ctx, tenantID, hash, s.clock.Now())
	if err != nil {
		return nil, err
	}
	if session.ID != flowSessionID || session.PartitionID != target.partitionID {
		return nil, port.ErrSessionNotFound
	}
	return session, nil
}

// ResolveDirectFlowSession returns the pending or active session behind the cookie of the partition, for a sign-in
// that has no interaction session to bind to.
func (s *SSOSessionService) ResolveDirectFlowSession(ctx context.Context, tenantID uuid.UUID, partitionID int64, cookies map[string]string) (*model.SSOSession, error) {
	if _, err := ensureTenantActive(ctx, s.storage, tenantID); err != nil {
		return nil, err
	}
	target, err := s.resolveCookieTarget(ctx, tenantID, partitionID)
	if err != nil {
		return nil, err
	}
	hash, ok := hashSessionSecret(cookies[target.name])
	if !ok {
		return nil, port.ErrSessionNotFound
	}
	session, err := s.storage.GetLiveSSOSession(ctx, tenantID, hash, s.clock.Now())
	if err != nil {
		return nil, err
	}
	if session.PartitionID != target.partitionID {
		return nil, port.ErrSessionNotFound
	}
	return session, nil
}

// maxFlowCookies bounds the lookups one callback can cause.
const maxFlowCookies = 8

// ResolveFlowSessionIDs returns the pending sessions behind the session cookies the browser sent.
func (s *SSOSessionService) ResolveFlowSessionIDs(ctx context.Context, tenantID uuid.UUID, cookies map[string]string) ([]uuid.UUID, error) {
	if _, err := ensureTenantActive(ctx, s.storage, tenantID); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	ids := []uuid.UUID{}
	checked := 0
	for name, value := range cookies {
		if !isSessionCookieName(name) {
			continue
		}
		if checked++; checked > maxFlowCookies {
			break
		}
		hash, ok := hashSessionSecret(value)
		if !ok {
			continue
		}
		if session, err := s.storage.GetLiveSSOSession(ctx, tenantID, hash, now); err == nil && session.State == model.SSOSessionPending {
			ids = append(ids, session.ID)
		}
	}
	return ids, nil
}

func isSessionCookieName(name string) bool {
	return strings.HasPrefix(strings.TrimPrefix(name, "__Host-"), "spz_session_")
}

// ResolvePartitionSession returns the signed-in session behind the cookie of the partition.
func (s *SSOSessionService) ResolvePartitionSession(ctx context.Context, tenantID uuid.UUID, partitionID int64, cookies map[string]string) (*model.SSOSession, error) {
	target, err := s.resolveCookieTarget(ctx, tenantID, partitionID)
	if err != nil {
		return nil, err
	}
	session, err := s.ResolveSession(ctx, tenantID, cookies[target.name])
	if err != nil {
		return nil, err
	}
	if session.PartitionID != target.partitionID {
		return nil, port.ErrSessionNotFound
	}
	return session, nil
}

// PromoteSession turns the pending session of a flow into the signed-in session. The secret is replaced, so the
// cookie the flow ran under is dead the moment the user is signed in (no session fixation), while the session ID
// stays, so the other flows of this browser stay bound to it.
func (s *SSOSessionService) PromoteSession(ctx context.Context, cmd port.PromoteSessionCommand) (*port.CreatedSession, error) {
	if _, err := ensureTenantActive(ctx, s.storage, cmd.TenantID); err != nil {
		return nil, err
	}
	target, err := s.resolveCookieTarget(ctx, cmd.TenantID, cmd.PartitionID)
	if err != nil {
		return nil, err
	}
	token, hash, err := newSessionSecret()
	if err != nil {
		return nil, err
	}

	absolute, idle := s.policy.limitsFor(target.partitionAlias)
	now := s.clock.Now()
	session := model.SSOSession{
		ID:                 cmd.SessionID,
		TenantID:           cmd.TenantID,
		PartitionID:        target.partitionID,
		State:              model.SSOSessionActive,
		UserProfileID:      cmd.UserProfileID,
		IdentityProviderID: cmd.IdentityProviderID,
		ACR:                cmd.ACR,
		AMR:                nonNilStrings(cmd.AMR),
		AuthTime:           now,
		CreatedAt:          now,
		LastSeenAt:         now,
		ExpiresAt:          now.Add(absolute),
		IdleExpiresAt:      now.Add(idle),
	}
	if err := s.storage.PromoteSSOSession(ctx, session, hash, now); err != nil {
		return nil, err
	}

	return &port.CreatedSession{
		Session: session,
		Token:   token,
		Cookie: port.CookieIntentResponse{
			CookieName:  target.name,
			CookieValue: token,
			MaxAge:      int(absolute / time.Second),
			Secure:      target.secure,
		},
	}, nil
}

// CreateSession stores a new session and returns the cookie that carries it. The cookie value is a fresh random
// secret, so signing in again always yields a new session and a planted cookie never becomes valid (no fixation).
func (s *SSOSessionService) CreateSession(ctx context.Context, cmd port.CreateSessionCommand) (*port.CreatedSession, error) {
	if _, err := ensureTenantActive(ctx, s.storage, cmd.TenantID); err != nil {
		return nil, err
	}

	target, err := s.resolveCookieTarget(ctx, cmd.TenantID, cmd.PartitionID)
	if err != nil {
		return nil, err
	}

	token, hash, err := newSessionSecret()
	if err != nil {
		return nil, err
	}

	absolute, idle := s.policy.limitsFor(target.partitionAlias)
	now := s.clock.Now()
	session := model.SSOSession{
		ID:                 uuid.New(),
		TenantID:           cmd.TenantID,
		PartitionID:        target.partitionID,
		State:              model.SSOSessionActive,
		UserProfileID:      cmd.UserProfileID,
		IdentityProviderID: cmd.IdentityProviderID,
		ACR:                cmd.ACR,
		AMR:                nonNilStrings(cmd.AMR),
		AuthTime:           now,
		CreatedAt:          now,
		LastSeenAt:         now,
		ExpiresAt:          now.Add(absolute),
		IdleExpiresAt:      now.Add(idle),
	}
	if err := s.storage.SaveSSOSession(ctx, session, hash); err != nil {
		return nil, fmt.Errorf("sso_session_service: failed to store session: %w", err)
	}

	return &port.CreatedSession{
		Session: session,
		Token:   token,
		Cookie: port.CookieIntentResponse{
			CookieName:  target.name,
			CookieValue: token,
			MaxAge:      int(absolute / time.Second),
			Secure:      target.secure,
		},
	}, nil
}

// ResolveSession turns a cookie value into the live session behind it. Values that are not a live session (garbage,
// unknown, expired, idle, revoked, other tenant) all give ErrSessionNotFound.
func (s *SSOSessionService) ResolveSession(ctx context.Context, tenantID uuid.UUID, cookieValue string) (*model.SSOSession, error) {
	if _, err := ensureTenantActive(ctx, s.storage, tenantID); err != nil {
		return nil, err
	}

	hash, ok := hashSessionSecret(cookieValue)
	if !ok {
		return nil, port.ErrSessionNotFound
	}

	now := s.clock.Now()
	session, err := s.storage.GetLiveSSOSession(ctx, tenantID, hash, now)
	if err != nil {
		return nil, err
	}
	if session.State != model.SSOSessionActive {
		// A sign-in in progress names no user and authenticates nothing.
		return nil, port.ErrSessionNotFound
	}

	s.touch(ctx, session, hash, now)
	return session, nil
}

// touch slides the idle deadline, at most once per TouchInterval. The idle length is read back from the row, so
// every partition keeps its own limit without another lookup. A failed touch is not worth failing the request for.
func (s *SSOSessionService) touch(ctx context.Context, session *model.SSOSession, hash []byte, now time.Time) {
	if now.Sub(session.LastSeenAt) < s.policy.TouchInterval {
		return
	}

	idle := session.IdleExpiresAt.Sub(session.LastSeenAt)
	if err := s.storage.TouchSSOSession(ctx, session.TenantID, hash, now, now.Add(idle)); err != nil {
		return
	}
	session.LastSeenAt = now
	session.IdleExpiresAt = now.Add(idle)
}

// RevokeSession ends one session. Ending sessions only reduces access, so it works for inactive tenants too.
func (s *SSOSessionService) RevokeSession(ctx context.Context, tenantID uuid.UUID, sessionID uuid.UUID) error {
	return s.storage.DeleteSSOSession(ctx, tenantID, sessionID)
}

// RevokeUserSessions ends every session of a user.
func (s *SSOSessionService) RevokeUserSessions(ctx context.Context, tenantID uuid.UUID, userProfileID uuid.UUID) error {
	return s.storage.DeleteSSOSessionsByUser(ctx, tenantID, userProfileID)
}

// newSessionSecret returns a fresh cookie secret and the hash that is stored for it.
func newSessionSecret() (string, []byte, error) {
	raw := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("sso_session_service: no randomness available: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

// hashSessionSecret hashes a presented cookie value. Anything that cannot be a secret we issued (wrong length or
// alphabet) is rejected before the database is asked.
func hashSessionSecret(token string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != sessionTokenBytes {
		return nil, false
	}
	sum := sha256.Sum256([]byte(token))
	return sum[:], true
}
