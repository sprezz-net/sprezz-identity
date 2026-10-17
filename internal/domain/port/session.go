package port

import (
	"context"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

// =========================================================================
// 1. SSO SESSION & COOKIE COORDINATOR BOUNDARIES
// =========================================================================

type CookieIntentCommand struct {
	TenantID       uuid.UUID
	PartitionID    int64
	PayloadValue   string
	LifecycleStage string // "handshake" | "clear"
	RequestHost    string // For r.Host environment calculation checks [8.3]
}

type CookieIntentResponse struct {
	CookieName  string
	CookieValue string
	MaxAge      int
	Secure      bool
}

// CreateSessionCommand carries the outcome of a successful sign-in.
type CreateSessionCommand struct {
	TenantID           uuid.UUID
	PartitionID        int64
	UserProfileID      uuid.UUID
	IdentityProviderID uuid.UUID // uuid.Nil when unknown
	ACR                string
	AMR                []string
	RequestHost        string
}

// CreatedSession is returned once, at sign-in. Token is the raw cookie secret and is never stored or logged.
type CreatedSession struct {
	Session model.SSOSession
	Token   string
	Cookie  CookieIntentResponse
}

// SSOSessionUseCase owns the browser single-sign-on session: the cookie that carries it and the server-side record
// behind it. The cookie is an opaque random secret, so a session can be listed, expired and revoked on the server.
type SSOSessionUseCase interface {
	// BuildSessionCookie resolves the name and attributes of the partition cookie. It issues the short-lived
	// "handshake" value or an eviction ("clear"); signed-in sessions come from CreateSession.
	BuildSessionCookie(ctx context.Context, cmd CookieIntentCommand) (*CookieIntentResponse, error)
	// ParseSessionCookie reads the "handshake:<payload>" value that carries the state of a sign-in in progress.
	ParseSessionCookie(ctx context.Context, cookieValue string) (stage string, payload string, err error)

	// CreateSession records a new signed-in session and returns the cookie to set.
	CreateSession(ctx context.Context, cmd CreateSessionCommand) (*CreatedSession, error)
	// ResolveSession returns the live session behind a cookie value, or ErrSessionNotFound. It never errors for
	// garbage, expired, idle or revoked values; those are simply not sessions.
	ResolveSession(ctx context.Context, tenantID uuid.UUID, cookieValue string) (*model.SSOSession, error)
	// RevokeSession ends one session (sign out).
	RevokeSession(ctx context.Context, tenantID uuid.UUID, sessionID uuid.UUID) error
	// RevokeUserSessions ends every session of a user (sign out everywhere, blocked or deleted accounts).
	RevokeUserSessions(ctx context.Context, tenantID uuid.UUID, userProfileID uuid.UUID) error
}

// =========================================================================
// 2. IDENTITY ASSURANCE GATING PORT CONTRACT
// =========================================================================

type SecurityAccessAssertion struct {
	TenantID     uuid.UUID
	ProviderID   uuid.UUID
	TargetAction string // "profile_view" | "change_email" | "change_password" [4.3]
}

type IdentityAssuranceUseCase interface {
	AssertActionTrust(ctx context.Context, cmd SecurityAccessAssertion) error
}
