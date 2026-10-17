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
	LifecycleStage string // "clear": resolve the partition cookie name and evict it
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

// StartFlowCommand starts, or continues, a sign-in in a partition.
type StartFlowCommand struct {
	TenantID    uuid.UUID
	PartitionID int64
	// Cookies are the cookies the browser sent, by name. The domain picks the one of the partition.
	Cookies     map[string]string
	RequestHost string
}

// StartedFlow is the pending session that binds a sign-in to its browser.
type StartedFlow struct {
	Session model.SSOSession
	// Cookie is set when a pending session was created. It is nil when the browser's own pending session was reused.
	Cookie *CookieIntentResponse
}

// PromoteSessionCommand turns the pending session of a flow into a signed-in session.
type PromoteSessionCommand struct {
	TenantID           uuid.UUID
	SessionID          uuid.UUID // the pending session
	PartitionID        int64
	UserProfileID      uuid.UUID
	IdentityProviderID uuid.UUID // uuid.Nil when unknown
	ACR                string
	AMR                []string
	RequestHost        string
}

// SSOSessionUseCase owns the browser single-sign-on session: the cookie that carries it and the server-side record
// behind it. The cookie is an opaque random secret, so a session can be listed, expired and revoked on the server.
//
// A session is either pending (a sign-in in progress, naming no user) or active (a signed-in browser). ResolveSession
// only ever returns active sessions, so a pending one can never authenticate anything. Only the sign-in handlers use
// ResolveFlowSession, which also returns pending ones.
type SSOSessionUseCase interface {
	// BuildSessionCookie resolves the name and attributes of the partition cookie, to read or to evict it.
	BuildSessionCookie(ctx context.Context, cmd CookieIntentCommand) (*CookieIntentResponse, error)

	// StartFlow returns the browser's own live session for the partition (pending, or active when already signed in),
	// or creates a pending one and the cookie that carries it.
	StartFlow(ctx context.Context, cmd StartFlowCommand) (*StartedFlow, error)
	// ResolveFlowSession returns the pending or active session behind the cookie of the partition, but only when it is
	// the session the flow was started with (flowSessionID). Anything else, including a flow that has no binding
	// (uuid.Nil), gives ErrSessionNotFound: the cookie of another browser, no cookie, or an expired session.
	ResolveFlowSession(ctx context.Context, tenantID uuid.UUID, partitionID int64, cookies map[string]string, flowSessionID uuid.UUID) (*model.SSOSession, error)
	// ResolveDirectFlowSession is ResolveFlowSession for a sign-in that did not start at /authorize (the login page
	// opened directly, so there is no interaction session to bind to): it returns the pending or active session
	// behind the cookie of the partition.
	ResolveDirectFlowSession(ctx context.Context, tenantID uuid.UUID, partitionID int64, cookies map[string]string) (*model.SSOSession, error)
	// ResolveFlowSessionIDs returns the pending sessions behind the session cookies a browser sent. The federation
	// callback does not know the partition of the flow before it redeems the state, so it offers all of them.
	ResolveFlowSessionIDs(ctx context.Context, tenantID uuid.UUID, cookies map[string]string) ([]uuid.UUID, error)
	// ResolvePartitionSession returns the signed-in session behind the cookie of the partition, or ErrSessionNotFound.
	ResolvePartitionSession(ctx context.Context, tenantID uuid.UUID, partitionID int64, cookies map[string]string) (*model.SSOSession, error)
	// PromoteSession turns a pending session into an active one under a fresh secret and returns the new cookie.
	// It fails with ErrSessionNotFound unless the session is pending, unexpired and in that partition, so a double
	// submit cannot sign in twice.
	PromoteSession(ctx context.Context, cmd PromoteSessionCommand) (*CreatedSession, error)

	// CreateSession records a new signed-in session in one step, for sign-ins that have no flow to bind.
	CreateSession(ctx context.Context, cmd CreateSessionCommand) (*CreatedSession, error)
	// ResolveSession returns the live signed-in session behind a cookie value, or ErrSessionNotFound. It never errors
	// for garbage, expired, idle, pending or revoked values; those are simply not signed in.
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
