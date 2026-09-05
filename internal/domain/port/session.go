package port

import (
	"context"

	"github.com/google/uuid"
)

// =========================================================================
// 1. SSO SESSION & COOKIE COORDINATOR BOUNDARIES
// =========================================================================

type CookieIntentCommand struct {
	TenantID       uuid.UUID
	PartitionID    int64
	PayloadValue   string
	LifecycleStage string // "handshake" | "bearer" | "clear"
	RequestHost    string // For r.Host environment calculation checks [8.3]
}

type CookieIntentResponse struct {
	CookieName  string
	CookieValue string
	MaxAge      int
	Secure      bool
}

// SSOSessionUseCase completely drives Use Case 4, exposing both cookie emission
// intent mapping and incoming request token dissection hooks.
type SSOSessionUseCase interface {
	BuildSessionCookie(ctx context.Context, cmd CookieIntentCommand) (*CookieIntentResponse, error)
	ParseSessionCookie(ctx context.Context, cookieValue string) (stage string, payload string, err error)
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
