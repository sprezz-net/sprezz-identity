package model

import (
	"time"

	"github.com/google/uuid"
)

// SSOSessionState tells a sign-in in progress from a signed-in browser.
type SSOSessionState string

const (
	// SSOSessionPending is the cookie of a sign-in in progress. It names no user and authenticates nobody; it only
	// binds the login, sign-up and federation callback to the browser that started the flow.
	SSOSessionPending SSOSessionState = "PENDING"
	// SSOSessionActive is a signed-in browser.
	SSOSessionActive SSOSessionState = "ACTIVE"
)

// SSOSession is a browser single-sign-on session held on the server.
// The browser only holds an opaque random secret; the secret is never part of this model and only its hash is stored.
// A pending session names no user. ID is the public identifier: it is the OIDC "sid" claim and the anchor of client session links.
type SSOSession struct {
	ID                 uuid.UUID
	TenantID           uuid.UUID
	PartitionID        int64
	State              SSOSessionState
	UserProfileID      uuid.UUID // uuid.Nil while the session is pending
	IdentityProviderID uuid.UUID // uuid.Nil when the sign-in did not go through a known provider
	ACR                string
	AMR                []string
	AuthTime           time.Time
	CreatedAt          time.Time
	LastSeenAt         time.Time
	ExpiresAt          time.Time // absolute deadline
	IdleExpiresAt      time.Time // moves forward while the session is used
}
