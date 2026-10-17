package model

import (
	"time"

	"github.com/google/uuid"
)

// SSOSession is a browser single-sign-on session held on the server.
// The browser only holds an opaque random secret; the secret is never part of this model and only its hash is stored.
// ID is the public identifier: it is the OIDC "sid" claim and the anchor of client session links.
type SSOSession struct {
	ID                 uuid.UUID
	TenantID           uuid.UUID
	PartitionID        int64
	UserProfileID      uuid.UUID
	IdentityProviderID uuid.UUID // uuid.Nil when the sign-in did not go through a known provider
	ACR                string
	AMR                []string
	AuthTime           time.Time
	CreatedAt          time.Time
	LastSeenAt         time.Time
	ExpiresAt          time.Time // absolute deadline
	IdleExpiresAt      time.Time // moves forward while the session is used
}
