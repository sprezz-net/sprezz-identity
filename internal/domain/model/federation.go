package model

import (
	"time"

	"github.com/google/uuid"
)

// OutboundOidcRequest defines parameters needed to generate an outbound federation flow.
type OutboundOidcRequest struct {
	ClientID         string            `json:"client_id"`
	RedirectURI      string            `json:"redirect_uri"`
	TargetURI        string            `json:"target_uri"`
	Scopes           []string          `json:"scopes"`
	IdentityProvider *IdentityProvider `json:"identity_provider,omitempty"` // Complete dynamic configuration context
}

// OutboundHandshakeSession secures the transient protocol metrics required
// to validate incoming callbacks across both admin and user federation routes.
type OutboundHandshakeSession struct {
	ID                 string    `json:"id"`                     // Maps to the tracking state key token
	TenantID           uuid.UUID `json:"tenant_id"`              // LINK: Public tracking UUID partition key
	IdentityProviderID uuid.UUID `json:"identity_provider_id"`   // LINK: Which external IDP initiated this flow?
	ClientID           string    `json:"client_id"`              // Tracking which client initiated the request
	CodeVerifier       string    `json:"code_verifier"`          // Safe storage for the PKCE secret string
	ExpiresAt          time.Time `json:"expires_at"`             // Strict short-lived expiration tracking
	AccessToken        string    `json:"access_token,omitempty"` // Reused if stored downstream inside cookies
	TargetURI          string    `json:"target_uri"`             // Remembers where to return the user
}

// OidcLoginIntent holds the public, non-sensitive transport metrics
// returned by the domain service to orchestrate an outbound redirection.
type OidcLoginIntent struct {
	// AuthURL is the complete target redirection URL built for the browser
	// (e.g., https://upstream-idp.com...)
	AuthURL string `json:"auth_url"`

	// State is the public high-entropy tracking key string used to cross-reference
	// the transaction when the user returns to our callback route
	State string `json:"state"`

	// CodeChallenge is the cryptographically hashed representation of the PKCE verifier
	// sent upstream to bind the future authorization code exchange
	CodeChallenge string `json:"code_challenge,omitempty"`
}
