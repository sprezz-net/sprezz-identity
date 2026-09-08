package model

import (
	"time"

	"github.com/google/uuid"
)

// OIDC Request Constraints Carrier Struct
// Captures the parsed OIDC-compliant constraint rules extracted out of
// inbound client request parameters during the federation handshake leg.
type ACRConstraint struct {
	Essential bool     `json:"essential"`
	Values    []string `json:"values"`
}

// OutboundHandshakeSession secures the transient protocol metrics required
// to validate incoming callbacks across both admin and user federation routes.
type OutboundHandshakeSession struct {
	ID                 string    `json:"id"`                   // Maps to the tracking state key token
	TenantID           uuid.UUID `json:"tenant_id"`            // LINK: Public tracking UUID partition key
	PartitionID        int64     `json:"partition_id"`         // Partition where the external IDP is defined on
	IdentityProviderID uuid.UUID `json:"identity_provider_id"` // LINK: Which external IDP initiated this flow?
	ClientID           string    `json:"client_id"`            // Tracking which client initiated the request
	CodeVerifier       string    `json:"code_verifier"`        // Safe storage for the PKCE secret string
	CreatedAt          time.Time `json:"created_at"`           // When initiated
	ExpiresAt          time.Time `json:"expires_at"`           // Strict short-lived expiration tracking
	CallbackURI        string    `json:"callback_uri"`         // Callback from external IDP
	TargetURI          string    `json:"target_uri"`           // Remembers where to return the user
}

// OIDCDiscoveryMetadata mirrors the structural parameters fetched back-channel
// during standard OpenID Metadata Discovery sweeps.
type OIDCDiscoveryMetadata struct {
	Issuer                             string   `json:"issuer"`
	AuthorizationEndpoint              string   `json:"authorization_endpoint"`
	TokenEndpoint                      string   `json:"token_endpoint"`
	JwksURI                            string   `json:"jwks_uri"`
	PushedAuthorizationRequestEndpoint string   `json:"pushed_authorization_request_endpoint,omitempty"`
	CodeChallengeMethodsSupported      []string `json:"code_challenge_methods_supported,omitempty"`
}

// FederatedSession represents an active upstream identity provider session state.
type FederatedSession struct {
	ID                   uuid.UUID
	TenantUUID           uuid.UUID
	PartitionID          int64
	SessionID            string
	IdentityProviderID   uuid.UUID
	UpstreamSubject      string
	UpstreamAccessToken  string
	UpstreamIDToken      string
	UpstreamRefreshToken string
	CreatedAt            time.Time
	ExpiresAt            time.Time
}
