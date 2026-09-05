package port

import (
	"context"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

// ============================================================================
// INBOUND PORTS (DRIVING): Use Cases invoked by HTTP Delivery Adapters
// ============================================================================

// InitiateFederatedLoginCommand encapsulates data needed to initiate an outbound OIDC flow
type InitiateFederatedLoginCommand struct {
	TenantID           uuid.UUID // The current isolated multi-tenant target
	IdentityProviderID uuid.UUID // Unique ID of the targeted upstream provider configuration
	ClientID           string    // Added to preserve application lineage tracking and audit loops
	RequestedScopes    []string  // Added to dynamically support runtime incoming client application requests
	LocalCallbackURI   string    // The address where the provider must send the user back (e.g. /oauth/federation/callback)
	FinalTargetURI     string    // The target landing URL the user intended to access inside the system
}

// InitiateFederatedLoginResponse delivers the final computed parameters to the controller layer
type InitiateFederatedLoginResponse struct {
	TargetRedirectURL string // The absolute URL where the user browser must be sent (PAR or legacy query fallback)
	StateToken        string // High-entropy anti-replay tracker token bound to this handshake sequence
}

type FederatedCallbackCommand struct {
	TenantID      uuid.UUID // Root tenant isolation anchor
	IncomingState string    // State parameter used for XSRF validation
	IncomingCode  string    // Back-channel authorization trade code
	SessionID     string    // The active native session identifier string
	RequestURL    string    // For validating incoming protocol metrics if needed
	HTTPMethod    string    // For validating incoming protocol metrics if needed
}

type FederatedCallbackResponse struct {
	UpstreamAccessToken  string // The active authentication token/session key
	UpstreamIDToken      string // Retained for the id_token_hint parameter during full SLO loops
	UpstreamRefreshToken string // Retained if offline background API proxy renewals are required
	PartitionID          int64  // Internal database primary key preserved for tracking [3.1]
	TargetLandingURI     string // Resolved target landing zone (e.g., /admin/dashboard) [5.7]
	ReachedAAL           int    // Trust metric passed cleanly up to the delivery shell
	ReachedIAL           int    // Trust metric passed cleanly up to the delivery shell
}

// FederatedCallbackUseCase handles the entire inbound external provider callback journey
type FederatedLoginUseCase interface {
	// InitiateFederatedLogin coordinates Use Case 2.0: Outbound Handshake Construction with dynamic PAR fallback capabilities
	InitiateFederatedLogin(ctx context.Context, cmd InitiateFederatedLoginCommand) (*InitiateFederatedLoginResponse, error)
	// ExecuteFederatedCallback coordinates Use Case 2.1: The multi-stage external handshake pipeline natively [5.7]
	ExecuteFederatedCallback(ctx context.Context, cmd FederatedCallbackCommand) (*FederatedCallbackResponse, error)
}

// ============================================================================
// OUTBOUND PORTS (DRIVEN): Clients implemented by Infrastructure Network Adapters
// ============================================================================

// OutboundOIDCRequest defines parameters needed to generate an outbound federation flow.
type OutboundOIDCParams struct {
	ClientID         string                  `json:"client_id"`
	RedirectURI      string                  `json:"redirect_uri"`
	TargetURI        string                  `json:"target_uri"`
	Scopes           []string                `json:"scopes"`
	IdentityProvider *model.IdentityProvider `json:"identity_provider,omitempty"` // Complete dynamic configuration context
}

// UpstreamTokenSet encapsulates the standard string tokens returned
// during a standard back-channel OIDC authorization code trade loop.
type UpstreamTokenSet struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
}

// FederationClient isolates outbound back-channel network calls from your services.
type FederationClient interface {
	FetchOIDCDiscoveryMetadata(ctx context.Context, discoveryURL string) (*model.OIDCDiscoveryMetadata, error)
	ExecutePushedAuthorization(ctx context.Context, endpointURL string, req OutboundOIDCParams, state, challenge, scopes string) (string, error)
	ExchangeAuthorizationCode(ctx context.Context, tokenEndpoint string, req OutboundOIDCParams, incomingCode, codeVerifier string) (*UpstreamTokenSet, error)
}
