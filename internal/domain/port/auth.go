package port

import (
	"context"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

type DiscoveryResponse struct {
	Issuer                                     string   `json:"issuer"`
	JWKSURI                                    string   `json:"jwks_uri"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	PushedAuthorizationRequestEndpoint         string   `json:"pushed_authorization_request_endpoint"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ACRValuesSupported                         []string `json:"acr_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported  []string `json:"introspection_endpoint_auth_methods_supported"`
	DPoPSigningAlgValuesSupported              []string `json:"dpop_signing_alg_values_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	RequirePushedAuthorizationRequests         bool     `json:"require_pushed_authorization_requests"`

	// OpenID Connect specialized extension parameters (Omitted for plain OAuth2 metadata)
	UserInfoEndpoint                   string   `json:"userinfo_endpoint,omitempty"`
	EndSessionEndpoint                 string   `json:"end_session_endpoint,omitempty"`
	FrontChannelLogoutSupported        bool     `json:"frontchannel_logout_supported,omitempty"`
	FrontChannelLogoutSessionSupported bool     `json:"frontchannel_logout_session_supported,omitempty"`
	ClaimsSupported                    []string `json:"claims_supported,omitempty"`
	IDTokenSigningAlgValuesSupported   []string `json:"id_token_signing_alg_values_supported,omitempty"`
	SubjectTypesSupported              []string `json:"subject_types_supported,omitempty"`
}

// AuthorizeRequestCommand carries raw transport elements straight across the inbound perimeter.
type AuthorizeRequestCommand struct {
	TenantID        uuid.UUID
	ClientID        string
	RedirectURI     string
	CodeChallenge   string
	ChallengeMethod string
	IDPHint         string
	State           string
	Nonce           string
	ACRValues       string
	ClaimsJSON      string
	Scopes          []string
	ActiveSessionID string
	RequestHost     string
	RequestURI      string
}

// PushedAuthCommand carries raw parameters from the back-channel client POST payload.
type PushedAuthCommand struct {
	TenantID              uuid.UUID
	ClientID              string
	ClientAuthMethod      model.TokenEndpointAuthMethod
	IsClientAuthenticated bool
	RedirectURI           string
	CodeChallenge         string
	ChallengeMethod       string
	Scopes                []string
	State                 string
	Nonce                 string
	IDPHint               string
	ACRValues             string
}

// UserInfoRequestCommand isolates transport mechanics away from the userinfo engine.
type UserInfoRequestCommand struct {
	TenantID            uuid.UUID
	AuthorizationHeader string
	DPoPProofHeader     string
	HTTPMethod          string
	RequestURL          string
}

// IntrospectTokenCommand carries transport-validated parameters across the inbound perimeter.
type IntrospectTokenCommand struct {
	TenantID              uuid.UUID
	ClientID              string
	IsClientAuthenticated bool
	TargetTokenString     string
}

// RevokeTokenCommand carries transport parameter blocks straight across the inbound perimeter.
type RevokeTokenCommand struct {
	TenantID              uuid.UUID
	ClientID              string
	IsClientAuthenticated bool
	TokenString           string
}

// LogoutRequestCommand carries transport properties straight across the inbound perimeter.
type LogoutRequestCommand struct {
	TenantID              uuid.UUID
	ActiveSessionID       string
	PostLogoutRedirectURI string
	State                 string
	RequestHost           string
	IDTokenHint           string
}

type AuthorizeActionType string

const (
	ActionRedirectToLoginUI     AuthorizeActionType = "LOGIN_UI"
	ActionRedirectToExternalIDP AuthorizeActionType = "EXTERNAL_IDP"
	ActionEmitAuthorizationCode AuthorizeActionType = "EMIT_CODE"
)

// AuthorizeExecutionResult structures the response instructions for the delivery adapter.
type AuthorizeExecutionResult struct {
	Action          AuthorizeActionType
	RedirectURL     string
	HasCookieIntent bool
	CookieName      string
	CookieValue     string
	CookieMaxAge    int
	CookieSecure    bool
}

// PushedAuthResponse returns the generated spec-compliant URI handle and lifespan metrics.
type PushedAuthResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

// DynamicRegistrationResult carries the provisioned client context and raw secrets back up-funnel.
type DynamicRegistrationResult struct {
	Application     *model.Application
	PlaintextSecret string
}

// LogoutExecutionResult structures the response instructions for the delivery adapter.
type LogoutExecutionResult struct {
	PostLogoutRedirectURI  string
	FrontChannelLogoutURIs []string
	HasCookieIntent        bool
	CookieName             string
	CookieValue            string
	CookieMaxAge           int
	CookieSecure           bool
}

type ExchangeCodeForTokensCommand struct {
	TenantID           uuid.UUID
	ClientID           string
	Code               string
	CodeVerifier       string
	Tenant             *model.Tenant
	Application        *model.Application
	ApplicationProfile *model.ApplicationProfile
	ApplicationGroup   *model.ApplicationGroup
}

type RotateRefreshTokenCommand struct {
	TenantID           uuid.UUID
	ClientID           string
	RefreshToken       string
	Tenant             *model.Tenant
	Application        *model.Application
	ApplicationProfile *model.ApplicationProfile
	ApplicationGroup   *model.ApplicationGroup
}

type ExchangeClientCredentialsCommand struct {
	TenantID           uuid.UUID
	ClientID           string
	Tenant             *model.Tenant
	Application        *model.Application
	ApplicationProfile *model.ApplicationProfile
	ApplicationGroup   *model.ApplicationGroup
}

// AuthUseCase defines the primary driving port use-case orchestrations for core
// OAuth 2.0 and OpenID Connect lifecycles.
type AuthUseCase interface {
	// ProcessDiscoveryMetadata compiles server capabilities into an OIDC or OAuth2 specification layout.
	ProcessDiscoveryMetadata(ctx context.Context, tenantID uuid.UUID, isOIDC bool) (*DiscoveryResponse, error)

	// ProcessJWKSetRetrieval resolves the public keyset data container for an explicit runtime host.
	ProcessJWKSetRetrieval(ctx context.Context, tenantID uuid.UUID, host string, scheme string) (map[string]any, error)

	// Browser Interactive Protocol Channels
	ProcessAuthorizeRequest(ctx context.Context, cmd AuthorizeRequestCommand) (*AuthorizeExecutionResult, error)

	// Consolidated OpenID Connect Single Sign-Out Port Gateway
	ProcessLogoutRequest(ctx context.Context, cmd LogoutRequestCommand) (*LogoutExecutionResult, error)

	// Token Server Token Issuance Core (POST /oauth/token Channels)
	ExchangeCodeForTokens(ctx context.Context, cmd ExchangeCodeForTokensCommand) (*model.TokenSetResponse, error)
	RotateRefreshToken(ctx context.Context, cmd RotateRefreshTokenCommand) (*model.TokenSetResponse, error)
	ExchangeClientCredentials(ctx context.Context, cmd ExchangeClientCredentialsCommand) (*model.TokenSetResponse, error)
	ExchangeExternalToken(ctx context.Context, tenantID uuid.UUID, clientID, subjectToken string, subjectTokenType model.TokenType) (*model.TokenSetResponse, error)

	// Handles back-channel authorization caching
	ProcessPushedAuthorization(ctx context.Context, cmd PushedAuthCommand) (*PushedAuthResponse, error)

	// User Info Port Gateway
	ProcessUserInfoRequest(ctx context.Context, cmd UserInfoRequestCommand) (*model.OIDCTokenClaims, error)

	// Consolidated Dynamic Client Registration Port Gateway
	ProcessDynamicRegistration(ctx context.Context, tenantID uuid.UUID, payload model.DynamicRegistrationPayload) (*DynamicRegistrationResult, error)

	// Security Validation & Lifecycle Governance Channels
	ProcessTokenIntrospection(ctx context.Context, cmd IntrospectTokenCommand) (*model.IntrospectionResponse, error)
	ProcessTokenRevocation(ctx context.Context, cmd RevokeTokenCommand) error

	IntrospectToken(ctx context.Context, tenantID uuid.UUID, clientID, tokenStr string) (*model.IntrospectionResponse, error)
	RevokeToken(ctx context.Context, tenantID uuid.UUID, clientID, tokenStr string) error

	// Software Statement Driven Dynamic Registration Plane
	RegisterDynamicApplication(ctx context.Context, tenantID uuid.UUID, payload model.DynamicRegistrationPayload) (*model.Application, string, error)
}
