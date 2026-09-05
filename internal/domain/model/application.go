package model

import (
	"time"

	"github.com/google/uuid"
)

// TokenEndpointAuthMethod represents the verified OAuth 2.0 client authentication mechanism.
type TokenEndpointAuthMethod string

const (
	AuthMethodClientSecretPost  TokenEndpointAuthMethod = "client_secret_post"
	AuthMethodClientSecretBasic TokenEndpointAuthMethod = "client_secret_basic"
	AuthMethodNone              TokenEndpointAuthMethod = "none"
	// AuthMethodPrivateKeyJWT     TokenEndpointAuthMethod = "private_key_jwt"
)

// GrantType represents the requested OAuth 2.0 / OIDC protocol token issuance flow.
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypeTokenExchange     GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// ResponseType represents the requested OAuth 2.0 / OIDC protocol response mode.
type ResponseType string

const (
	ResponseTypeCode    ResponseType = "code"
	ResponseTypeToken   ResponseType = "token"
	ResponseTypeIDToken ResponseType = "id_token"
	ResponseTypeNone    ResponseType = "none"
)

// ApplicationProfile houses shared protocol capabilities, lifetimes, and authentication requirements.
type ApplicationProfile struct {
	ID                      uuid.UUID               `json:"id"`
	TenantID                uuid.UUID               `json:"tenant_id"`
	ProfileName             string                  `json:"profile_name"`
	IsEnabled               bool                    `json:"is_enabled"`
	TokenEndpointAuthMethod TokenEndpointAuthMethod `json:"token_endpoint_auth_method"`
	GrantTypes              []GrantType             `json:"grant_types"`
	ResponseTypes           []ResponseType          `json:"response_types"`
	AccessTokenLifetime     time.Duration           `json:"access_token_lifetime"`
	RefreshTokenLifetime    time.Duration           `json:"refresh_token_lifetime"`
	IDTokenLifetime         time.Duration           `json:"id_token_lifetime"`
	EnforceRTR              bool                    `json:"enforce_rtr"`
	SigningAlgorithm        SignatureAlgorithm      `json:"signing_algorithm"`
	CreatedAt               time.Time               `json:"created_at"`
	UpdatedAt               time.Time               `json:"updated_at"`
}

// ApplicationGroup houses shared whitelisted redirect URIs, scopes, logout configurations, and IDP maps.
type ApplicationGroup struct {
	ID                     uuid.UUID   `json:"id"`
	TenantID               uuid.UUID   `json:"tenant_id"`
	GroupName              string      `json:"group_name"`
	IsEnabled              bool        `json:"is_enabled"`
	RedirectURI            string      `json:"redirect_uri"`
	RedirectURIs           []string    `json:"redirect_uris"`
	PostLogoutRedirectURIs []string    `json:"post_logout_redirect_uris"`
	FrontChannelLogoutURI  string      `json:"front_channel_logout_uri"`
	BackChannelLogoutURI   string      `json:"back_channel_logout_uri"`
	AllowedScopes          []string    `json:"allowed_scopes"`
	DefaultScopes          []string    `json:"default_scopes"`
	AllowedAudiences       []string    `json:"allowed_audiences"`
	AllowedIDPIDs          []uuid.UUID `json:"allowed_idp_ids"`
	DefaultIDPID           *uuid.UUID  `json:"default_idp_id,omitempty"`
	CreatedAt              time.Time   `json:"created_at"`
	UpdatedAt              time.Time   `json:"updated_at"`
}

// Application represents the lightweight credential layer mapping an execution instance back to its rules.
type Application struct {
	ID               uuid.UUID `json:"id"`
	TenantID         uuid.UUID `json:"tenant_id"`
	ProfileID        uuid.UUID `json:"profile_id"`
	GroupID          uuid.UUID `json:"group_id"`
	ApplicationName  string    `json:"application_name"`
	IsEnabled        bool      `json:"is_enabled"`
	ClientID         string    `json:"client_id"`
	ClientSecretHash *string   `json:"client_secret_hash,omitempty"`
	IsDynamic        bool      `json:"is_dynamic"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	LastUsedAt       time.Time `json:"last_used_at"`

	// Outbound Runtime Context (Mapped from the shared application_group row)
	FrontChannelLogoutURI string             `json:"front_channel_logout_uri,omitempty"`
	BackChannelLogoutURI  string             `json:"back_channel_logout_uri,omitempty"`
	SigningAlgorithm      SignatureAlgorithm `json:"signing_algorithm"`
}

// DynamicRegistrationPayload encapsulates the complete set of RFC 7591 metadata parameters
// provided by an outbound client during a Dynamic Client Registration request sweep.
type DynamicRegistrationPayload struct {
	ApplicationName         string                  `json:"client_name"`
	RedirectURIs            []string                `json:"redirect_uris"`
	TokenEndpointAuthMethod TokenEndpointAuthMethod `json:"token_endpoint_auth_method"`
	GrantTypes              []GrantType             `json:"grant_types"`
	ResponseTypes           []ResponseType          `json:"response_types"`
	AllowedScopes           string                  `json:"scope"`
	AllowedAudiences        []string                `json:"allowed_audiences"`
	PostLogoutRedirectURIs  []string                `json:"post_logout_redirect_uris"`
	FrontChannelLogoutURI   string                  `json:"frontchannel_logout_uri"`
	BackChannelLogoutURI    string                  `json:"backchannel_logout_uri"`

	// The signed protocol assertion envelope containing your semantic profile;group mapping identifiers
	SoftwareStatement string `json:"software_statement"`
}
