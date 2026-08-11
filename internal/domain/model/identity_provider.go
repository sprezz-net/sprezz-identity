package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

const (
	UsernamePasswordIDPType = "username-password"
)

type Partition struct {
	ID        int64
	TenantID  uuid.UUID
	Name      string
	AliasName string
}

type IdentityProvider struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	IDPType     string
	Enabled     bool
	Alias       string
	Name        string
	PartitionID int64
	IssuerURL   string
	Config      IdentityProviderConfig
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// AcrTuple represents the multi-dimensional security assurance capabilities for a given claim
type AcrTuple struct {
	AAL int `json:"aal"`
	IAL int `json:"ial"`
}

type IdentityProviderConfig struct {
	UsernameField              string `json:"username_field"`
	IAL                        int    `json:"ial"`
	AAL                        int    `json:"aal"`
	AllowDecoupling            bool   `json:"allow_decoupling"`
	MaxFailedVerificationCount int    `json:"max_failed_verification_count"`
	PasswordBlockedTime        int    `json:"password_blocked_time"` // In seconds

	// OIDC-specific configurations
	DiscoveryEndpoint           string              `json:"discovery_endpoint,omitempty"`
	Issuer                      string              `json:"issuer,omitempty"`
	AuthorizationEndpoint       string              `json:"authorization_endpoint,omitempty"`
	TokenEndpoint               string              `json:"token_endpoint,omitempty"`
	UserinfoEndpoint            string              `json:"userinfo_endpoint,omitempty"`
	JwksURI                     string              `json:"jwks_uri,omitempty"`
	PushedAuthorizationEndpoint string              `json:"pushed_authorization_request_endpoint,omitempty"`
	ClientID                    string              `json:"client_id,omitempty"`
	ClientSecret                string              `json:"client_secret,omitempty"`
	AuthenticationMethod        string              `json:"authentication_method,omitempty"`
	PkceEnabled                 bool                `json:"pkce_enabled,omitempty"`
	ParEnabled                  bool                `json:"par_enabled,omitempty"`
	SLOEnabled                  bool                `json:"slo_enabled,omitempty"`
	Scopes                      []string            `json:"scopes,omitempty"`
	Claims                      []string            `json:"claims,omitempty"`
	ACRValues                   []string            `json:"acr_values,omitempty"`
	DomainAliases               []string            `json:"domain_aliases,omitempty"`
	UserIdentifierClaim         string              `json:"user_identifier_claim,omitempty"`
	DiscoveryResult             string              `json:"discovery_result,omitempty"`
	AcrToTuple                  map[string]AcrTuple `json:"acr_to_tuple,omitempty"`
	AmrToAAL                    map[string]int      `json:"amr_to_aal,omitempty"`
}

type UserIdentity struct {
	ID                        uuid.UUID
	UserProfileID             uuid.UUID
	IdentityProviderID        uuid.UUID
	ExternalIdentityID        string
	LoginCount                int
	LastLoginAt               time.Time
	LastVerificationAttemptAt time.Time
	FailedVerificationCount   int
	Blocked                   bool
	CoupledAt                 time.Time
}

type PasswordCredential struct {
	UserProfileID      uuid.UUID
	IdentityProviderID uuid.UUID
	Argon2Hash         string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type LoginResult struct {
	UserProfile *UserProfile
	Identity    *UserIdentity
}

func (c IdentityProviderConfig) MarshalJSON() ([]byte, error) {
	type Alias IdentityProviderConfig
	return json.Marshal(&struct {
		Alias
	}{
		Alias: Alias(c),
	})
}

func (c *IdentityProviderConfig) UnmarshalJSON(data []byte) error {
	type Alias IdentityProviderConfig
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if c.UsernameField == "" {
		c.UsernameField = "preferredUsername"
	}
	if c.MaxFailedVerificationCount == 0 {
		c.MaxFailedVerificationCount = 5
	}
	if c.PasswordBlockedTime == 0 {
		c.PasswordBlockedTime = 900 // Default 15 minutes
	}
	return nil
}
