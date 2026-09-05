package model

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Confirmation nests the RFC 8705 cryptographic proof-of-possession binding thumbprint.
type Confirmation struct {
	JKT string `json:"jkt,omitempty"`
}

// BaseTokenClaims encapsulates core multi-tenant and session tracking routing properties
// common across all native token lifecycle tracks.
type BaseTokenClaims struct {
	Issuer                string        `json:"iss"`
	Subject               string        `json:"sub"`
	ExpiresAt             int64         `json:"exp"`
	IssuedAt              int64         `json:"iat"`
	TokenID               string        `json:"jti"`
	TenantID              uuid.UUID     `json:"tid"`
	ClientID              string        `json:"azp"`
	SessionID             string        `json:"sid"`
	IdentityProviderID    uuid.UUID     `json:"idp_id,omitempty"`
	IdentityProviderAlias string        `json:"idp_alias,omitempty"`
	ACR                   string        `json:"acr,omitempty"`
	AMR                   []string      `json:"amr,omitempty"`
	Confirmation          *Confirmation `json:"cnf,omitempty"`
}

// TokenClaims represents the core payload for OAuth 2.0 Access Tokens.
// It focuses on authorization, access scopes, and routing boundaries.
// It implicitly fulfills the jwt.Claims interface without importing external packages.
type TokenClaims struct {
	BaseTokenClaims
	Audiences      []string `json:"aud"`
	PartitionAlias string   `json:"pid,omitempty"`
	Scopes         []string `json:"scp"`
	Roles          []string `json:"roles,omitempty"`
}

// OIDCTokenClaims represents the expansive payload for OIDC ID Tokens.
// It includes full human identity assertions alongside session contexts.
type OIDCTokenClaims struct {
	BaseTokenClaims
	Audience string `json:"aud"`
	AuthTime int64  `json:"auth_time"`
	Nonce    string `json:"nonce,omitempty"`

	// Raw Human Identity Claims (Spec-Compliant OIDC Profile Fields)
	Name              string `json:"name,omitempty"`               // Populated via UserProfile.DisplayName()
	GivenName         string `json:"given_name,omitempty"`         // Populated via UserProfile.FirstName
	FamilyName        string `json:"family_name,omitempty"`        // Populated via UserProfile.LastName
	PreferredUsername string `json:"preferred_username,omitempty"` // Populated via UserProfile.PreferredUsername
	Email             string `json:"email,omitempty"`              // Populated via UserProfile.Email
	EmailVerified     bool   `json:"email_verified,omitempty"`     // Populated via UserProfile.EmailVerified
}

// FilterByScope copies OIDCTokenClaims and drops unauthorized keys dynamically.
func (c OIDCTokenClaims) FilterByScope(grantedScopes []string) OIDCTokenClaims {
	hasScope := func(target string) bool {
		for _, s := range grantedScopes {
			if s == target {
				return true
			}
		}
		return false
	}

	filtered := c
	if !hasScope("profile") {
		filtered.Name = ""
		filtered.GivenName = ""
		filtered.FamilyName = ""
		filtered.PreferredUsername = ""
	}
	if !hasScope("email") {
		filtered.Email = ""
		filtered.EmailVerified = false
	}
	return filtered
}

// LogoutTokenClaims represents back-channel logout assertion containers.
type LogoutTokenClaims struct {
	Issuer    string         `json:"iss"`
	Subject   string         `json:"sub"`
	Audience  string         `json:"aud"`
	IssuedAt  int64          `json:"iat"`
	TokenID   string         `json:"jti"`
	Events    map[string]any `json:"events"`
	SessionID string         `json:"sid,omitempty"`
}

// RefreshToken represents the internal database and logic anchor for long-lived
// session persistence and refresh token rotation (RTR) tracking.
type RefreshToken struct {
	TokenID               string    `json:"token_id"`
	TenantID              uuid.UUID `json:"tenant_id"`
	ClientID              string    `json:"client_id"`
	Subject               string    `json:"subject"`
	Scopes                []string  `json:"scopes"`
	TokenFamilyID         string    `json:"token_family_id"`
	IsUsed                bool      `json:"is_used"`
	ExpiresAt             time.Time `json:"expires_at"`
	CreatedAt             time.Time `json:"created_at"`
	IdentityProviderID    uuid.UUID `json:"identity_provider_id"`
	IdentityProviderAlias string    `json:"identity_provider_alias"`
	SessionID             string    `json:"session_id"`
}

// TokenSetResponse encapsulates token generation response delivery formats.
type TokenSetResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// IntrospectionResponse delivers token details back to callers.
type IntrospectionResponse struct {
	Active                bool          `json:"active"`
	Issuer                string        `json:"iss,omitempty"`
	Subject               string        `json:"sub,omitempty"`
	ExpiresAt             int64         `json:"exp,omitempty"`
	IssuedAt              int64         `json:"iat,omitempty"`
	TokenType             string        `json:"token_type,omitempty"`
	TenantID              string        `json:"tid,omitempty"`
	PartitionAlias        string        `json:"pid,omitempty"`
	ClientID              string        `json:"azp,omitempty"`
	Scope                 string        `json:"scope,omitempty"`
	IdentityProviderID    string        `json:"idp_id,omitempty"`
	IdentityProviderAlias string        `json:"idp_alias,omitempty"`
	Confirmation          *Confirmation `json:"cnf,omitempty"`
}

// --- implicit golang-jwt/jwt/v5 validation interface satisfaction ---

func (b BaseTokenClaims) Validate() error {
	if b.Issuer == "" {
		return errors.New("token_validation: issuer cannot be empty")
	}
	if b.TenantID == uuid.Nil {
		return errors.New("token_validation: tenant identity missing")
	}
	return nil
}

// --- TokenClaims (Access Token) Interface Satisfaction ---
func (c TokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.ExpiresAt == 0 {
		return nil, nil
	}
	t := jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0))
	return t, nil
}
func (c TokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.IssuedAt == 0 {
		return nil, nil
	}
	t := jwt.NewNumericDate(time.Unix(c.IssuedAt, 0))
	return t, nil
}
func (c TokenClaims) GetNotBefore() (*jwt.NumericDate, error) { return nil, nil }
func (c TokenClaims) GetIssuer() (string, error)              { return c.Issuer, nil }
func (c TokenClaims) GetSubject() (string, error)             { return c.Subject, nil }
func (c TokenClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings(c.Audiences), nil
}

// Extra business rule validation wrapper extending BaseTokenClaims functionality
func (c TokenClaims) Validate() error {
	if err := c.BaseTokenClaims.Validate(); err != nil {
		return err
	}
	// Only enforce partition alias if it's a user token (Sub != ClientID)
	if c.Subject != c.ClientID && c.PartitionAlias == "" {
		return errors.New("token_validation: partition alias cannot be empty")
	}
	return nil
}

// --- OIDCTokenClaims (ID Token) Interface Satisfaction ---
func (c OIDCTokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.ExpiresAt == 0 {
		return nil, nil
	}
	t := jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0))
	return t, nil
}
func (c OIDCTokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.IssuedAt == 0 {
		return nil, nil
	}
	t := jwt.NewNumericDate(time.Unix(c.IssuedAt, 0))
	return t, nil
}
func (c OIDCTokenClaims) GetNotBefore() (*jwt.NumericDate, error) { return nil, nil }
func (c OIDCTokenClaims) GetIssuer() (string, error)              { return c.Issuer, nil }
func (c OIDCTokenClaims) GetSubject() (string, error)             { return c.Subject, nil }
func (c OIDCTokenClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings([]string{c.Audience}), nil
}

// Extra OIDC validation rule wrapper extending BaseTokenClaims functionality
func (c OIDCTokenClaims) Validate() error {
	if err := c.BaseTokenClaims.Validate(); err != nil {
		return err
	}
	if c.Audience == "" {
		return errors.New("oidc_validation: audience footprint cannot be empty")
	}
	return nil
}
