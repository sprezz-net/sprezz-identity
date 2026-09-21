package model

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Confirmation nests the RFC 8705 cryptographic proof-of-possession binding thumbprint.
type Confirmation struct {
	JKT string `json:"jkt,omitempty"`
}

// BaseTokenClaims encapsulates core multi-tenant and session tracking routing properties
// common across all native token lifecycle tracks.
type BaseTokenClaims struct {
	Issuer                string        `json:"iss,omitempty"`
	Subject               string        `json:"sub,omitempty"`
	ExpiresAt             int64         `json:"exp,omitempty"`
	IssuedAt              int64         `json:"iat,omitempty"`
	NotBefore             int64         `json:"nbf,omitempty"`
	TokenID               string        `json:"jti,omitempty"`
	TenantID              uuid.UUID     `json:"tid,omitempty"`
	ClientID              string        `json:"azp,omitempty"`
	SessionID             string        `json:"sid,omitempty"`
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
	Audiences      []string `json:"aud,omitempty"`
	PartitionAlias string   `json:"pid,omitempty"`
	Scopes         []string `json:"scp,omitempty"`
	Roles          []string `json:"roles,omitempty"`
}

// OIDCTokenClaims represents the expansive payload for OIDC ID Tokens.
// It includes full human identity assertions alongside session contexts.
type OIDCTokenClaims struct {
	BaseTokenClaims
	Audience string `json:"aud,omitempty"`
	AuthTime int64  `json:"auth_time,omitempty"`
	Nonce    string `json:"nonce,omitempty"`

	// Raw Human Identity Claims (Spec-Compliant OIDC Profile Fields)
	Name              string `json:"name,omitempty"`               // Populated via UserProfile.DisplayName()
	GivenName         string `json:"given_name,omitempty"`         // Populated via UserProfile.FirstName
	FamilyName        string `json:"family_name,omitempty"`        // Populated via UserProfile.LastName
	PreferredUsername string `json:"preferred_username,omitempty"` // Populated via UserProfile.PreferredUsername
	Email             string `json:"email,omitempty"`              // Populated via UserProfile.Email
	EmailVerified     bool   `json:"email_verified,omitempty"`     // Populated via UserProfile.EmailVerified
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

// ============================================================================
// DOMAIN BUSINESS VALIDATION LAYER (PURE GO)
// ============================================================================

// Validate checks standard temporal lifecycles and tenant containment constraints.
func (b BaseTokenClaims) Validate(now time.Time) error {
	if b.Issuer == "" {
		return errors.New("token_validation: issuer cannot be empty")
	}
	if b.TenantID == uuid.Nil {
		return errors.New("token_validation: tenant identity missing")
	}
	if b.IssuedAt == 0 {
		return errors.New("token_validation: token issue time missing (iat constraint violation)")
	}
	// Enforce strict lifecycle expiration auditing (Expires At)
	if b.ExpiresAt > 0 && now.Unix() > b.ExpiresAt {
		return errors.New("token_validation: token has expired (exp constraint violation)")
	}
	// Enforce strict cryptographic activation clock auditing (Not Before)
	if b.NotBefore > 0 && now.Unix() < b.NotBefore {
		return errors.New("token_validation: token is not active yet (nbf constraint violation)")
	}
	return nil
}

// Extra business rule validation wrapper extending BaseTokenClaims functionality
func (c TokenClaims) Validate(now time.Time) error {
	// Cascade validation down to core base properties first
	if err := c.BaseTokenClaims.Validate(now); err != nil {
		return err
	}
	// Only enforce partition alias if it's a user token (Sub != ClientID)
	if c.Subject != c.ClientID && c.PartitionAlias == "" {
		return errors.New("token_validation: partition alias cannot be empty for user tokens")
	}
	return nil
}

// Extra OIDC validation rule wrapper extending BaseTokenClaims functionality
func (c OIDCTokenClaims) Validate(now time.Time) error {
	// Cascade validation down to core base properties first
	if err := c.BaseTokenClaims.Validate(now); err != nil {
		return err
	}
	if c.Audience == "" {
		return errors.New("oidc_validation: audience cannot be empty")
	}
	return nil
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
