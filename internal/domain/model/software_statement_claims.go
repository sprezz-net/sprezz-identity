package model

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Ensure SoftwareStatementClaims correctly satisfies the golang-jwt ClaimsValidator interface at compile time.
var _ jwt.ClaimsValidator = (*SoftwareStatementClaims)(nil)

// SoftwareStatementClaims specifies the expected structure within the platform-signed JWT envelope.
// It integrates structural payload parameters along with custom validation logic blocks.
type SoftwareStatementClaims struct {
	jwt.RegisteredClaims
	SoftwareID             string   `json:"software_id"`
	ClientName             string   `json:"client_name,omitempty"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	Scopes                 []string `json:"scopes,omitempty"`
}

// Validate implements the jwt.ClaimsValidator interface method required by golang-jwt/v5.
func (c *SoftwareStatementClaims) Validate() error {
	now := time.Now()

	// 1. Manually enforce standard temporal lifecycle validations (exp, nbf)
	if c.ExpiresAt != nil && now.After(c.ExpiresAt.Time) {
		return errors.New("software_statement_validation: token is expired")
	}
	if c.NotBefore != nil && now.Before(c.NotBefore.Time) {
		return errors.New("software_statement_validation: token is not active yet")
	}

	// 2. Enforce your custom zero-trust business logic perimeters
	if strings.TrimSpace(c.SoftwareID) == "" {
		return errors.New("software_statement_validation: mandatory software_id claim is missing or empty")
	}

	return nil
}

// ToMapClaims flattens our embedded structural data matrices into a clean jwt.MapClaims dictionary footprint.
// This allows the use-case service layers to pass the structure seamlessly down-funnel into your port.Crypto adapter.
func (c *SoftwareStatementClaims) ToMapClaims() jwt.MapClaims {
	claims := jwt.MapClaims{
		"software_id":   c.SoftwareID,
		"redirect_uris": c.RedirectURIs,
	}

	// 1. Handle dynamic conditional field injection
	if c.ClientName != "" {
		claims["client_name"] = c.ClientName
	}
	if len(c.PostLogoutRedirectURIs) > 0 {
		claims["post_logout_redirect_uris"] = c.PostLogoutRedirectURIs
	}
	if len(c.Scopes) > 0 {
		claims["scopes"] = c.Scopes
	}

	// 2. Flatten embedded jwt.RegisteredClaims fields down to standard brief string keys
	if c.Issuer != "" {
		claims["iss"] = c.Issuer
	}
	if c.Subject != "" {
		claims["sub"] = c.Subject
	}
	if len(c.Audience) > 0 {
		claims["aud"] = c.Audience[0] // Isolate to your single, strict target server URL
	}
	if c.ExpiresAt != nil {
		claims["exp"] = c.ExpiresAt.Unix()
	}
	if c.IssuedAt != nil {
		claims["iat"] = c.IssuedAt.Unix()
	}
	if c.NotBefore != nil {
		claims["nbf"] = c.NotBefore.Unix()
	}
	if c.ID != "" {
		claims["jti"] = c.ID
	}

	return claims
}
