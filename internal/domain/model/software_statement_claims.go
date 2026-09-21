package model

import (
	"errors"
	"strings"
	"time"
)

// SoftwareStatementClaims specifies the expected structure within the platform-signed JWT envelope.
// It integrates structural payload parameters along with custom validation logic blocks.
type SoftwareStatementClaims struct {
	Issuer                 string   `json:"iss,omitempty"`
	Subject                string   `json:"sub,omitempty"`
	Audience               []string `json:"aud,omitempty"`
	ExpiresAt              int64    `json:"exp,omitempty"`
	IssuedAt               int64    `json:"iat,omitempty"`
	NotBefore              int64    `json:"nbf,omitempty"`
	TokenID                string   `json:"jti,omitempty"`
	SoftwareID             string   `json:"software_id,omitempty"`
	SoftwareVersion        string   `json:"software_version,omitempty"`
	ClientName             string   `json:"client_name,omitempty"`
	RedirectURIs           []string `json:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	Scopes                 []string `json:"scopes,omitempty"`
}

// Validate implements the jwt.ClaimsValidator interface method required by golang-jwt/v5.
func (c *SoftwareStatementClaims) Validate(now time.Time) error {
	// 1. Base token validations
	if c.Issuer == "" {
		return errors.New("software_statement_validation: issuer cannot be empty")
	}
	if c.IssuedAt == 0 {
		return errors.New("software_statement_validation: missing issued at")
	}

	// 2. Manually enforce standard temporal lifecycle validations (exp, nbf)
	if c.ExpiresAt > 0 && now.Unix() > c.ExpiresAt {
		return errors.New("software_statement_validation: token is expired")
	}
	if c.NotBefore > 0 && now.Unix() < c.NotBefore {
		return errors.New("software_statement_validation: token is not active yet")
	}

	// 3. Enforce your custom zero-trust business logic perimeters
	if strings.TrimSpace(c.SoftwareID) == "" {
		return errors.New("software_statement_validation: mandatory software_id claim is missing or empty")
	}

	return nil
}
