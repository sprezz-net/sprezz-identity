package model

import "time"

type TokenClaims struct {
	TokenID   string
	Issuer    string
	TenantID  string
	Subject   string
	ClientID  string
	Scopes    []string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Audiences []string
	DPoPHash  string
	ACR       string
}

type OIDCTokenClaims struct {
	TokenID   string
	Issuer    string
	Subject   string
	Audience  string
	TenantID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	AuthTime  time.Time
	Nonce     string
	SessionID string
	ACR       string
}

type TokenSetResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type Confirmation struct {
	JKT string `json:"jkt,omitempty"`
}

type IntrospectionResponse struct {
	Active       bool          `json:"active"`
	Scope        string        `json:"scope,omitempty"`
	ClientID     string        `json:"client_id,omitempty"`
	Subject      string        `json:"sub,omitempty"`
	ExpiresAt    int64         `json:"exp,omitempty"`
	IssuedAt     int64         `json:"iat,omitempty"`
	Issuer       string        `json:"iss,omitempty"`
	TokenType    string        `json:"token_type,omitempty"`
	TenantID     string        `json:"tid,omitempty"`
	Confirmation *Confirmation `json:"cnf,omitempty"`
}

type LogoutTokenClaims struct {
	TokenID  string
	Issuer   string
	Subject  string
	Audience string
	IssuedAt time.Time
}
