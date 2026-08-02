package model

import "time"

type TokenClaims struct {
	TokenID   string
	TenantID  string
	Subject   string
	ClientID  string
	Scopes    []string
	IssuedAt  time.Time
	ExpiresAt time.Time
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
}

type TokenSetResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}
