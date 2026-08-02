package model

import "time"

type AuthorizationCodeSession struct {
	Code            string
	TenantID        string
	ClientID        string
	Subject         string
	CodeChallenge   string
	ChallengeMethod string
	RedirectURI     string
	Scopes          []string
	ExpiresAt       time.Time
}
