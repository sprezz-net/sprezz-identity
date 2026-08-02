package model

import (
	"time"

	"github.com/google/uuid"
)

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

type InteractionSession struct {
	ID              uuid.UUID
	TenantID        uuid.UUID
	ClientID        string
	RedirectURI     string
	CodeChallenge   string
	ChallengeMethod string
	IDPHint         string
	ExpiresAt       time.Time
}
