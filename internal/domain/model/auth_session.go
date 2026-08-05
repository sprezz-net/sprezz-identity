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
	SessionID       string
	State           string
	Nonce           string
	ACRValues       string
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
	State           string
	Nonce           string
	ACRValues       string
}

type PushedAuthorizationRequest struct {
	RequestURI      string
	TenantID        uuid.UUID
	ClientID        string
	RedirectURI     string
	CodeChallenge   string
	ChallengeMethod string
	Scopes          []string
	State           string
	Nonce           string
	IDPHint         string
	ACRValues       string
	ExpiresAt       time.Time
}

type RefreshToken struct {
	TokenID       string
	TenantID      uuid.UUID
	ClientID      string
	Subject       string
	Scopes        []string
	TokenFamilyID string
	IsUsed        bool
	ExpiresAt     time.Time
	CreatedAt     time.Time
}
