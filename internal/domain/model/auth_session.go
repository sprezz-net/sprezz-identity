package model

import (
	"time"

	"github.com/google/uuid"
)

// AuthorizationCodeSession represents a transient, short-lived database record
// that persists authorization code tracking parameters during standard authorization flows.
// AuthorizationCodeSession handles short-lived state parameters during standard authorization code trades.
type AuthorizationCodeSession struct {
	Code                  string    `json:"code"`
	TenantID              uuid.UUID `json:"tenant_id"`
	PartitionID           int64     `json:"partition_id"`
	ClientID              string    `json:"client_id"`
	Subject               string    `json:"subject"`
	CodeChallenge         string    `json:"code_challenge"`
	ChallengeMethod       string    `json:"challenge_method"`
	RedirectURI           string    `json:"redirect_uri"`
	Scopes                []string  `json:"scopes"`
	ExpiresAt             time.Time `json:"expires_at"`
	SessionID             string    `json:"session_id"`
	State                 string    `json:"state"`
	Nonce                 string    `json:"nonce"`
	ACRValues             string    `json:"acr_values"`
	AMRValues             []string  `json:"amr_values"`
	IdentityProviderID    uuid.UUID `json:"identity_provider_id"`
	IdentityProviderAlias string    `json:"identity_provider_alias"`
}

// InteractionSession handles short-lived parameters across localized login interface renders.
type InteractionSession struct {
	ID                    uuid.UUID `json:"id"`
	TenantID              uuid.UUID `json:"tenant_id"`
	PartitionID           int64     `json:"partition_id"`
	ClientID              string    `json:"client_id"`
	RedirectURI           string    `json:"redirect_uri"`
	CodeChallenge         string    `json:"code_challenge"`
	ChallengeMethod       string    `json:"challenge_method"`
	IDPHint               string    `json:"idp_hint,omitempty"`
	ExpiresAt             time.Time `json:"expires_at"`
	State                 string    `json:"state"`
	Nonce                 string    `json:"nonce"`
	ACRValues             string    `json:"acr_values"`
	AMRValues             []string  `json:"amr_values"`
	IdentityProviderID    uuid.UUID `json:"identity_provider_id"`
	IdentityProviderAlias string    `json:"identity_provider_alias"`
}

// PushedAuthorizationRequest handles early RFC 9126 data caching validations.
type PushedAuthorizationRequest struct {
	RequestURI            string    `json:"request_uri"`
	TenantID              uuid.UUID `json:"tenant_id"`
	PartitionID           int64     `json:"partition_id"`
	ClientID              string    `json:"client_id"`
	RedirectURI           string    `json:"redirect_uri"`
	CodeChallenge         string    `json:"code_challenge"`
	ChallengeMethod       string    `json:"challenge_method"`
	Scopes                []string  `json:"scopes"`
	State                 string    `json:"state"`
	Nonce                 string    `json:"nonce"`
	IDPHint               string    `json:"idp_hint,omitempty"`
	ACRValues             string    `json:"acr_values"` // The requested ACR
	ExpiresAt             time.Time `json:"expires_at"`
	IdentityProviderID    uuid.UUID `json:"identity_provider_id"`
	IdentityProviderAlias string    `json:"identity_provider_alias"`
}

// PKCEPair contains the cleartext verifier and cryptographic challenge
type PKCEPair struct {
	Verifier  string `json:"verifier"`
	Challenge string `json:"challenge"`
}
