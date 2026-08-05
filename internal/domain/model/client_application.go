package model

import (
	"time"

	"github.com/google/uuid"
)

const (
	ClientTypePublic            = "public"
	ClientTypeConfidential      = "confidential"
	ClientTypeInternalEphemeral = "internal_ephemeral"
)

type ClientApplication struct {
	ID                     string
	TenantID               uuid.UUID
	ClientID               string
	ClientSecret           *string
	ClientName             string
	RedirectURI            string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	FrontChannelLogoutURI  string
	BackChannelLogoutURI   string
	GrantTypes             []string
	ResponseTypes          []string
	Algorithm              SignatureAlgorithm
	AccessTokenLifetime    time.Duration
	RefreshTokenLifetime   time.Duration
	IDTokenLifetime        time.Duration
	AllowedScopes          []string
	DefaultScopes          []string
	AllowedIDPs            []string
	DefaultIDP             string
	AllowedAudiences       []string
	ClientType             string
	EnforceRTR             bool
}
