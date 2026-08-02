package model

import (
	"time"

	"github.com/google/uuid"
)

type ClientApplication struct {
	ID                     string
	TenantID               uuid.UUID
	ClientID               string
	ClientSecret           *string
	ClientName             string
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
}
