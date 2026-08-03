package model

import (
	"time"

	"github.com/google/uuid"
)

type Tenant struct {
	ID        uuid.UUID
	Name      string
	Domain    string
	IsActive  bool
	CreatedAt time.Time
	Config    TenantConfig
}

type TenantConfig struct {
	PredefinedScopes    []string `json:"predefined_scopes"`
	PredefinedAudiences []string `json:"predefined_audiences"`
	DefaultRedirectURI  string   `json:"default_redirect_uri"`
	RedirectWhitelist   []string `json:"redirect_whitelist"`
}
