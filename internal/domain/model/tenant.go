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

type Levels struct {
	IAL int `json:"ial,omitempty"`
	AAL int `json:"aal,omitempty"`
}

type TenantConfig struct {
	PredefinedScopes     []string          `json:"predefined_scopes"`
	PredefinedAudiences  []string          `json:"predefined_audiences"`
	DefaultRedirectURI   string            `json:"default_redirect_uri"`
	RedirectWhitelist    []string          `json:"redirect_whitelist"`
	ACRToLevels          map[string]Levels `json:"acr_to_levels"`
	ACREssential         bool              `json:"acr_essential"`
	AllowSignup          bool              `json:"allow_signup"`
	EncryptedAdminSecret string            `json:"encrypted_admin_secret,omitempty"`
}
