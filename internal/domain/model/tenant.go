package model

import (
	"time"

	"github.com/google/uuid"
)

type DCRMode string

const (
	DCRModeOff               DCRMode = "off"
	DCRModePublic            DCRMode = "public"
	DCRModeSoftwareStatement DCRMode = "software_statement"
	DCRModeAuthenticated     DCRMode = "authenticated"
)

type Tenant struct {
	ID               uuid.UUID
	Name             string
	Domain           string
	IsActive         bool
	CreatedAt        time.Time
	Config           TenantConfig
	DefaultPartition *int64
	UpdatedAt        time.Time
	Scheme           string
}

func (t Tenant) GetBaseURI() string {
	return t.Scheme + "://" + t.Domain
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
	DefaultAAL           int               `json:"default_aal,omitempty"`
	DefaultIAL           int               `json:"default_ial,omitempty"`
	ProfileAAL           int               `json:"profile_aal,omitempty"`
	NameAAL              int               `json:"name_aal,omitempty"`
	EmailAAL             int               `json:"email_aal,omitempty"`
	PasswordAAL          int               `json:"password_aal,omitempty"`
	DCRMode              DCRMode           `json:"dcr_mode,omitempty"`
}

func (tc TenantConfig) GetDefaultAAL() int {
	if tc.DefaultAAL <= 0 {
		return 1
	}
	return tc.DefaultAAL
}

func (tc TenantConfig) GetDefaultIAL() int {
	if tc.DefaultIAL <= 0 {
		return 1
	}
	return tc.DefaultIAL
}

func (tc TenantConfig) GetProfileAAL() int {
	if tc.ProfileAAL <= 0 {
		return 1
	}
	return tc.ProfileAAL
}

func (tc TenantConfig) GetNameAAL() int {
	if tc.NameAAL <= 0 {
		return 1
	}
	return tc.NameAAL
}

func (tc TenantConfig) GetEmailAAL() int {
	if tc.EmailAAL <= 0 {
		return 1
	}
	return tc.EmailAAL
}

func (tc TenantConfig) GetPasswordAAL() int {
	if tc.PasswordAAL <= 0 {
		return 1
	}
	return tc.PasswordAAL
}
