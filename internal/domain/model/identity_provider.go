package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

const (
	UsernamePasswordIDPType = "username-password"
)

type IdentityProvider struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	IDPType   string
	Enabled   bool
	Alias     string
	Config    IdentityProviderConfig
	CreatedAt time.Time
}

type IdentityProviderConfig struct {
	UsernameField string `json:"username_field"`
}

type UserIdentity struct {
	ID                 uuid.UUID
	UserProfileID      uuid.UUID
	IdentityProviderID uuid.UUID
	ExternalIdentityID string
	LoginCount         int
	LastLoginAt        time.Time
	LastLoginAttemptAt time.Time
	Blocked            bool
	CoupledAt          time.Time
}

type PasswordCredential struct {
	UserProfileID      uuid.UUID
	IdentityProviderID uuid.UUID
	Argon2Hash         string
}

type LoginResult struct {
	UserProfile *UserProfile
	Identity    *UserIdentity
}

func (c IdentityProviderConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"username_field": c.UsernameField,
	})
}

func (c *IdentityProviderConfig) UnmarshalJSON(data []byte) error {
	var payload map[string]string
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	c.UsernameField = payload["username_field"]
	if c.UsernameField == "" {
		c.UsernameField = "preferredUsername"
	}
	return nil
}
