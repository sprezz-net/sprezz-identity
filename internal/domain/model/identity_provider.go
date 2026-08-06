package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

const (
	UsernamePasswordIDPType = "username-password"
)

type Partition struct {
	ID        int64
	TenantID  uuid.UUID
	Name      string
	AliasName string
}

type IdentityProvider struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	IDPType     string
	Enabled     bool
	Alias       string
	Name        string
	PartitionID int64
	Config      IdentityProviderConfig
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type IdentityProviderConfig struct {
	UsernameField              string `json:"username_field"`
	IAL                        int    `json:"ial"`
	AAL                        int    `json:"aal"`
	AllowDecoupling            bool   `json:"allow_decoupling"`
	MaxFailedVerificationCount int    `json:"max_failed_verification_count"`
	PasswordBlockedTime        int    `json:"password_blocked_time"` // In seconds
}

type UserIdentity struct {
	ID                        uuid.UUID
	UserProfileID             uuid.UUID
	IdentityProviderID        uuid.UUID
	ExternalIdentityID        string
	LoginCount                int
	LastLoginAt               time.Time
	LastVerificationAttemptAt time.Time
	FailedVerificationCount   int
	Blocked                   bool
	CoupledAt                 time.Time
}

type PasswordCredential struct {
	UserProfileID      uuid.UUID
	IdentityProviderID uuid.UUID
	Argon2Hash         string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type LoginResult struct {
	UserProfile *UserProfile
	Identity    *UserIdentity
}

func (c IdentityProviderConfig) MarshalJSON() ([]byte, error) {
	type Alias IdentityProviderConfig
	return json.Marshal(&struct {
		Alias
	}{
		Alias: Alias(c),
	})
}

func (c *IdentityProviderConfig) UnmarshalJSON(data []byte) error {
	type Alias IdentityProviderConfig
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if c.UsernameField == "" {
		c.UsernameField = "preferredUsername"
	}
	if c.MaxFailedVerificationCount == 0 {
		c.MaxFailedVerificationCount = 5
	}
	if c.PasswordBlockedTime == 0 {
		c.PasswordBlockedTime = 900 // Default 15 minutes
	}
	return nil
}
