package model

import "github.com/google/uuid"

type UserProfile struct {
	ID                uuid.UUID
	TenantID          uuid.UUID
	PreferredUsername string
	Name              string
	Email             string
	EmailVerified     bool
}
