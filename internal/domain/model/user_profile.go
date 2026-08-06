package model

import (
	"time"

	"github.com/google/uuid"
)

type UserProfile struct {
	ID                uuid.UUID
	TenantID          uuid.UUID
	PartitionID       int64
	PreferredUsername string
	Name              string
	Email             string
	EmailVerified     bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}
