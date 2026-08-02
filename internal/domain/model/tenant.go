package model

import (
	"time"

	"github.com/google/uuid"
)

type Tenant struct {
	ID                  uuid.UUID
	Name                string
	Domain              string
	IsActive            bool
	CreatedAt           time.Time
	PredefinedScopes    []string
	PredefinedAudiences []string
}
