package model

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Custom domain errors to give clear context to the use-case layer
var (
	ErrAccountBlocked         = errors.New("user account is blocked")
	ErrAccountNotActivated    = errors.New("user account is not activated")
	ErrAccountDeactivated     = errors.New("user account has been deactivated")
	ErrAccountApprovalPending = errors.New("user account is pending approval")
)

type ProfileLifecycleState string

const (
	LifecycleCreated     ProfileLifecycleState = "CREATED"
	LifecycleInvited     ProfileLifecycleState = "INVITED"
	LifecycleRequested   ProfileLifecycleState = "REQUESTED"
	LifecycleActivated   ProfileLifecycleState = "ACTIVATED"
	LifecycleDeactivated ProfileLifecycleState = "DEACTIVATED"
)

type UserProfile struct {
	ID                uuid.UUID
	TenantID          uuid.UUID
	PartitionID       int64
	PreferredUsername string
	FirstName         string // Maps to OIDC standard 'given_name' assertion
	LastName          string // Maps to OIDC standard 'family_name' assertion
	Name              string // Serves as the computed full display name
	Email             string
	EmailVerified     bool
	LifecycleState    ProfileLifecycleState
	Blocked           bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// DisplayName dynamically computes a formatted name payload based on field density.
func (p UserProfile) DisplayName() string {
	// 1. Evaluate explicit split components first
	firstName := strings.TrimSpace(p.FirstName)
	lastName := strings.TrimSpace(p.LastName)

	if firstName != "" || lastName != "" {
		return strings.TrimSpace(fmt.Sprintf("%s %s", firstName, lastName))
	}

	// 2. Fall back to structural composite field if split entries are missing
	if legacyName := strings.TrimSpace(p.Name); legacyName != "" {
		return legacyName
	}

	// 3. Ultimate fallback to ensure token claims are never left empty or broken
	if p.PreferredUsername != "" {
		return p.PreferredUsername
	}
	return p.Email
}

// IsLoginAllowed evaluates the security gates and returns a semantic error
// if authentication should be denied.
func (p *UserProfile) IsLoginAllowed() (bool, error) {
	// Gate 1: Check the global administrative override first
	if p.Blocked {
		return false, ErrAccountBlocked
	}

	// Gate 2: Verify the progression state
	switch p.LifecycleState {
	case LifecycleActivated:
		return true, nil // Access granted
	case LifecycleRequested:
		return false, ErrAccountApprovalPending
	case LifecycleInvited, LifecycleCreated:
		return false, ErrAccountNotActivated
	case LifecycleDeactivated:
		return false, ErrAccountDeactivated
	default:
		return false, ErrAccountNotActivated
	}
}
