package model

import (
	"time"

	"github.com/google/uuid"
)

// ApplicationSummary projects an aggregated list view model of an application registration.
// It appends human-readable profile and routing group tags to optimize rendering performance
// across separate static integration screens and high-volume dynamic fleet dashboard grids.
type ApplicationSummary struct {
	ID              uuid.UUID `json:"id"`
	ClientID        string    `json:"client_id"`
	ApplicationName string    `json:"application_name"`
	IsEnabled       bool      `json:"is_enabled"`
	IsDynamic       bool      `json:"is_dynamic"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	LastUsedAt      time.Time `json:"last_used_at"`

	// Relational Context Pointers (Feeds clickable UI links to specific configuration editors)
	ProfileID   uuid.UUID `json:"profile_id"`
	ProfileName string    `json:"profile_name"`
	GroupID     uuid.UUID `json:"group_id"`
	GroupName   string    `json:"group_name"`
}

// ApplicationDetailsProps wraps Application, ApplicationProfile, and ApplicationGroup into a unified layout for edit/view workflows.
type ApplicationDetailsProps struct {
	Application        *Application        `json:"application"`
	ApplicationProfile *ApplicationProfile `json:"application_profile"`
	ApplicationGroup   *ApplicationGroup   `json:"application_group"`
}
