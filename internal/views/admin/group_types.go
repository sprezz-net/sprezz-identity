package admin

import (
	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

// StandardScopes are offered as one-click suggestions in the scope picker.
var StandardScopes = []string{"openid", "profile", "email", "offline_access", "phone", "address"}

// SectionResult carries the outcome of saving one section card back into its re-rendered card.
type SectionResult struct {
	Saved  bool
	Error  string            // a problem that does not belong to a single field
	Errors map[string]string // field name to message
}

// FieldErr returns the message for a field, and is safe on a nil map.
func (r SectionResult) FieldErr(field string) string {
	return r.Errors[field]
}

// GroupPageProps is everything the group detail page renders.
type GroupPageProps struct {
	ActiveTenant model.Tenant
	Group        *model.ApplicationGroup
	Partitions   []model.PartitionWithProviders
	UsedBy       []model.ApplicationSummary
	Counts       NavCounts
	Msg          string
	Sections     map[string]SectionResult
}

// Section returns the result for a section, or the zero value when it was not just saved.
func (p GroupPageProps) Section(name string) SectionResult {
	return p.Sections[name]
}

// NavCounts feeds the numbers in the Applications sub navigation.
type NavCounts struct {
	Applications int
	Groups       int
	Profiles     int
}

// SignInCardProps is the sign-in methods section of a group.
type SignInCardProps struct {
	Group      *model.ApplicationGroup
	Partitions []model.PartitionWithProviders
	Result     SectionResult
	// FederatedOnly hides local accounts, which the admin group never allows.
	FederatedOnly bool
}

// idpAllowed reports whether a provider is part of the group's allowed list.
func idpAllowed(group *model.ApplicationGroup, id uuid.UUID) bool {
	return containsUUID(group.AllowedIDPIDs, id)
}

// isDefaultIDP reports whether a provider is the group's default sign-in method.
func isDefaultIDP(group *model.ApplicationGroup, id uuid.UUID) bool {
	return group.DefaultIDPID != nil && *group.DefaultIDPID == id
}

// allowedCount counts how many providers of a partition the group allows.
func allowedCount(group *model.ApplicationGroup, partition model.PartitionWithProviders) int {
	n := 0
	for _, p := range partition.Providers {
		if idpAllowed(group, p.ID) {
			n++
		}
	}
	return n
}

// totalProviders counts every provider across partitions.
func totalProviders(partitions []model.PartitionWithProviders) int {
	n := 0
	for _, p := range partitions {
		n += len(p.Providers)
	}
	return n
}

// totalAllowed counts the allowed providers across partitions.
func totalAllowed(group *model.ApplicationGroup, partitions []model.PartitionWithProviders) int {
	n := 0
	for _, p := range partitions {
		n += allowedCount(group, p)
	}
	return n
}

// hasLocalProvider reports whether a partition offers local accounts at all.
func hasLocalProvider(partition model.PartitionWithProviders) bool {
	for _, p := range partition.Providers {
		if p.IDPType == model.UsernamePasswordIDPType {
			return true
		}
	}
	return false
}
