package port

import (
	"context"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

// TenantSection names one independently saved part of the tenant page.
type TenantSection string

const (
	TenantSectionGeneral   TenantSection = "general"
	TenantSectionSignup    TenantSection = "signup"
	TenantSectionRedirects TenantSection = "redirects"
	TenantSectionScopes    TenantSection = "scopes"
	TenantSectionStatus    TenantSection = "status"
)

// PatchTenantCommand saves one section of a tenant. Only the fields of Section are read; everything else the
// tenant holds (assurance levels, registration settings, encrypted secrets) is carried over unchanged.
type PatchTenantCommand struct {
	TenantID     uuid.UUID
	ActingTenant uuid.UUID
	Section      TenantSection

	// General
	Name   string
	Domain string

	// Signup
	AllowSignup bool

	// Status. An inactive tenant refuses every sign-in and token request.
	Active bool

	// Redirects
	RedirectWhitelist  []string
	DefaultRedirectURI string

	// Scopes
	PredefinedScopes    []string
	PredefinedAudiences []string
}

// CreateTenantFromConsoleCommand adds a tenant from the admin console.
type CreateTenantFromConsoleCommand struct {
	ActingTenant uuid.UUID
	Name         string
	Domain       string
}

// TenantDetail is a tenant together with what it owns.
type TenantDetail struct {
	Tenant model.Tenant
	Usage  model.TenantUsage
}

// AdminTenantUseCase defines the driving port for managing tenants from the admin console. Managing other tenants is
// reserved for the administrative (system) tenant; every other tenant may only see and edit itself.
type AdminTenantUseCase interface {
	// ListTenants returns the tenants the acting tenant may see: all of them for the system tenant, itself otherwise.
	ListTenants(ctx context.Context, actingTenant uuid.UUID) ([]TenantDetail, error)
	GetTenant(ctx context.Context, actingTenant, id uuid.UUID) (*TenantDetail, error)
	CreateTenant(ctx context.Context, cmd CreateTenantFromConsoleCommand) (*model.Tenant, error)
	PatchTenant(ctx context.Context, cmd PatchTenantCommand) error
	DeleteTenant(ctx context.Context, cmd DeleteTenantCommand) error
}
