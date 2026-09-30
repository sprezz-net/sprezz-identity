package port

import (
	"context"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

type CreateTenantCommand struct {
	TenantName  string
	DomainName  string
	AllowSignup bool
}

// DeleteTenantCommand carries the parameters of a tenant hard-delete.
type DeleteTenantCommand struct {
	TenantID uuid.UUID
	// Confirmation must exactly equal the tenant's domain name.
	Confirmation string
	// ActingTenantID is the tenant the request is executing under; it can never be deleted by its own session.
	ActingTenantID uuid.UUID
	// ActingUserID identifies the administrator for the final audit log record.
	ActingUserID string
}

type TenantUseCase interface {
	// ResolveTenantContext handles runtime domain-to-tenant verification mappings.
	ResolveTenantContext(ctx context.Context, host string) (*model.Tenant, error)

	// CreateTenant provisions a fresh, isolated tenant organizational boundary.
	CreateTenant(ctx context.Context, cmd CreateTenantCommand) (*model.Tenant, error)

	// ToggleTenantSignup enforces runtime platform signup policy adjustments.
	ToggleSignup(ctx context.Context, tenantID uuid.UUID, allow bool) (*model.Tenant, error)

	UpdateTenant(ctx context.Context, id uuid.UUID, name, domain string, config model.TenantConfig) (*model.Tenant, error)

	// DeleteTenant permanently removes a tenant and everything it owns. The administrative (system) tenant can never be
	// deleted, and the caller must echo the tenant's domain as a typed confirmation.
	DeleteTenant(ctx context.Context, cmd DeleteTenantCommand) error
}
