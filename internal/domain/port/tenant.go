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

type TenantUseCase interface {
	// ResolveTenantContext handles runtime domain-to-tenant verification mappings.
	ResolveTenantContext(ctx context.Context, host string) (*model.Tenant, error)

	// CreateTenant provisions a fresh, isolated tenant organizational boundary.
	CreateTenant(ctx context.Context, cmd CreateTenantCommand) (*model.Tenant, error)

	// ToggleTenantSignup enforces runtime platform signup policy adjustments.
	ToggleSignup(ctx context.Context, tenantID uuid.UUID, allow bool) (*model.Tenant, error)

	UpdateTenant(ctx context.Context, id uuid.UUID, name, domain string, config model.TenantConfig) (*model.Tenant, error)
}
