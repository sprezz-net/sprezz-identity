package service

import (
	"context"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

// requireActiveTenant refuses entry to a tenant an administrator has deactivated. A missing tenant is refused too,
// so the gate fails closed.
func requireActiveTenant(tenant *model.Tenant) error {
	if tenant == nil || !tenant.IsActive {
		return port.ErrTenantInactive
	}
	return nil
}

// ensureTenantActive loads the tenant and refuses entry when it is inactive. Every service that signs a user in,
// issues a token or a session, or answers a protocol request calls it (or requireActiveTenant) before it changes
// any state, so a deactivation cannot be bypassed by reaching the domain without the HTTP middleware.
//
// Operations that only reduce access stay available on an inactive tenant: logout and token revocation.
func ensureTenantActive(ctx context.Context, storage port.Storage, tenantID uuid.UUID) (*model.Tenant, error) {
	tenant, err := storage.ResolveTenantByUUID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if err := requireActiveTenant(tenant); err != nil {
		return nil, err
	}
	return tenant, nil
}

// activeTenantFor is ensureTenantActive for commands that may already carry the tenant resolved for this request.
// A supplied tenant is checked too, so a caller cannot smuggle in a stale or inactive one.
func activeTenantFor(ctx context.Context, storage port.Storage, supplied *model.Tenant, tenantID uuid.UUID) (*model.Tenant, error) {
	if supplied != nil {
		if err := requireActiveTenant(supplied); err != nil {
			return nil, err
		}
		return supplied, nil
	}
	return ensureTenantActive(ctx, storage, tenantID)
}
