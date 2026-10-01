package service

import (
	"context"
	"fmt"
	"log/slog"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

// setActive activates or deactivates a tenant.
//
// Only the administrative tenant may do it, and never to itself or to another system tenant: that would shut out
// the console the change is made from. Deactivating ends every live session and refresh token of the tenant, so
// the change takes effect now and not when the next token expires. Reactivating restores nothing; people sign in
// again.
func (s *AdminTenantService) setActive(ctx context.Context, actor, target *model.Tenant, cmd port.PatchTenantCommand) error {
	if !actor.IsSystem {
		return port.ErrForbidden
	}
	if target.IsSystem {
		return port.ErrSystemManaged
	}
	if target.ID == actor.ID {
		return port.ErrOwnAccount
	}
	if target.IsActive == cmd.Active {
		return nil
	}

	updated := *target
	updated.IsActive = cmd.Active
	if err := s.save(ctx, updated); err != nil {
		return err
	}

	slog.Warn("tenant status changed", "tenant_id", target.ID, "tenant_domain", target.Domain, "active", cmd.Active, "by_tenant", actor.ID)
	if cmd.Active {
		return nil
	}
	if err := s.storage.PurgeTenantSessionsAndTokens(ctx, target.ID); err != nil {
		return fmt.Errorf("tenant deactivated, but ending its sessions failed: %w", err)
	}
	return nil
}
