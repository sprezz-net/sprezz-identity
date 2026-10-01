package service

import (
	"context"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

// CreateTenant adds a tenant. Only the system tenant may do this. Provisioning (partitions, the admin SSO link and
// the default settings) is done by the tenant service, so a console-created tenant is identical to any other.
func (s *AdminTenantService) CreateTenant(ctx context.Context, cmd port.CreateTenantFromConsoleCommand) (*model.Tenant, error) {
	actor, err := s.actor(ctx, cmd.ActingTenant)
	if err != nil {
		return nil, err
	}
	if !actor.IsSystem {
		return nil, port.ErrForbidden
	}

	name, domain := strings.TrimSpace(cmd.Name), normalizeDomain(cmd.Domain)
	verr := port.NewValidationError()
	validateTenantName(name, verr)
	validateDomain(domain, verr)
	if verr.HasErrors() {
		return nil, verr
	}
	if err := s.ensureDomainFree(ctx, domain, uuid.Nil, verr); err != nil {
		return nil, err
	}
	if verr.HasErrors() {
		return nil, verr
	}

	return s.tenants.CreateTenant(ctx, port.CreateTenantCommand{TenantName: name, DomainName: domain})
}
