package service

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

// AdminTenantService manages tenants for console administrators.
//
// Access rule, enforced here so every caller is covered: the administrative (system) tenant may list, create, edit
// and delete every tenant; any other tenant may only see and edit itself and can never delete or create tenants.
type AdminTenantService struct {
	storage      port.Storage
	adminStorage port.AdminStorage
	clock        port.Clock
	tenants      port.TenantUseCase
}

var _ port.AdminTenantUseCase = (*AdminTenantService)(nil)

func NewAdminTenantService(s port.Storage, as port.AdminStorage, cl port.Clock, tenants port.TenantUseCase) *AdminTenantService {
	return &AdminTenantService{storage: s, adminStorage: as, clock: cl, tenants: tenants}
}

// actor loads the acting tenant. It is the single place that decides whether the caller is the system tenant.
func (s *AdminTenantService) actor(ctx context.Context, actingTenant uuid.UUID) (*model.Tenant, error) {
	t, err := s.storage.ResolveTenantByUUID(ctx, actingTenant)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// authorize returns the target tenant when the actor may manage it, and ErrForbidden otherwise. An unknown or
// foreign tenant is reported as forbidden to a non-system actor, so tenant IDs cannot be probed.
func (s *AdminTenantService) authorize(ctx context.Context, actingTenant, target uuid.UUID) (*model.Tenant, *model.Tenant, error) {
	actor, err := s.actor(ctx, actingTenant)
	if err != nil {
		return nil, nil, err
	}
	if !actor.IsSystem && actor.ID != target {
		return nil, nil, port.ErrForbidden
	}
	tenant := actor
	if actor.ID != target {
		if tenant, err = s.storage.ResolveTenantByUUID(ctx, target); err != nil {
			return nil, nil, err
		}
	}
	return actor, tenant, nil
}

// ListTenants returns every tenant for the system tenant and only the acting tenant otherwise.
func (s *AdminTenantService) ListTenants(ctx context.Context, actingTenant uuid.UUID) ([]port.TenantDetail, error) {
	actor, err := s.actor(ctx, actingTenant)
	if err != nil {
		return nil, err
	}
	tenants := []model.Tenant{*actor}
	if actor.IsSystem {
		if tenants, err = s.adminStorage.GetAllTenants(ctx); err != nil {
			return nil, fmt.Errorf("admin_tenant_service: failed listing tenants: %w", err)
		}
	}
	usage, err := s.usageByTenant(ctx)
	if err != nil {
		return nil, err
	}

	details := make([]port.TenantDetail, 0, len(tenants))
	for _, t := range tenants {
		details = append(details, port.TenantDetail{Tenant: t, Usage: usage[t.ID]})
	}
	sort.SliceStable(details, func(i, j int) bool {
		return strings.ToLower(details[i].Tenant.Name) < strings.ToLower(details[j].Tenant.Name)
	})
	return details, nil
}

func (s *AdminTenantService) usageByTenant(ctx context.Context) (map[uuid.UUID]model.TenantUsage, error) {
	rows, err := s.adminStorage.GetAllTenantUsage(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin_tenant_service: failed counting tenant contents: %w", err)
	}
	usage := make(map[uuid.UUID]model.TenantUsage, len(rows))
	for _, row := range rows {
		usage[row.TenantID] = row
	}
	return usage, nil
}

// GetTenant returns one tenant with what it owns.
func (s *AdminTenantService) GetTenant(ctx context.Context, actingTenant, id uuid.UUID) (*port.TenantDetail, error) {
	_, tenant, err := s.authorize(ctx, actingTenant, id)
	if err != nil {
		return nil, err
	}
	usage, err := s.usageByTenant(ctx)
	if err != nil {
		return nil, err
	}
	return &port.TenantDetail{Tenant: *tenant, Usage: usage[tenant.ID]}, nil
}

// DeleteTenant delegates to the tenant service, which refuses system tenants, the acting tenant and a wrong
// confirmation. Only the system tenant may delete anything.
func (s *AdminTenantService) DeleteTenant(ctx context.Context, cmd port.DeleteTenantCommand) error {
	actor, err := s.actor(ctx, cmd.ActingTenantID)
	if err != nil {
		return err
	}
	if !actor.IsSystem {
		return port.ErrForbidden
	}
	return s.tenants.DeleteTenant(ctx, cmd)
}
