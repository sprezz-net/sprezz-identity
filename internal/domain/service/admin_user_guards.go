package service

import (
	"context"
	"fmt"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

// isAdminPartition reports whether a partition is the one whose users may sign in to the admin console.
func (s *AdminUserService) isAdminPartition(ctx context.Context, tenantID uuid.UUID, partitionID int64) (bool, error) {
	partitions, err := s.storage.GetPartitions(ctx, tenantID)
	if err != nil {
		return false, fmt.Errorf("admin_user_service: failed reading partitions: %w", err)
	}
	for _, p := range partitions {
		if p.ID == partitionID {
			return p.AliasName == model.AdminPartitionAliasName, nil
		}
	}
	return false, port.ErrPartitionNotFound
}

// otherUsableAdmins counts administrators other than the target who can currently sign in.
func (s *AdminUserService) otherUsableAdmins(ctx context.Context, tenantID uuid.UUID, partitionID int64, except uuid.UUID) (int, error) {
	users, err := s.adminStorage.GetUserProfilesByTenant(ctx, tenantID, partitionID)
	if err != nil {
		return 0, fmt.Errorf("admin_user_service: failed reading administrators: %w", err)
	}
	count := 0
	for i := range users {
		if users[i].ID == except {
			continue
		}
		if allowed, _ := users[i].IsLoginAllowed(); allowed {
			count++
		}
	}
	return count, nil
}

// guardLosingAccess refuses a change that would stop an administrator from signing in when that administrator is
// the acting one, or the last one who can. It does nothing for ordinary users and for changes that keep access.
func (s *AdminUserService) guardLosingAccess(ctx context.Context, before, after *model.UserProfile, acting uuid.UUID) error {
	wasAllowed, _ := before.IsLoginAllowed()
	if !wasAllowed {
		return nil
	}
	if after != nil {
		if stillAllowed, _ := after.IsLoginAllowed(); stillAllowed {
			return nil
		}
	}

	isAdmin, err := s.isAdminPartition(ctx, before.TenantID, before.PartitionID)
	if err != nil || !isAdmin {
		return err
	}
	if before.ID == acting {
		return port.ErrOwnAccount
	}
	others, err := s.otherUsableAdmins(ctx, before.TenantID, before.PartitionID, before.ID)
	if err != nil {
		return err
	}
	if others == 0 {
		return port.ErrLastAdministrator
	}
	return nil
}
