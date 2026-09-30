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

// AdminUserService manages users on behalf of console administrators. It is separate from UserProfileService,
// which serves the users themselves and therefore asks for current passwords and similar proofs.
type AdminUserService struct {
	storage      port.Storage
	adminStorage port.AdminStorage
	crypto       port.Crypto
	clock        port.Clock
}

var _ port.AdminUserUseCase = (*AdminUserService)(nil)

func NewAdminUserService(s port.Storage, as port.AdminStorage, c port.Crypto, cl port.Clock) *AdminUserService {
	return &AdminUserService{storage: s, adminStorage: as, crypto: c, clock: cl}
}

// ListUsers returns users ordered by username, then partition, so pages are stable between requests.
func (s *AdminUserService) ListUsers(ctx context.Context, tenantID uuid.UUID, partitionID int64) ([]model.UserProfile, error) {
	ids := []int64{partitionID}
	if partitionID == 0 {
		partitions, err := s.storage.GetPartitions(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("admin_user_service: failed reading partitions: %w", err)
		}
		ids = ids[:0]
		for _, p := range partitions {
			ids = append(ids, p.ID)
		}
	}

	users := []model.UserProfile{}
	for _, id := range ids {
		part, err := s.adminStorage.GetUserProfilesByTenant(ctx, tenantID, id)
		if err != nil {
			return nil, fmt.Errorf("admin_user_service: failed listing users: %w", err)
		}
		users = append(users, part...)
	}
	sort.SliceStable(users, func(i, j int) bool {
		a, b := strings.ToLower(users[i].PreferredUsername), strings.ToLower(users[j].PreferredUsername)
		if a != b {
			return a < b
		}
		return users[i].PartitionID < users[j].PartitionID
	})
	return users, nil
}

// GetUser loads a user with its sign-in methods and the state of its local password.
func (s *AdminUserService) GetUser(ctx context.Context, tenantID uuid.UUID, partitionID int64, id uuid.UUID) (*port.UserDetail, error) {
	user, err := s.storage.GetUserProfileByID(ctx, tenantID, partitionID, id)
	if err != nil {
		return nil, err
	}
	providers, err := s.storage.GetIdentityProviders(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("admin_user_service: failed reading providers: %w", err)
	}
	identities, err := s.storage.GetUserIdentitiesByProfileID(ctx, tenantID, partitionID, id)
	if err != nil {
		return nil, fmt.Errorf("admin_user_service: failed reading sign-in methods: %w", err)
	}

	detail := &port.UserDetail{User: *user, Links: linksFor(identities, providers)}
	if local := localProviderOf(providers, partitionID); local != nil {
		s.fillPasswordState(ctx, detail, local.ID)
	}
	return detail, nil
}

func linksFor(identities []model.UserIdentity, providers []model.IdentityProvider) []port.UserLink {
	byID := make(map[uuid.UUID]model.IdentityProvider, len(providers))
	for _, p := range providers {
		byID[p.ID] = p
	}
	links := make([]port.UserLink, 0, len(identities))
	for _, ident := range identities {
		p := byID[ident.IdentityProviderID]
		links = append(links, port.UserLink{Identity: ident, ProviderName: p.Name, ProviderAlias: p.Alias, ProviderType: p.IDPType})
	}
	sort.SliceStable(links, func(i, j int) bool { return links[i].ProviderName < links[j].ProviderName })
	return links
}

func localProviderOf(providers []model.IdentityProvider, partitionID int64) *model.IdentityProvider {
	for i := range providers {
		if providers[i].IDPType == model.UsernamePasswordIDPType && providers[i].PartitionID == partitionID {
			return &providers[i]
		}
	}
	return nil
}

func (s *AdminUserService) fillPasswordState(ctx context.Context, d *port.UserDetail, providerID uuid.UUID) {
	cred, err := s.storage.GetPasswordCredentialByProfileID(ctx, d.User.TenantID, d.User.PartitionID, d.User.ID, providerID)
	if err != nil {
		return
	}
	d.HasPassword = true
	if cred.IsBlocked(s.clock.Now()) {
		d.Locked, d.BlockedUntil = true, cred.BlockedUntil
	}
}
