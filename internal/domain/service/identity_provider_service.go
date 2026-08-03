package service

import (
	"context"
	"errors"
	"fmt"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"
)

type IdentityProviderService struct {
	storage port.Storage
	clock   port.Clock
}

func NewIdentityProviderService(storage port.Storage, cl port.Clock) *IdentityProviderService {
	return &IdentityProviderService{storage: storage, clock: cl}
}

func (s *IdentityProviderService) AuthenticateUsernamePassword(ctx context.Context, tenantID uuid.UUID, username string, password string) (*model.LoginResult, error) {
	providers, err := s.storage.GetEnabledIdentityProviders(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve enabled identity providers: %w", err)
	}
	if len(providers) == 0 {
		return nil, errors.New("no identity providers configured for tenant")
	}

	var provider *model.IdentityProvider
	for _, candidate := range providers {
		if candidate.IDPType == model.UsernamePasswordIDPType {
			provider = &candidate
			break
		}
	}
	if provider == nil {
		return nil, fmt.Errorf("identity provider %s is not configured for tenant", model.UsernamePasswordIDPType)
	}

	profile, err := s.storage.GetUserProfileByIdentifier(ctx, tenantID, provider.ID, username)
	if err != nil {
		return nil, fmt.Errorf("lookup user profile: %w", err)
	}
	passwordRecord, err := s.storage.GetPasswordCredential(ctx, profile.ID, provider.ID)
	if err != nil {
		return nil, fmt.Errorf("lookup password credential: %w", err)
	}
	if !verifyArgon2idPassword(password, passwordRecord.Argon2Hash) {
		return nil, errors.New("invalid credentials")
	}

	now := s.clock.Now()
	identity, err := s.storage.GetIdentityByProfileAndProvider(ctx, profile.ID, provider.ID)
	if err != nil {
		identity = &model.UserIdentity{
			ID:                 uuid.New(),
			UserProfileID:      profile.ID,
			IdentityProviderID: provider.ID,
			ExternalIdentityID: profile.ID.String(),
			CoupledAt:          now,
			LoginCount:         0,
		}
	}
	identity.LastLoginAt = now
	identity.LoginCount++
	identity.Blocked = false
	if identity.CoupledAt.IsZero() {
		identity.CoupledAt = now
	}
	if err := s.storage.UpsertIdentity(ctx, *identity); err != nil {
		return nil, fmt.Errorf("upsert identity record: %w", err)
	}

	return &model.LoginResult{UserProfile: profile, Identity: identity}, nil
}

func verifyArgon2idPassword(password string, hash string) bool {
	match, err := argon2id.ComparePasswordAndHash(password, hash)
	return err == nil && match
}
