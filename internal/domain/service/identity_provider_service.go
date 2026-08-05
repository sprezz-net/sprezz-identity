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

func (s *IdentityProviderService) GetIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error) {
	return s.storage.GetIdentityProviders(ctx, tenantID)
}

func (s *IdentityProviderService) VerifyPassword(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, password string) (bool, error) {
	provider, err := s.storage.GetIdentityProviderByType(ctx, tenantID, model.UsernamePasswordIDPType)
	if err != nil {
		return false, fmt.Errorf("username-password provider not found: %w", err)
	}

	passwordRecord, err := s.storage.GetPasswordCredential(ctx, userID, provider.ID)
	if err != nil {
		if errors.Is(err, port.ErrPasswordCredentialNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("lookup password credential: %w", err)
	}

	return verifyArgon2idPassword(password, passwordRecord.Argon2Hash), nil
}

func (s *IdentityProviderService) ChangePassword(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, currentPassword string, newPassword string) error {
	provider, err := s.storage.GetIdentityProviderByType(ctx, tenantID, model.UsernamePasswordIDPType)
	if err != nil {
		return fmt.Errorf("username-password provider not found: %w", err)
	}

	passwordRecord, err := s.storage.GetPasswordCredential(ctx, userID, provider.ID)
	if err != nil {
		return fmt.Errorf("lookup password credential: %w", err)
	}

	if !verifyArgon2idPassword(currentPassword, passwordRecord.Argon2Hash) {
		return errors.New("invalid current password")
	}

	newHash, err := argon2id.CreateHash(newPassword, argon2id.DefaultParams)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	passwordRecord.Argon2Hash = newHash
	if err := s.storage.SavePasswordCredential(ctx, *passwordRecord); err != nil {
		return fmt.Errorf("failed to save password credential: %w", err)
	}

	return nil
}

func (s *IdentityProviderService) CreateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) (*model.IdentityProvider, error) {
	if provider.Alias == "" {
		return nil, fmt.Errorf("provider alias is required")
	}
	if provider.IDPType == "" {
		return nil, fmt.Errorf("provider IDP type is required")
	}

	if provider.IDPType == model.UsernamePasswordIDPType {
		existing, err := s.storage.GetIdentityProviders(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		for _, ext := range existing {
			if ext.IDPType == model.UsernamePasswordIDPType {
				return nil, errors.New("a username-password identity provider already exists for this tenant")
			}
		}
	}

	provider.ID = uuid.New()
	provider.TenantID = tenantID

	if err := s.storage.CreateIdentityProvider(ctx, tenantID, provider); err != nil {
		return nil, err
	}

	return &provider, nil
}

func (s *IdentityProviderService) DeleteIdentityProvider(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) error {
	return s.storage.DeleteIdentityProvider(ctx, tenantID, idpID)
}

func (s *IdentityProviderService) UpdateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) (*model.IdentityProvider, error) {
	if provider.Alias == "" {
		return nil, fmt.Errorf("provider alias is required")
	}
	if provider.IDPType == "" {
		return nil, fmt.Errorf("provider IDP type is required")
	}

	if provider.IDPType == model.UsernamePasswordIDPType {
		existing, err := s.storage.GetIdentityProviders(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		for _, ext := range existing {
			if ext.IDPType == model.UsernamePasswordIDPType && ext.ID != provider.ID {
				return nil, errors.New("a username-password identity provider already exists for this tenant")
			}
		}
	}

	provider.TenantID = tenantID
	// In our PostgresStorage implementation, CreateIdentityProvider uses ON CONFLICT DO UPDATE
	if err := s.storage.CreateIdentityProvider(ctx, tenantID, provider); err != nil {
		return nil, err
	}

	return &provider, nil
}
