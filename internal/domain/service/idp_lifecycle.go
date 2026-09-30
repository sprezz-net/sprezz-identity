package service

import (
	"context"
	"fmt"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

// CreateIdentityProvider validates and creates a provider. It is always created as a normal provider: the system
// flag is only ever set by the bootstrap.
func (s *IdentityProviderService) CreateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) (*model.IdentityProvider, error) {
	provider.Alias = strings.TrimSpace(provider.Alias)
	provider.Config = withConfigDefaults(provider.IDPType, provider.Config)

	if verr := s.refreshDiscovery(ctx, &provider); verr != nil {
		return nil, verr
	}
	if verr := validateNewIdentityProvider(provider); verr.HasErrors() {
		return nil, verr
	}
	provider.ID = uuid.New()
	if err := s.ensureUniqueProvider(ctx, tenantID, provider); err != nil {
		return nil, err
	}

	provider.IsSystem = false
	if err := s.saveProvider(ctx, tenantID, provider); err != nil {
		return nil, err
	}
	return &provider, nil
}

// CreateSystemIdentityProvider creates a provider the platform depends on, such as the admin console's
// 'admin-sso'. It is used only by the tenant bootstrap paths and is deliberately not part of the admin use case
// port, so the admin UI can never create a system provider.
func (s *IdentityProviderService) CreateSystemIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) (*model.IdentityProvider, error) {
	provider.Config = withConfigDefaults(provider.IDPType, provider.Config)
	if verr := validateNewIdentityProvider(provider); verr.HasErrors() {
		return nil, verr
	}
	provider.ID = uuid.New()
	provider.IsSystem = true
	if err := s.saveProvider(ctx, tenantID, provider); err != nil {
		return nil, err
	}
	return &provider, nil
}

// UpdateIdentityProvider replaces a provider with a complete new definition. The alias, type and partition are the
// storage conflict key, so they are taken from the stored provider; changing them would create a second provider
// instead of editing this one. Page edits use PatchIdentityProvider, which also keeps unseen configuration.
func (s *IdentityProviderService) UpdateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) (*model.IdentityProvider, error) {
	existing, err := s.storage.GetIdentityProviderByUUID(ctx, tenantID, provider.ID)
	if err != nil {
		return nil, fmt.Errorf("failed locating identity provider: %w", err)
	}
	if existing.IsSystem {
		return nil, port.ErrSystemManaged
	}

	provider.Alias, provider.IDPType, provider.PartitionID = existing.Alias, existing.IDPType, existing.PartitionID
	provider.IsSystem = false
	provider.Config = withConfigDefaults(provider.IDPType, provider.Config)

	if verr := validateIdentityProvider(provider); verr.HasErrors() {
		return nil, verr
	}
	if err := s.saveProvider(ctx, tenantID, provider); err != nil {
		return nil, err
	}
	return &provider, nil
}

// DescribeIdentityProviderDeletion reports what removing a provider would do, for the delete dialog.
func (s *IdentityProviderService) DescribeIdentityProviderDeletion(ctx context.Context, tenantID, idpID uuid.UUID) (port.IdentityProviderDeletion, error) {
	usage, err := s.GetIdentityProviderUsage(ctx, tenantID)
	if err != nil {
		return port.IdentityProviderDeletion{}, err
	}
	entry := usage[idpID]
	return port.IdentityProviderDeletion{LinkedUsers: entry.LinkedUsers, GroupNames: entry.GroupNames}, nil
}

// DeleteIdentityProvider removes a provider. System providers and providers that application groups still allow
// cannot be deleted; users linked to the provider lose that link.
func (s *IdentityProviderService) DeleteIdentityProvider(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) error {
	existing, err := s.storage.GetIdentityProviderByUUID(ctx, tenantID, idpID)
	if err != nil {
		return fmt.Errorf("failed locating identity provider for removal: %w", err)
	}
	if existing.IsSystem {
		return port.ErrSystemManaged
	}

	deletion, err := s.DescribeIdentityProviderDeletion(ctx, tenantID, idpID)
	if err != nil {
		return err
	}
	if len(deletion.GroupNames) > 0 {
		return fmt.Errorf("provider is allowed by %d application group(s): %w", len(deletion.GroupNames), port.ErrInUse)
	}

	// The storage layer repeats the group check through the foreign key, which covers a concurrent change.
	return s.adminStorage.DeleteIdentityProvider(ctx, tenantID, idpID)
}

// ensureUniqueProvider keeps provider routing unambiguous: one local accounts provider per partition, and one
// alias per partition and type (the storage conflict key).
func (s *IdentityProviderService) ensureUniqueProvider(ctx context.Context, tenantID uuid.UUID, p model.IdentityProvider) error {
	existing, err := s.storage.GetIdentityProviders(ctx, tenantID)
	if err != nil {
		return err
	}
	verr := port.NewValidationError()
	for _, other := range existing {
		if other.ID == p.ID || other.PartitionID != p.PartitionID {
			continue
		}
		if p.IDPType == model.UsernamePasswordIDPType && other.IDPType == model.UsernamePasswordIDPType {
			verr.Add("idp_type", "this partition already has a local accounts provider")
		}
		if other.IDPType == p.IDPType && other.Alias == p.Alias {
			verr.Add("alias", "this partition already has a provider with that alias")
		}
	}
	if verr.HasErrors() {
		return verr
	}
	return nil
}

// withConfigDefaults fills the security defaults a provider needs, so an unset value is never stored as zero.
func withConfigDefaults(idpType string, c model.IdentityProviderConfig) model.IdentityProviderConfig {
	if idpType == model.UsernamePasswordIDPType {
		if c.UsernameField == "" {
			c.UsernameField = "preferredUsername"
		}
		if c.MaxFailedVerificationCount == 0 {
			c.MaxFailedVerificationCount = 5
		}
		if c.PasswordBlockedTime == 0 {
			c.PasswordBlockedTime = 900
		}
	}
	if c.AAL == 0 {
		c.AAL = 1
	}
	if c.IAL == 0 {
		c.IAL = 1
	}
	return c
}
