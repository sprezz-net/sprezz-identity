package service

import (
	"context"
	"fmt"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

// GetIdentityProvider returns one provider of the tenant.
func (s *IdentityProviderService) GetIdentityProvider(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) (*model.IdentityProvider, error) {
	return s.storage.GetIdentityProviderByUUID(ctx, tenantID, idpID)
}

// GetIdentityProviderUsage indexes the usage of every provider by provider ID.
func (s *IdentityProviderService) GetIdentityProviderUsage(ctx context.Context, tenantID uuid.UUID) (map[uuid.UUID]model.IdentityProviderUsage, error) {
	rows, err := s.adminStorage.GetIdentityProviderUsage(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed reading identity provider usage: %w", err)
	}
	usage := make(map[uuid.UUID]model.IdentityProviderUsage, len(rows))
	for _, row := range rows {
		usage[row.ProviderID] = row
	}
	return usage, nil
}

// PatchIdentityProvider saves one section. The stored provider is re-read, only the submitted section is overlaid
// and the result is validated as a whole, so a section save can never drop configuration the form does not show
// (domain aliases, lockout policy, discovery data and so on).
func (s *IdentityProviderService) PatchIdentityProvider(ctx context.Context, cmd port.PatchIdentityProviderCommand) error {
	existing, err := s.storage.GetIdentityProviderByUUID(ctx, cmd.TenantID, cmd.ID)
	if err != nil {
		return fmt.Errorf("failed locating identity provider: %w", err)
	}
	if existing.IsSystem {
		return port.ErrSystemManaged
	}

	updated := *existing
	if err := overlayProviderSection(&updated, cmd); err != nil {
		return err
	}
	if cmd.Section == port.IDPSectionConnection {
		if verr := s.refreshDiscovery(ctx, &updated); verr != nil {
			return verr
		}
	}
	if verr := validateIdentityProvider(updated); verr.HasErrors() {
		return verr
	}
	return s.saveProvider(ctx, cmd.TenantID, updated)
}

// saveProvider persists a provider that already passed validation. The alias, type and partition are the
// storage conflict key and are never changed here.
func (s *IdentityProviderService) saveProvider(ctx context.Context, tenantID uuid.UUID, p model.IdentityProvider) error {
	p.TenantID = tenantID
	p.Name = strings.TrimSpace(p.Name)
	p.Config.Scopes = nonNilStrings(p.Config.Scopes)
	p.Config.DomainAliases = nonNilStrings(p.Config.DomainAliases)
	return s.adminStorage.CreateIdentityProvider(ctx, tenantID, p)
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// overlayProviderSection copies the fields of one section from the command onto the provider.
func overlayProviderSection(p *model.IdentityProvider, cmd port.PatchIdentityProviderCommand) error {
	c := &p.Config
	switch cmd.Section {
	case port.IDPSectionGeneral:
		p.Name, p.Enabled = cmd.Name, cmd.Enabled
	case port.IDPSectionConnection:
		c.DiscoveryEndpoint = strings.TrimSpace(cmd.DiscoveryEndpoint)
		p.Issuer = strings.TrimSpace(cmd.Issuer)
		c.AuthenticationMethod = cmd.AuthenticationMethod
		c.PkceEnabled, c.ParEnabled, c.SLOEnabled = cmd.PkceEnabled, cmd.ParEnabled, cmd.SLOEnabled
	case port.IDPSectionCredentials:
		c.ClientID = strings.TrimSpace(cmd.ClientID)
		switch {
		case cmd.ClearSecret:
			c.ClientSecret = ""
		case cmd.ClientSecret != "":
			c.ClientSecret = cmd.ClientSecret
		}
	case port.IDPSectionBehavior:
		c.Scopes, c.UserIdentifierClaim, c.DomainAliases = cmd.Scopes, strings.TrimSpace(cmd.UserIdentifierClaim), cmd.DomainAliases
		c.AutoProvisionUser, c.AutoVerifyEmail = cmd.AutoProvisionUser, cmd.AutoVerifyEmail
	case port.IDPSectionAssurance:
		c.AAL, c.IAL, c.ACRValues = cmd.AAL, cmd.IAL, cmd.ACRValues
		c.AcrToTuple, c.AmrToAAL = cmd.AcrToTuple, cmd.AmrToAAL
	case port.IDPSectionLocalPolicy:
		c.UsernameField, c.MaxFailedVerificationCount = cmd.UsernameField, cmd.MaxFailedVerificationCount
		c.PasswordBlockedTime, c.AllowDecoupling = cmd.PasswordBlockedTime, cmd.AllowDecoupling
	default:
		verr := port.NewValidationError()
		verr.Add("section", "unknown identity provider section")
		return verr
	}
	return nil
}
