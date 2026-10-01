package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

// PatchTenant saves one section. The stored tenant is re-read and only the submitted section is overlaid, so a
// save from one card can never drop settings it does not show (assurance levels, registration mode, secrets).
func (s *AdminTenantService) PatchTenant(ctx context.Context, cmd port.PatchTenantCommand) error {
	actor, tenant, err := s.authorize(ctx, cmd.ActingTenant, cmd.TenantID)
	if err != nil {
		return err
	}

	updated := *tenant
	verr := port.NewValidationError()
	switch cmd.Section {
	case port.TenantSectionGeneral:
		if err := s.overlayGeneral(ctx, &updated, cmd, verr); err != nil {
			return err
		}
	case port.TenantSectionSignup:
		return s.setSignup(ctx, tenant, cmd.AllowSignup)
	case port.TenantSectionStatus:
		return s.setActive(ctx, actor, tenant, cmd)
	case port.TenantSectionRedirects:
		overlayRedirects(&updated, cmd, verr)
	case port.TenantSectionScopes:
		overlayScopes(&updated, cmd, verr)
	default:
		verr.Add("section", "unknown tenant section")
	}
	if verr.HasErrors() {
		return verr
	}
	return s.save(ctx, updated)
}

func (s *AdminTenantService) save(ctx context.Context, t model.Tenant) error {
	t.UpdatedAt = s.clock.Now()
	if err := s.adminStorage.CreateTenant(ctx, t); err != nil {
		return fmt.Errorf("admin_tenant_service: failed saving tenant: %w", err)
	}
	return nil
}

// overlayGeneral changes the name and the domain. The system tenant's domain is the key its bootstrap, admin
// issuer and redirect URIs hang off, so it can never be changed here.
func (s *AdminTenantService) overlayGeneral(ctx context.Context, t *model.Tenant, cmd port.PatchTenantCommand, verr *port.ValidationError) error {
	name, domain := strings.TrimSpace(cmd.Name), normalizeDomain(cmd.Domain)
	validateTenantName(name, verr)
	if t.IsSystem && domain != t.Domain {
		return port.ErrSystemManaged
	}
	if !t.IsSystem {
		validateDomain(domain, verr)
	}
	if verr.HasErrors() {
		return nil
	}
	if domain != t.Domain {
		if err := s.ensureDomainFree(ctx, domain, t.ID, verr); err != nil {
			return err
		}
	}
	t.Name, t.Domain = name, domain
	return nil
}

// ensureDomainFree makes sure no other tenant already owns the domain.
func (s *AdminTenantService) ensureDomainFree(ctx context.Context, domain string, self uuid.UUID, verr *port.ValidationError) error {
	other, err := s.storage.ResolveTenantByDomain(ctx, domain)
	if err != nil {
		if errors.Is(err, port.ErrTenantNotFound) {
			return nil
		}
		return fmt.Errorf("admin_tenant_service: failed checking domain: %w", err)
	}
	if other.ID != self {
		verr.Add("domain", "another tenant already uses this domain")
	}
	return nil
}

// overlayRedirects replaces the redirect whitelist and the default. Entries are exact URIs; the default must be one
// of them. The system tenant must keep the two URIs the admin console itself relies on.
func overlayRedirects(t *model.Tenant, cmd port.PatchTenantCommand, verr *port.ValidationError) {
	whitelist := validateURIList(cmd.RedirectWhitelist, "redirect_whitelist", false, verr)
	def := resolveDefaultRedirect(cmd.DefaultRedirectURI, whitelist, verr)
	if t.IsSystem {
		for _, required := range systemRedirects(*t) {
			if !slices.Contains(whitelist, required) {
				verr.Add("redirect_whitelist", "the administrative tenant must keep "+required)
			}
		}
	}
	if verr.HasErrors() {
		return
	}
	t.Config.RedirectWhitelist, t.Config.DefaultRedirectURI = whitelist, def
}

func systemRedirects(t model.Tenant) []string {
	base := t.GetBaseURI()
	return []string{base + port.RouteAdmin, base + port.RouteFederationCallback}
}

// overlayScopes replaces the scope and audience lists the tenant offers.
func overlayScopes(t *model.Tenant, cmd port.PatchTenantCommand, verr *port.ValidationError) {
	scopes, audiences := cleanUnique(cmd.PredefinedScopes), cleanUnique(cmd.PredefinedAudiences)
	validateTenantScopes(scopes, verr)
	validateTenantAudiences(audiences, verr)
	if verr.HasErrors() {
		return
	}
	t.Config.PredefinedScopes, t.Config.PredefinedAudiences = scopes, audiences
}

// setSignup delegates to the tenant service so closing signup on the system tenant keeps its side effect of
// ending the sessions that were created while registration was open.
func (s *AdminTenantService) setSignup(ctx context.Context, t *model.Tenant, allow bool) error {
	if _, err := s.tenants.ToggleSignup(ctx, t.ID, allow); err != nil {
		return fmt.Errorf("admin_tenant_service: failed changing registration: %w", err)
	}
	return nil
}
