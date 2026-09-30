package service

import (
	"context"
	"fmt"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

// enabledOrStored returns the explicit enabled flag when one was given, and the stored state otherwise.
func enabledOrStored(explicit *bool, stored bool) bool {
	if explicit != nil {
		return *explicit
	}
	return stored
}

// PatchGroup saves one section of a group. The stored group is re-read, only the submitted section is overlaid
// and the result goes through the same validated update path as a full save, so system-object protection and
// routing validation apply unchanged. A failing section never loses edits made to the others.
func (s *ApplicationService) PatchGroup(ctx context.Context, cmd port.PatchGroupCommand) error {
	existing, err := s.adminStorage.GetApplicationGroupByID(ctx, cmd.TenantID, cmd.ID)
	if err != nil {
		return fmt.Errorf("failed locating group: %w", err)
	}

	// System groups only accept sign-in changes, and only the admin group gets them (see UpdateGroup).
	if existing.IsSystem && cmd.Section != port.GroupSectionSignIn {
		return port.ErrSystemManaged
	}

	update := updateCommandFromGroup(existing)
	if err := overlayGroupSection(&update, cmd); err != nil {
		return err
	}
	return s.UpdateGroup(ctx, update)
}

// updateCommandFromGroup turns the stored group into a full update command.
func updateCommandFromGroup(g *model.ApplicationGroup) port.UpdateGroupCommand {
	enabled := g.IsEnabled
	return port.UpdateGroupCommand{
		TenantID:               g.TenantID,
		ID:                     g.ID,
		GroupName:              g.GroupName,
		IsEnabled:              &enabled,
		DefaultRedirectURI:     g.RedirectURI,
		RedirectURIs:           g.RedirectURIs,
		PostLogoutRedirectURIs: g.PostLogoutRedirectURIs,
		FrontChannelLogoutURI:  g.FrontChannelLogoutURI,
		BackChannelLogoutURI:   g.BackChannelLogoutURI,
		AllowedScopes:          g.AllowedScopes,
		DefaultScopes:          g.DefaultScopes,
		AllowedAudiences:       g.AllowedAudiences,
		AllowedIDPIDs:          g.AllowedIDPIDs,
		DefaultIDPID:           g.DefaultIDPID,
	}
}

// overlayGroupSection copies the fields of one section from the patch onto the full update command.
func overlayGroupSection(update *port.UpdateGroupCommand, cmd port.PatchGroupCommand) error {
	switch cmd.Section {
	case port.GroupSectionGeneral:
		update.GroupName = cmd.GroupName
		update.IsEnabled = &cmd.IsEnabled
	case port.GroupSectionRedirects:
		update.RedirectURIs = cmd.RedirectURIs
		update.DefaultRedirectURI = cmd.DefaultRedirectURI
	case port.GroupSectionLogout:
		update.PostLogoutRedirectURIs = cmd.PostLogoutRedirectURIs
		update.FrontChannelLogoutURI = cmd.FrontChannelLogoutURI
		update.BackChannelLogoutURI = cmd.BackChannelLogoutURI
	case port.GroupSectionScopes:
		update.AllowedScopes = cmd.AllowedScopes
		update.DefaultScopes = cmd.DefaultScopes
		update.AllowedAudiences = cmd.AllowedAudiences
	case port.GroupSectionSignIn:
		update.AllowedIDPIDs = cmd.AllowedIDPIDs
		update.DefaultIDPID = cmd.DefaultIDPID
	default:
		verr := port.NewValidationError()
		verr.Add("section", "unknown group section")
		return verr
	}
	return nil
}

// PatchProfile saves one section of a security profile with the same semantics as PatchGroup.
func (s *ApplicationService) PatchProfile(ctx context.Context, cmd port.PatchProfileCommand) error {
	existing, err := s.adminStorage.GetApplicationProfileByID(ctx, cmd.TenantID, cmd.ID)
	if err != nil {
		return fmt.Errorf("failed locating profile: %w", err)
	}
	if existing.IsSystem {
		return port.ErrSystemManaged
	}

	update := updateCommandFromProfile(existing)
	if err := overlayProfileSection(&update, cmd); err != nil {
		return err
	}
	return s.UpdateProfile(ctx, update)
}

func updateCommandFromProfile(p *model.ApplicationProfile) port.UpdateProfileCommand {
	enabled := p.IsEnabled
	return port.UpdateProfileCommand{
		TenantID:                p.TenantID,
		ID:                      p.ID,
		ProfileName:             p.ProfileName,
		IsEnabled:               &enabled,
		TokenEndpointAuthMethod: p.TokenEndpointAuthMethod,
		GrantTypes:              p.GrantTypes,
		ResponseTypes:           p.ResponseTypes,
		AccessTokenLifetime:     p.AccessTokenLifetime,
		RefreshTokenLifetime:    p.RefreshTokenLifetime,
		IDTokenLifetime:         p.IDTokenLifetime,
		EnforceRTR:              p.EnforceRTR,
		SigningAlgorithm:        p.SigningAlgorithm,
	}
}

func overlayProfileSection(update *port.UpdateProfileCommand, cmd port.PatchProfileCommand) error {
	switch cmd.Section {
	case port.ProfileSectionGeneral:
		update.ProfileName = cmd.ProfileName
		update.IsEnabled = &cmd.IsEnabled
	case port.ProfileSectionAuthentication:
		update.TokenEndpointAuthMethod = cmd.TokenEndpointAuthMethod
		update.SigningAlgorithm = cmd.SigningAlgorithm
		update.GrantTypes = cmd.GrantTypes
		update.EnforceRTR = cmd.EnforceRTR
	case port.ProfileSectionLifetimes:
		update.AccessTokenLifetime = cmd.AccessTokenLifetime
		update.RefreshTokenLifetime = cmd.RefreshTokenLifetime
		update.IDTokenLifetime = cmd.IDTokenLifetime
	default:
		verr := port.NewValidationError()
		verr.Add("section", "unknown profile section")
		return verr
	}
	return nil
}
