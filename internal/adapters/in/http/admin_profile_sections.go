package http

import (
	"net/http"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

var profileSections = map[string]port.ProfileSection{
	"general":        port.ProfileSectionGeneral,
	"authentication": port.ProfileSectionAuthentication,
	"lifetimes":      port.ProfileSectionLifetimes,
}

// profilePatchFromForm reads only the fields that belong to the section from the submitted form.
func profilePatchFromForm(r *http.Request, section port.ProfileSection, errs map[string]string) port.PatchProfileCommand {
	cmd := port.PatchProfileCommand{Section: section}

	switch section {
	case port.ProfileSectionGeneral:
		cmd.ProfileName = strings.TrimSpace(r.FormValue("profile_name"))
		cmd.IsEnabled = r.FormValue("is_enabled") == "true"
	case port.ProfileSectionAuthentication:
		cmd.TokenEndpointAuthMethod = model.TokenEndpointAuthMethod(r.FormValue("token_endpoint_auth_method"))
		cmd.SigningAlgorithm = model.SignatureAlgorithm(r.FormValue("signing_algorithm"))
		cmd.GrantTypes = parseGrantTypes(r.Form["grant_types"])
		cmd.EnforceRTR = r.FormValue("enforce_rtr") == "true"
	case port.ProfileSectionLifetimes:
		cmd.AccessTokenLifetime = parseLifetime(r.FormValue("access_token_lifetime"), "access_token_lifetime", errs)
		cmd.IDTokenLifetime = parseLifetime(r.FormValue("id_token_lifetime"), "id_token_lifetime", errs)
		cmd.RefreshTokenLifetime = parseLifetime(r.FormValue("refresh_token_lifetime"), "refresh_token_lifetime", errs)
	}
	return cmd
}

// applyProfileEdits overlays submitted-but-unsaved values so a failed card keeps what was typed.
func applyProfileEdits(profile *model.ApplicationProfile, cmd port.PatchProfileCommand) {
	switch cmd.Section {
	case port.ProfileSectionGeneral:
		profile.ProfileName, profile.IsEnabled = cmd.ProfileName, cmd.IsEnabled
	case port.ProfileSectionAuthentication:
		profile.TokenEndpointAuthMethod, profile.SigningAlgorithm = cmd.TokenEndpointAuthMethod, cmd.SigningAlgorithm
		profile.GrantTypes, profile.EnforceRTR = cmd.GrantTypes, cmd.EnforceRTR
	case port.ProfileSectionLifetimes:
		profile.AccessTokenLifetime, profile.IDTokenLifetime, profile.RefreshTokenLifetime = cmd.AccessTokenLifetime, cmd.IDTokenLifetime, cmd.RefreshTokenLifetime
	}
}

// saveSection saves one card and answers with that card only.
func (h *AdminProfileHandler) saveSection(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id, ok := h.profileID(w, r)
	if !ok {
		return
	}
	section, known := profileSections[chi.URLParam(r, "section")]
	if !known {
		h.renderError(w, r, http.StatusNotFound, "unknown section")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}

	parseErrs := map[string]string{}
	cmd := profilePatchFromForm(r, section, parseErrs)
	cmd.TenantID, cmd.ID = tenant.ID, id

	var saveErr error
	if len(parseErrs) == 0 {
		saveErr = h.adminApplicationUseCase.PatchProfile(r.Context(), cmd)
	}
	h.renderProfileSection(w, r, tenant, id, cmd, parseErrs, saveErr)
}

func (h *AdminProfileHandler) renderProfileSection(w http.ResponseWriter, r *http.Request, tenant *model.Tenant, id uuid.UUID, cmd port.PatchProfileCommand, parseErrs map[string]string, saveErr error) {
	props, err := h.loadProfilePage(r, tenant, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	result, status := sectionResultFor(saveErr)
	if len(parseErrs) > 0 {
		result, status = admin.SectionResult{Errors: parseErrs}, http.StatusUnprocessableEntity
	}
	if status != http.StatusOK {
		applyProfileEdits(props.Profile, cmd)
	}
	props.Sections[string(cmd.Section)] = result
	h.renderFragment(w, r, status, profileCard(cmd.Section, props))
}

func profileCard(section port.ProfileSection, props admin.ProfilePageProps) templ.Component {
	name := string(section)
	readOnly := props.Profile.IsSystem
	switch section {
	case port.ProfileSectionGeneral:
		return admin.ProfileGeneralCard(props.Profile, props.Section(name), readOnly)
	case port.ProfileSectionAuthentication:
		return admin.ProfileAuthCard(props.Profile, props.Section(name), readOnly)
	default:
		return admin.ProfileLifetimesCard(props.Profile, props.Section(name), readOnly)
	}
}

// delete removes a profile after the admin typed its name. The service refuses system profiles and profiles in use.
func (h *AdminProfileHandler) delete(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id, ok := h.profileID(w, r)
	if !ok {
		return
	}
	if err := parseBodyForm(r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}

	props, err := h.loadProfilePage(r, tenant, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	if r.FormValue("confirmation") != props.Profile.ProfileName {
		h.renderProfileDeleteError(w, r, props, "Type the profile name exactly to confirm.")
		return
	}
	if err := h.adminApplicationUseCase.DeleteProfile(r.Context(), tenant.ID, id); err != nil {
		_, message := adminErrorStatus(err)
		h.renderProfileDeleteError(w, r, props, message)
		return
	}
	redirectTo(w, r, flashURL(profilesBase(), "Profile deleted"))
}

func (h *AdminProfileHandler) renderProfileDeleteError(w http.ResponseWriter, r *http.Request, props admin.ProfilePageProps, message string) {
	del := admin.ProfileDeleteProps(props)
	del.Error = message
	h.renderFragment(w, r, http.StatusUnprocessableEntity, admin.ConfirmDelete(del))
}
