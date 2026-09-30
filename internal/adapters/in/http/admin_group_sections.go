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

// groupSections maps the URL segment of a section to its domain section.
var groupSections = map[string]port.GroupSection{
	"general":   port.GroupSectionGeneral,
	"redirects": port.GroupSectionRedirects,
	"logout":    port.GroupSectionLogout,
	"scopes":    port.GroupSectionScopes,
	"signin":    port.GroupSectionSignIn,
}

// patchFromForm reads only the fields that belong to the section from the submitted form.
func patchFromForm(r *http.Request, section port.GroupSection, errs map[string]string) port.PatchGroupCommand {
	cmd := port.PatchGroupCommand{Section: section}
	form := r.Form

	switch section {
	case port.GroupSectionGeneral:
		cmd.GroupName = strings.TrimSpace(r.FormValue("group_name"))
		cmd.IsEnabled = r.FormValue("is_enabled") == "true"
	case port.GroupSectionRedirects:
		cmd.RedirectURIs = CleanBoundaryStringSlice(parseFormStringSlice(form, "redirect_uris"))
		cmd.DefaultRedirectURI = strings.TrimSpace(r.FormValue("default_redirect_uri"))
	case port.GroupSectionLogout:
		cmd.PostLogoutRedirectURIs = CleanBoundaryStringSlice(parseFormStringSlice(form, "post_logout_redirect_uris"))
		cmd.FrontChannelLogoutURI = strings.TrimSpace(r.FormValue("front_channel_logout_uri"))
		cmd.BackChannelLogoutURI = strings.TrimSpace(r.FormValue("back_channel_logout_uri"))
	case port.GroupSectionScopes:
		cmd.AllowedScopes = CleanBoundaryStringSlice(parseFormStringSlice(form, "allowed_scopes"))
		cmd.DefaultScopes = CleanBoundaryStringSlice(parseFormStringSlice(form, "default_scopes"))
		cmd.AllowedAudiences = CleanBoundaryStringSlice(parseFormStringSlice(form, "allowed_audiences"))
	case port.GroupSectionSignIn:
		cmd.AllowedIDPIDs = parseUUIDList(form["allowed_idps"], "allowed_idps", errs)
		cmd.DefaultIDPID = parseOptionalUUID(r.FormValue("default_idp_id"), "default_idp_id", errs)
	}
	return cmd
}

// applyGroupEdits overlays submitted-but-unsaved values onto the group so a failed card keeps what was typed.
func applyGroupEdits(group *model.ApplicationGroup, cmd port.PatchGroupCommand) {
	switch cmd.Section {
	case port.GroupSectionGeneral:
		group.GroupName, group.IsEnabled = cmd.GroupName, cmd.IsEnabled
	case port.GroupSectionRedirects:
		group.RedirectURIs, group.RedirectURI = cmd.RedirectURIs, cmd.DefaultRedirectURI
	case port.GroupSectionLogout:
		group.PostLogoutRedirectURIs = cmd.PostLogoutRedirectURIs
		group.FrontChannelLogoutURI, group.BackChannelLogoutURI = cmd.FrontChannelLogoutURI, cmd.BackChannelLogoutURI
	case port.GroupSectionScopes:
		group.AllowedScopes, group.DefaultScopes, group.AllowedAudiences = cmd.AllowedScopes, cmd.DefaultScopes, cmd.AllowedAudiences
	case port.GroupSectionSignIn:
		group.AllowedIDPIDs, group.DefaultIDPID = cmd.AllowedIDPIDs, cmd.DefaultIDPID
	}
}

// saveSection saves one card and answers with that card only. Other cards on the page are untouched.
func (h *AdminGroupHandler) saveSection(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id, ok := h.groupID(w, r)
	if !ok {
		return
	}
	section, known := groupSections[chi.URLParam(r, "section")]
	if !known {
		h.renderError(w, r, http.StatusNotFound, "unknown section")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}

	parseErrs := map[string]string{}
	cmd := patchFromForm(r, section, parseErrs)
	cmd.TenantID, cmd.ID = tenant.ID, id

	var saveErr error
	if len(parseErrs) == 0 {
		saveErr = h.adminApplicationUseCase.PatchGroup(r.Context(), cmd)
	}
	h.renderGroupSection(w, r, tenant, id, cmd, parseErrs, saveErr)
}

func (h *AdminGroupHandler) renderGroupSection(w http.ResponseWriter, r *http.Request, tenant *model.Tenant, id uuid.UUID, cmd port.PatchGroupCommand, parseErrs map[string]string, saveErr error) {
	props, err := h.loadGroupPage(r, tenant, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	result, status := sectionResultFor(saveErr)
	if len(parseErrs) > 0 {
		result, status = admin.SectionResult{Errors: parseErrs}, http.StatusUnprocessableEntity
	}
	if status != http.StatusOK {
		applyGroupEdits(props.Group, cmd)
	}
	props.Sections[string(cmd.Section)] = result
	h.renderFragment(w, r, status, groupCard(cmd.Section, props))
}

// groupCard picks the card component for a section.
func groupCard(section port.GroupSection, props admin.GroupPageProps) templ.Component {
	name := string(section)
	switch section {
	case port.GroupSectionGeneral:
		return admin.GroupGeneralCard(props.Group, props.Section(name))
	case port.GroupSectionRedirects:
		return admin.GroupRedirectsCard(props.Group, props.Section(name))
	case port.GroupSectionLogout:
		return admin.GroupLogoutCard(props.Group, props.Section(name))
	case port.GroupSectionScopes:
		return admin.GroupScopesCard(props.Group, props.Section(name))
	default:
		return admin.SignInCard(admin.SignInCardProps{
			Group:         props.Group,
			Partitions:    props.Partitions,
			Result:        props.Section(name),
			FederatedOnly: props.Group.IsSystem,
		})
	}
}
