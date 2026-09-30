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

func applicationURL(clientID string) string {
	return applicationsBase() + "/" + clientID
}

func (h *AdminApplicationHandler) loadApplicationPage(r *http.Request, tenant *model.Tenant, clientID string) (admin.ApplicationPageProps, error) {
	details, err := h.adminApplicationUseCase.GetApplication(r.Context(), tenant.ID, clientID)
	if err != nil {
		return admin.ApplicationPageProps{}, err
	}
	profiles, err := h.adminApplicationUseCase.GetProfiles(r.Context(), tenant.ID)
	if err != nil {
		return admin.ApplicationPageProps{}, err
	}
	groups, err := h.adminApplicationUseCase.GetGroups(r.Context(), tenant.ID)
	if err != nil {
		return admin.ApplicationPageProps{}, err
	}
	return admin.ApplicationPageProps{
		ActiveTenant: *tenant,
		Application:  details.Application,
		Profile:      details.ApplicationProfile,
		Group:        details.ApplicationGroup,
		Profiles:     profiles,
		Groups:       groups,
		Msg:          r.URL.Query().Get("msg"),
		Sections:     map[string]admin.SectionResult{},
	}, nil
}

func (h *AdminApplicationHandler) detail(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	props, err := h.loadApplicationPage(r, tenant, chi.URLParam(r, "clientID"))
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	h.renderAdminPage(w, r, admin.ApplicationContent(props), admin.ApplicationPage(props))
}

// saveSection saves one card of an application and answers with that card only.
func (h *AdminApplicationHandler) saveSection(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clientID, section := chi.URLParam(r, "clientID"), chi.URLParam(r, "section")
	if section != "general" && section != "policy" {
		h.renderError(w, r, http.StatusNotFound, "unknown section")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}

	props, err := h.loadApplicationPage(r, tenant, clientID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	errs := map[string]string{}
	cmd := h.applicationCommand(r, props, section, errs)
	var saveErr error
	if len(errs) == 0 {
		saveErr = h.adminApplicationUseCase.UpdateApplication(r.Context(), cmd)
	}

	result, status := sectionResultFor(saveErr)
	if len(errs) > 0 {
		result, status = admin.SectionResult{Errors: errs}, http.StatusUnprocessableEntity
	}
	if status == http.StatusOK {
		// Re-read so the page shows the stored state, including the new group or profile link targets.
		if fresh, loadErr := h.loadApplicationPage(r, tenant, clientID); loadErr == nil {
			props = fresh
		}
	} else {
		applyApplicationEdits(props.Application, cmd, section)
	}
	props.Sections[section] = result
	h.renderFragment(w, r, status, applicationCard(section, props))
}

// applicationCommand builds the update command: the submitted section is overlaid on the stored application.
func (h *AdminApplicationHandler) applicationCommand(r *http.Request, props admin.ApplicationPageProps, section string, errs map[string]string) port.UpdateApplicationCommand {
	app := props.Application
	enabled := app.IsEnabled
	cmd := port.UpdateApplicationCommand{
		TenantID:        props.ActiveTenant.ID,
		ClientID:        app.ClientID,
		ApplicationName: app.ApplicationName,
		ProfileID:       app.ProfileID,
		GroupID:         app.GroupID,
		IsEnabled:       &enabled,
	}

	switch section {
	case "general":
		cmd.ApplicationName = strings.TrimSpace(r.FormValue("application_name"))
		submitted := r.FormValue("is_enabled") == "true"
		cmd.IsEnabled = &submitted
		if cmd.ApplicationName == "" {
			errs["application_name"] = "an application name is required"
		}
	case "policy":
		cmd.GroupID = requiredUUID(r.FormValue("group_id"), "group_id", "choose a group", errs, cmd.GroupID)
		cmd.ProfileID = requiredUUID(r.FormValue("profile_id"), "profile_id", "choose a profile", errs, cmd.ProfileID)
	}
	return cmd
}

func requiredUUID(raw, field, message string, errs map[string]string, fallback uuid.UUID) uuid.UUID {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		errs[field] = message
		return fallback
	}
	return id
}

func applyApplicationEdits(app *model.Application, cmd port.UpdateApplicationCommand, section string) {
	switch section {
	case "general":
		app.ApplicationName = cmd.ApplicationName
		if cmd.IsEnabled != nil {
			app.IsEnabled = *cmd.IsEnabled
		}
	case "policy":
		app.GroupID, app.ProfileID = cmd.GroupID, cmd.ProfileID
	}
}

func applicationCard(section string, props admin.ApplicationPageProps) templ.Component {
	if section == "policy" {
		return admin.ApplicationPolicyCard(props, props.Section(section))
	}
	return admin.ApplicationGeneralCard(props, props.Section(section))
}
