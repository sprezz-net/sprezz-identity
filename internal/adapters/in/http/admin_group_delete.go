package http

import (
	"net/http"

	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"
)

// delete removes a group after the admin typed its name. The service refuses system groups and groups in use.
func (h *AdminGroupHandler) delete(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id, ok := h.groupID(w, r)
	if !ok {
		return
	}
	if err := parseBodyForm(r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}

	props, err := h.loadGroupPage(r, tenant, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	// The typed name is checked here because the group service has no confirmation concept of its own.
	if r.FormValue("confirmation") != props.Group.GroupName {
		h.renderDeleteError(w, r, props, "Type the group name exactly to confirm.")
		return
	}
	if err := h.adminApplicationUseCase.DeleteGroup(r.Context(), tenant.ID, id); err != nil {
		_, message := adminErrorStatus(err)
		h.renderDeleteError(w, r, props, message)
		return
	}
	redirectTo(w, r, flashURL(applicationsBase()+port.RouteAdminApplicationsGroups, "Group deleted"))
}

func (h *AdminGroupHandler) renderDeleteError(w http.ResponseWriter, r *http.Request, props admin.GroupPageProps, message string) {
	del := admin.GroupDeleteProps(props)
	del.Error = message
	h.renderFragment(w, r, http.StatusUnprocessableEntity, admin.ConfirmDelete(del))
}
