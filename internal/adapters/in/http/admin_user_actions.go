package http

import (
	"net/http"

	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// unlock clears a lockout and reloads the page so the notice disappears.
func (h *AdminUserHandler) unlock(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	partition, id, ok := h.target(w, r)
	if !ok {
		return
	}
	if err := h.adminUserUseCase.UnlockUser(r.Context(), tenant.ID, partition, id); err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	props, err := h.loadPage(r, tenant, partition, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	props.Msg = "Account unlocked."
	h.renderFragment(w, r, http.StatusOK, admin.UserContent(props))
}

// unlink removes one sign-in method and answers with the refreshed list.
func (h *AdminUserHandler) unlink(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	partition, id, ok := h.target(w, r)
	if !ok {
		return
	}
	idp, err := uuid.Parse(chi.URLParam(r, "idp"))
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, port.ErrIdentityNotFound.Error())
		return
	}

	unlinkErr := h.adminUserUseCase.UnlinkIdentity(r.Context(), port.UnlinkIdentityCommand{
		TenantID: tenant.ID, PartitionID: partition, UserID: id, IdentityProviderID: idp,
	})
	props, err := h.loadPage(r, tenant, partition, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	result, status := sectionResultFor(unlinkErr)
	props.Sections["links"] = result
	h.renderFragment(w, r, status, admin.UserLinksCard(props, result.Error))
}

// delete removes a user after the admin typed the username. The service refuses the administrator's own account
// and the last administrator.
func (h *AdminUserHandler) delete(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	partition, id, ok := h.target(w, r)
	if !ok {
		return
	}
	if err := parseBodyForm(r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}
	props, err := h.loadPage(r, tenant, partition, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	cmd := port.DeleteUserCommand{TenantID: tenant.ID, PartitionID: partition, ID: id, Confirmation: r.FormValue("confirmation")}
	if session, ok := AdminSessionFromContext(r.Context()); ok {
		cmd.ActingUserID = session.UserID
	}
	if err := h.adminUserUseCase.DeleteUser(r.Context(), cmd); err != nil {
		h.renderUserDeleteError(w, r, props, err)
		return
	}
	redirectTo(w, r, flashURL(port.RouteAdmin+port.RouteAdminUsers, "User deleted"))
}

func (h *AdminUserHandler) renderUserDeleteError(w http.ResponseWriter, r *http.Request, props admin.UserPageProps, err error) {
	result, _ := sectionResultFor(err)
	message := result.Error
	if msg, ok := result.Errors["confirmation"]; ok {
		message = msg
	}
	del := admin.UserDeleteProps(props)
	del.Error = message
	h.renderFragment(w, r, http.StatusUnprocessableEntity, admin.ConfirmDelete(del))
}
