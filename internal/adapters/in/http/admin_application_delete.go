package http

import (
	"net/http"

	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"

	"github.com/go-chi/chi/v5"
)

// delete removes an application after the admin typed its client ID. System applications are refused by the service.
func (h *AdminApplicationHandler) delete(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clientID := chi.URLParam(r, "clientID")
	if err := parseBodyForm(r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}

	props, err := h.loadApplicationPage(r, tenant, clientID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	if r.FormValue("confirmation") != clientID {
		h.renderApplicationDeleteError(w, r, clientID, "Type the client ID exactly to confirm.")
		return
	}
	if err := h.adminApplicationUseCase.DeleteApplication(r.Context(), props.ActiveTenant.ID, clientID); err != nil {
		_, message := adminErrorStatus(err)
		h.renderApplicationDeleteError(w, r, clientID, message)
		return
	}
	redirectTo(w, r, flashURL(applicationsBase(), "Application deleted"))
}

func (h *AdminApplicationHandler) renderApplicationDeleteError(w http.ResponseWriter, r *http.Request, clientID, message string) {
	h.renderFragment(w, r, http.StatusUnprocessableEntity, admin.ConfirmDelete(admin.ConfirmDeleteProps{
		Action:   applicationURL(clientID),
		Expected: clientID,
		Noun:     "application",
		Warning:  "Deleting an application signs out its users and cannot be undone.",
		Error:    message,
	}))
}

var _ = port.ErrSystemManaged
