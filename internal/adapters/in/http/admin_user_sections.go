package http

import (
	"net/http"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// userSections maps the URL segment of a section to its domain section.
var userSections = map[string]port.UserSection{
	"profile":  port.UserSectionProfile,
	"status":   port.UserSectionStatus,
	"password": port.UserSectionPassword,
}

// userPatchFromForm reads only the fields of one section from a submitted form.
func userPatchFromForm(r *http.Request, section port.UserSection) port.PatchUserCommand {
	cmd := port.PatchUserCommand{Section: section}
	switch section {
	case port.UserSectionProfile:
		cmd.Username, cmd.FirstName, cmd.LastName, cmd.Email = r.FormValue("username"), r.FormValue("first_name"), r.FormValue("last_name"), r.FormValue("email")
	case port.UserSectionStatus:
		cmd.Blocked, cmd.EmailVerified = r.FormValue("blocked") == "true", r.FormValue("email_verified") == "true"
		cmd.Lifecycle = model.ProfileLifecycleState(r.FormValue("lifecycle"))
	case port.UserSectionPassword:
		cmd.NewPassword = r.FormValue("new_password")
	}
	return cmd
}

// saveSection saves one card and answers with that card only. Other cards on the page are untouched.
func (h *AdminUserHandler) saveSection(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	partition, id, ok := h.target(w, r)
	if !ok {
		return
	}
	section, known := userSections[chi.URLParam(r, "section")]
	if !known {
		h.renderError(w, r, http.StatusNotFound, "unknown section")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}

	cmd := userPatchFromForm(r, section)
	cmd.TenantID, cmd.PartitionID, cmd.ID = tenant.ID, partition, id
	if session, ok := AdminSessionFromContext(r.Context()); ok {
		cmd.ActingUserID = session.UserID
	}
	saveErr := h.adminUserUseCase.PatchUser(r.Context(), cmd)
	h.renderUserSection(w, r, tenant, partition, id, section, saveErr)
}

func (h *AdminUserHandler) renderUserSection(w http.ResponseWriter, r *http.Request, tenant *model.Tenant, partition int64, id uuid.UUID, section port.UserSection, saveErr error) {
	props, err := h.loadPage(r, tenant, partition, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	result, status := sectionResultFor(saveErr)
	props.Sections[string(section)] = result
	h.renderFragment(w, r, status, userCard(section, props))
}

// userCard picks the card component for a section.
func userCard(section port.UserSection, props admin.UserPageProps) templ.Component {
	result := props.Section(string(section))
	switch section {
	case port.UserSectionStatus:
		return admin.UserStatusCard(props, result)
	case port.UserSectionPassword:
		return admin.UserPasswordCard(props, result)
	default:
		return admin.UserProfileCard(props.Detail.User, result)
	}
}
