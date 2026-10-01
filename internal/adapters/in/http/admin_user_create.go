package http

import (
	"net/http"
	"strconv"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"
)

func userPageURL(u *model.UserProfile) string {
	return port.RouteAdmin + port.RouteAdminUsers + "/" + strconv.FormatInt(u.PartitionID, 10) + "/" + u.ID.String()
}

func (h *AdminUserHandler) newForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	partitions, err := h.storagePort.GetPartitions(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	props := admin.UserNewProps{ActiveTenant: *tenant, Partitions: partitions, Errors: map[string]string{}, Values: map[string]string{}}
	h.renderAdminPage(w, r, admin.NewUserContent(props), admin.NewUserPage(props))
}

// create adds a user, then continues on the new user's page.
func (h *AdminUserHandler) create(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}
	partitionID, _ := strconv.ParseInt(r.FormValue("partition_id"), 10, 64)
	cmd := port.CreateUserCommand{
		TenantID: tenant.ID, PartitionID: partitionID,
		Username: r.FormValue("username"), FirstName: r.FormValue("first_name"), LastName: r.FormValue("last_name"),
		Email: r.FormValue("email"), EmailVerified: r.FormValue("email_verified") == "true", Password: r.FormValue("password"),
	}

	created, err := h.adminUserUseCase.CreateUser(r.Context(), cmd)
	if err != nil {
		h.renderCreateUserErrors(w, r, tenant, cmd, err)
		return
	}
	redirectTo(w, r, flashURL(userPageURL(created), "User added."))
}

func (h *AdminUserHandler) renderCreateUserErrors(w http.ResponseWriter, r *http.Request, tenant *model.Tenant, cmd port.CreateUserCommand, err error) {
	errs := map[string]string{}
	mergeFieldErrors(err, errs)
	if len(errs) == 0 {
		h.renderDomainError(w, r, err)
		return
	}
	partitions, perr := h.storagePort.GetPartitions(r.Context(), tenant.ID)
	if perr != nil {
		h.renderDomainError(w, r, perr)
		return
	}
	// The password is never echoed back into the form.
	props := admin.UserNewProps{
		ActiveTenant: *tenant, Partitions: partitions, Errors: errs,
		Values: map[string]string{
			"partition_id": strconv.FormatInt(cmd.PartitionID, 10), "username": cmd.Username, "first_name": cmd.FirstName,
			"last_name": cmd.LastName, "email": cmd.Email, "email_verified": strconv.FormatBool(cmd.EmailVerified),
		},
	}
	h.renderFragment(w, r, http.StatusUnprocessableEntity, admin.NewUserContent(props))
}
