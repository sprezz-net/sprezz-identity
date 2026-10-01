package http

import (
	"net/http"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"
)

func (h *AdminTenantHandler) newForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	if !tenant.IsSystem {
		h.renderDomainError(w, r, port.ErrForbidden)
		return
	}
	props := admin.TenantNewProps{ActiveTenant: *tenant, Errors: map[string]string{}, Values: map[string]string{}}
	h.renderAdminPage(w, r, admin.NewTenantContent(props), admin.NewTenantPage(props))
}

// create adds a tenant, then continues on the new tenant's page.
func (h *AdminTenantHandler) create(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}
	cmd := port.CreateTenantFromConsoleCommand{ActingTenant: tenant.ID, Name: r.FormValue("name"), Domain: r.FormValue("domain")}

	created, err := h.adminTenantUseCase.CreateTenant(r.Context(), cmd)
	if err != nil {
		h.renderCreateTenantErrors(w, r, tenant, cmd, err)
		return
	}
	redirectTo(w, r, flashURL(tenantURLFor(created), "Tenant added. Review its settings below."))
}

func tenantURLFor(t *model.Tenant) string {
	return port.RouteAdmin + port.RouteAdminTenants + "/" + t.ID.String()
}

func (h *AdminTenantHandler) renderCreateTenantErrors(w http.ResponseWriter, r *http.Request, tenant *model.Tenant, cmd port.CreateTenantFromConsoleCommand, err error) {
	errs := map[string]string{}
	mergeFieldErrors(err, errs)
	if len(errs) == 0 {
		h.renderDomainError(w, r, err)
		return
	}
	props := admin.TenantNewProps{
		ActiveTenant: *tenant, Errors: errs, Values: map[string]string{"name": cmd.Name, "domain": cmd.Domain},
	}
	h.renderFragment(w, r, http.StatusUnprocessableEntity, admin.NewTenantContent(props))
}
