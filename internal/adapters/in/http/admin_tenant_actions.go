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

// tenantSections maps the URL segment of a section to its domain section.
var tenantSections = map[string]port.TenantSection{
	"general":   port.TenantSectionGeneral,
	"signup":    port.TenantSectionSignup,
	"redirects": port.TenantSectionRedirects,
	"scopes":    port.TenantSectionScopes,
}

// tenantPatchFromForm reads only the fields of one section from a submitted form.
func tenantPatchFromForm(r *http.Request, section port.TenantSection) port.PatchTenantCommand {
	cmd := port.PatchTenantCommand{Section: section}
	switch section {
	case port.TenantSectionGeneral:
		cmd.Name, cmd.Domain = r.FormValue("name"), r.FormValue("domain")
	case port.TenantSectionSignup:
		cmd.AllowSignup = r.FormValue("allow_signup") == "true"
	case port.TenantSectionRedirects:
		cmd.RedirectWhitelist = CleanBoundaryStringSlice(parseFormStringSlice(r.Form, "redirect_uris"))
		cmd.DefaultRedirectURI = strings.TrimSpace(r.FormValue("default_redirect_uri"))
	case port.TenantSectionScopes:
		cmd.PredefinedScopes = strings.Fields(r.FormValue("predefined_scopes_text"))
		cmd.PredefinedAudiences = CleanBoundaryStringSlice(parseFormStringSlice(r.Form, "predefined_audiences"))
	}
	return cmd
}

// saveSection saves one card and answers with that card only. Other cards on the page are untouched.
func (h *AdminTenantHandler) saveSection(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	section, known := tenantSections[chi.URLParam(r, "section")]
	if !known {
		h.renderError(w, r, http.StatusNotFound, "unknown section")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}

	cmd := tenantPatchFromForm(r, section)
	cmd.TenantID, cmd.ActingTenant = id, tenant.ID
	saveErr := h.adminTenantUseCase.PatchTenant(r.Context(), cmd)
	h.renderTenantSection(w, r, tenant, id, section, saveErr)
}

func (h *AdminTenantHandler) renderTenantSection(w http.ResponseWriter, r *http.Request, tenant *model.Tenant, id uuid.UUID, section port.TenantSection, saveErr error) {
	props, err := h.loadPage(r, tenant, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	result, status := sectionResultFor(saveErr)
	props.Sections[string(section)] = result
	h.renderFragment(w, r, status, tenantCard(section, props))
}

// tenantCard picks the card component for a section.
func tenantCard(section port.TenantSection, props admin.TenantPageProps) templ.Component {
	t, result := props.Detail.Tenant, props.Section(string(section))
	switch section {
	case port.TenantSectionSignup:
		return admin.TenantSignupCard(t, result)
	case port.TenantSectionRedirects:
		return admin.TenantRedirectsCard(t, result)
	case port.TenantSectionScopes:
		return admin.TenantScopesCard(t, result)
	default:
		return admin.TenantGeneralCard(t, result)
	}
}

// delete removes a tenant after the admin typed its domain. The service decides who may do it: only the
// administrative tenant, never a system tenant and never the tenant the session belongs to.
func (h *AdminTenantHandler) delete(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	if err := parseBodyForm(r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}
	props, err := h.loadPage(r, tenant, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	cmd := port.DeleteTenantCommand{TenantID: id, ActingTenantID: tenant.ID, Confirmation: r.FormValue("confirmation")}
	if session, ok := AdminSessionFromContext(r.Context()); ok {
		cmd.ActingUserID = session.UserID.String()
	}
	if err := h.adminTenantUseCase.DeleteTenant(r.Context(), cmd); err != nil {
		h.renderTenantDeleteError(w, r, props, err)
		return
	}
	redirectTo(w, r, flashURL(port.RouteAdmin+port.RouteAdminTenants, "Tenant deleted"))
}

func (h *AdminTenantHandler) renderTenantDeleteError(w http.ResponseWriter, r *http.Request, props admin.TenantPageProps, err error) {
	result, _ := sectionResultFor(err)
	message := result.Error
	if msg, ok := result.Errors["confirmation"]; ok {
		message = msg
	}
	del := admin.TenantDeleteProps(props)
	del.Error = message
	h.renderFragment(w, r, http.StatusUnprocessableEntity, admin.ConfirmDelete(del))
}
