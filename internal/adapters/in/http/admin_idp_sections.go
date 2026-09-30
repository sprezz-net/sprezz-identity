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

// saveSection saves one card and answers with that card only. Other cards on the page are untouched.
func (h *AdminIDPHandler) saveSection(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id, ok := h.idpID(w, r)
	if !ok {
		return
	}
	section, known := idpSections[chi.URLParam(r, "section")]
	if !known {
		h.renderError(w, r, http.StatusNotFound, "unknown section")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}

	parseErrs := map[string]string{}
	cmd := idpPatchFromForm(r, section, parseErrs)
	cmd.TenantID, cmd.ID = tenant.ID, id

	var saveErr error
	if len(parseErrs) == 0 {
		saveErr = h.idpService.PatchIdentityProvider(r.Context(), cmd)
	}
	h.renderIDPSection(w, r, tenant, id, section, parseErrs, saveErr)
}

func (h *AdminIDPHandler) renderIDPSection(w http.ResponseWriter, r *http.Request, tenant *model.Tenant, id uuid.UUID, section port.IdentityProviderSection, parseErrs map[string]string, saveErr error) {
	props, err := h.loadPage(r, tenant, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	result, status := sectionResultFor(saveErr)
	if len(parseErrs) > 0 {
		result, status = admin.SectionResult{Errors: parseErrs}, http.StatusUnprocessableEntity
	}
	props.Sections[string(section)] = result
	h.renderFragment(w, r, status, idpCard(section, props))
}

// idpCard picks the card component for a section.
func idpCard(section port.IdentityProviderSection, props admin.IDPPageProps) templ.Component {
	p, result := props.Provider, props.Section(string(section))
	switch section {
	case port.IDPSectionConnection:
		return admin.IDPConnectionCard(p, result)
	case port.IDPSectionCredentials:
		return admin.IDPCredentialsCard(p, result)
	case port.IDPSectionBehavior:
		return admin.IDPBehaviorCard(p, result)
	case port.IDPSectionAssurance:
		return admin.IDPAssuranceCard(p, result)
	case port.IDPSectionLocalPolicy:
		return admin.IDPLocalPolicyCard(p, result)
	default:
		return admin.IDPGeneralCard(p, props.PartitionName, result)
	}
}

// delete removes a provider after the admin typed its alias. The service refuses system providers and providers
// that a group still allows.
func (h *AdminIDPHandler) delete(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id, ok := h.idpID(w, r)
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
	if r.FormValue("confirmation") != props.Provider.Alias {
		h.renderIDPDeleteError(w, r, props, "Type the provider alias exactly to confirm.")
		return
	}
	if err := h.idpService.DeleteIdentityProvider(r.Context(), tenant.ID, id); err != nil {
		_, message := adminErrorStatus(err)
		h.renderIDPDeleteError(w, r, props, message)
		return
	}
	redirectTo(w, r, flashURL(port.RouteAdmin+port.RouteAdminIdentityProviders, "Provider deleted"))
}

func (h *AdminIDPHandler) renderIDPDeleteError(w http.ResponseWriter, r *http.Request, props admin.IDPPageProps, message string) {
	del := admin.IDPDeleteProps(props)
	del.Error = message
	h.renderFragment(w, r, http.StatusUnprocessableEntity, admin.ConfirmDelete(del))
}
