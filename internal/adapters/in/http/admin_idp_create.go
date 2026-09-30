package http

import (
	"net/http"
	"strconv"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"

	"github.com/google/uuid"
)

func idpPageURL(id uuid.UUID) string {
	return port.RouteAdmin + port.RouteAdminIdentityProviders + "/" + id.String()
}

// newForm shows the type picker, or the short form once a type is chosen.
func (h *AdminIDPHandler) newForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	partitions, err := h.storagePort.GetPartitions(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	idpType := r.URL.Query().Get("type")
	if idpType != model.OpenIDConnectIDPType && idpType != model.UsernamePasswordIDPType {
		idpType = ""
	}
	props := admin.IDPNewProps{ActiveTenant: *tenant, Partitions: partitions, Type: idpType, Errors: map[string]string{}, Values: map[string]string{}}
	h.renderAdminPage(w, r, admin.NewIDPContent(props), admin.NewIDPPage(props))
}

// create adds a provider with its essentials, then continues on its own page for everything else.
func (h *AdminIDPHandler) create(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}
	partitionID, _ := strconv.ParseInt(r.FormValue("partition_id"), 10, 64)
	provider := model.IdentityProvider{
		IDPType: r.FormValue("idp_type"), Enabled: true, PartitionID: partitionID,
		Alias: strings.TrimSpace(r.FormValue("alias")), Name: strings.TrimSpace(r.FormValue("name")),
		Config: model.IdentityProviderConfig{
			DiscoveryEndpoint:    strings.TrimSpace(r.FormValue("discovery_endpoint")),
			ClientID:             strings.TrimSpace(r.FormValue("client_id")),
			ClientSecret:         r.FormValue("client_secret"),
			AuthenticationMethod: "client_secret_basic",
			Scopes:               []string{"openid", "profile", "email"},
		},
	}

	created, err := h.idpService.CreateIdentityProvider(r.Context(), tenant.ID, provider)
	if err != nil {
		h.renderCreateErrors(w, r, tenant, provider, err)
		return
	}
	redirectTo(w, r, flashURL(idpPageURL(created.ID), "Provider added. Review its settings below."))
}

func (h *AdminIDPHandler) renderCreateErrors(w http.ResponseWriter, r *http.Request, tenant *model.Tenant, p model.IdentityProvider, err error) {
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
	// Secrets are never echoed back into the form.
	props := admin.IDPNewProps{
		ActiveTenant: *tenant, Partitions: partitions, Type: p.IDPType, Errors: errs,
		Values: map[string]string{
			"name": p.Name, "alias": p.Alias, "partition_id": strconv.FormatInt(p.PartitionID, 10),
			"discovery_endpoint": p.Config.DiscoveryEndpoint, "client_id": p.Config.ClientID,
		},
	}
	h.renderFragment(w, r, http.StatusUnprocessableEntity, admin.NewIDPContent(props))
}
