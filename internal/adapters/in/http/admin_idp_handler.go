package http

import (
	"fmt"
	"net/http"
	"strconv"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type AdminIDPHandler struct {
	*HttpAdapter
}

func NewAdminIDPHandler(adapter *HttpAdapter) *AdminIDPHandler {
	return &AdminIDPHandler{HttpAdapter: adapter}
}

func (h *AdminIDPHandler) Routes(r chi.Router) {
	r.Route(port.RouteAdminIdentityProviders, func(r chi.Router) {
		r.Get("/", h.adminIDPsPage)
		r.Get("/discover", h.adminDiscoverIDP)
		r.Get("/new", h.adminNewIDPForm)
		r.Get("/edit", h.adminEditIDPForm)
		r.Post("/", h.adminSaveIDP)
		r.Delete("/{id}", h.adminDeleteIDP)
	})
}

func (h *AdminIDPHandler) adminIDPsPage(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	idps, err := h.idpService.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	var filterPartitionID int64
	if pStr := r.URL.Query().Get("partition_id"); pStr != "" {
		filterPartitionID, _ = strconv.ParseInt(pStr, 10, 64)
	}

	partitions, err := h.storagePort.GetPartitions(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	if filterPartitionID > 0 {
		var filtered []model.IdentityProvider
		for _, idp := range idps {
			if idp.PartitionID == filterPartitionID {
				filtered = append(filtered, idp)
			}
		}
		idps = filtered
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	msg := r.URL.Query().Get("msg")
	props := admin.IDPsPageProps{
		ActiveTenant:      *tenant,
		Providers:         idps,
		Partitions:        partitions,
		FilterPartitionID: filterPartitionID,
		Msg:               msg,
	}
	if r.Header.Get(model.HeaderHXRequest) == "true" {
		_ = admin.IDPsContent(props).Render(r.Context(), w)
	} else {
		_ = admin.IDPsPage(props).Render(r.Context(), w)
	}
}

func (h *AdminIDPHandler) adminNewIDPForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Add Identity Provider", "/admin/idps/new")
		_ = component.Render(r.Context(), w)
		return
	}
	partitions, err := h.storagePort.GetPartitions(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	component := admin.IDPForm(admin.IDPFormProps{
		Partitions: partitions,
		IsEdit:     false,
	})
	_ = component.Render(r.Context(), w)
}

func (h *AdminIDPHandler) adminEditIDPForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	idpIDStr := r.URL.Query().Get("id")
	idpUUID, err := uuid.Parse(idpIDStr)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, errInvalidIDPUUID)
		return
	}

	idp, err := h.storagePort.GetIdentityProviderByUUID(r.Context(), tenant.ID, idpUUID)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, "identity provider not found")
		return
	}

	partitions, err := h.storagePort.GetPartitions(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Edit Identity Provider", fmt.Sprintf("/admin/idps/edit?id=%s", idpIDStr))
		_ = component.Render(r.Context(), w)
		return
	}
	component := admin.IDPForm(admin.IDPFormProps{
		Provider:   *idp,
		Partitions: partitions,
		IsEdit:     true,
	})
	_ = component.Render(r.Context(), w)
}

func (h *AdminIDPHandler) adminDiscoverIDP(w http.ResponseWriter, r *http.Request) {
	urlStr := r.URL.Query().Get("url")
	if urlStr == "" {
		http.Error(w, "OIDC discovery URL is required", http.StatusBadRequest)
		return
	}

	meta, err := h.idpService.DiscoverOIDC(r.Context(), urlStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, http.StatusOK, meta)
}

func (h *AdminIDPHandler) adminSaveIDP(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id := r.FormValue("id")
	alias := r.FormValue("alias")
	name := r.FormValue("name")
	idpType := r.FormValue("idp_type")
	issuer := r.FormValue("issuer")
	enabled := r.FormValue("enabled") == "true"
	partitionIDStr := r.FormValue("partition_id")
	partitionID, _ := strconv.ParseInt(partitionIDStr, 10, 64)

	var errs = make(map[string]string)
	if alias == "" {
		errs["alias"] = "provider alias is required"
	}
	if name == "" {
		errs["name"] = "provider display name is required"
	}
	if idpType == "" {
		errs["idp_type"] = "identity provider type is required"
	}

	var parsedUUID uuid.UUID
	var isUpdate bool
	if id != "" {
		parsedUUID, _ = uuid.Parse(id)
		isUpdate = true
	} else {
		parsedUUID = uuid.New()
	}

	idpConfig := model.IdentityProviderConfig{}
	if idpType == "oidc" {
		idpConfig.DiscoveryEndpoint = r.FormValue("discovery_endpoint")
		idpConfig.ClientID = r.FormValue("client_id")
		idpConfig.ClientSecret = r.FormValue("client_secret")
		idpConfig.DCRMode = model.DCRMode(r.FormValue("dcr_mode"))
		idpConfig.Scopes = r.Form["scopes"]
		if idpConfig.Scopes == nil {
			idpConfig.Scopes = []string{}
		}

		if idpConfig.DiscoveryEndpoint == "" {
			errs["discovery_endpoint"] = "Discovery Endpoint is required for OIDC providers"
		}
		if idpConfig.ClientID == "" {
			errs["client_id"] = "Client ID is required for OIDC providers"
		}
		if issuer == "" {
			errs["issuer"] = "Issuer is required for OIDC providers"
		}
	} else {
		idpConfig.UsernameField = r.FormValue("username_field")
		if idpConfig.UsernameField == "" {
			idpConfig.UsernameField = "preferredUsername"
		}
	}

	if len(errs) > 0 {
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusUnprocessableEntity)
		partitions, _ := h.storagePort.GetPartitions(r.Context(), tenant.ID)
		var formIdp model.IdentityProvider
		if isUpdate {
			if existing, err := h.storagePort.GetIdentityProviderByUUID(r.Context(), tenant.ID, parsedUUID); err == nil && existing != nil {
				formIdp = *existing
			}
		}
		component := admin.IDPForm(admin.IDPFormProps{
			Provider:   formIdp,
			Partitions: partitions,
			Errors:     errs,
			IsEdit:     isUpdate,
		})
		_ = component.Render(r.Context(), w)
		return
	}

	idp := model.IdentityProvider{
		ID:          parsedUUID,
		TenantID:    tenant.ID,
		IDPType:     idpType,
		Enabled:     enabled,
		Alias:       alias,
		Name:        name,
		PartitionID: partitionID,
		Issuer:      issuer,
		Config:      idpConfig,
	}

	var err error
	if isUpdate {
		_, err = h.idpService.UpdateIdentityProvider(r.Context(), tenant.ID, idp)
	} else {
		_, err = h.idpService.CreateIdentityProvider(r.Context(), tenant.ID, idp)
	}

	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(hxRedirectHeader, "/admin/idps?msg=Identity+provider+saved+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *AdminIDPHandler) adminDeleteIDP(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	idpIDStr := chi.URLParam(r, "id")
	idpUUID, err := uuid.Parse(idpIDStr)
	if err != nil {
		http.Error(w, errInvalidIDPUUID, http.StatusBadRequest)
		return
	}

	if err := h.idpService.DeleteIdentityProvider(r.Context(), tenant.ID, idpUUID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set(hxRedirectHeader, "/admin/idps?msg=Identity+provider+deleted+successfully")
	w.WriteHeader(http.StatusOK)
}
