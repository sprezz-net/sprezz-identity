package http

import (
	"net/http"
	"net/url"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/views/admin"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type AdminTenantHandler struct {
	*HttpAdapter
}

func NewAdminTenantHandler(adapter *HttpAdapter) *AdminTenantHandler {
	return &AdminTenantHandler{HttpAdapter: adapter}
}

func (h *AdminTenantHandler) Routes(r chi.Router) {
	r.Get("/tenants", h.adminTenantsPage)
	r.Get("/tenants/new", h.adminNewTenantForm)
	r.Post("/tenants", h.adminCreateTenant)
	r.Post("/tenants/settings", h.adminSaveTenantSettings)
	r.Patch("/tenants/{id}/toggle-signup", h.adminToggleSignup)
}

func (h *AdminTenantHandler) adminNewTenantForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentTypeHeader, contentTypeHtml)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Create Tenant", "/admin/tenants/new")
		_ = component.Render(r.Context(), w)
		return
	}
	component := admin.CreateTenantForm(nil)
	_ = component.Render(r.Context(), w)
}

func (h *AdminTenantHandler) adminCreateTenant(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	domain := r.FormValue("domain")

	errs := make(map[string]string)
	if name == "" {
		errs["name"] = "tenant name is required"
	}
	if domain == "" {
		errs["domain"] = "canonical domain is required"
	}

	if len(errs) > 0 {
		w.Header().Set(contentTypeHeader, contentTypeHtml)
		w.WriteHeader(http.StatusUnprocessableEntity)
		component := admin.CreateTenantForm(errs)
		_ = component.Render(r.Context(), w)
		return
	}

	scheme := model.SchemeHttp + "://"
	if r.TLS != nil || r.Header.Get(xForwardedProto) == "https" {
		scheme = model.SchemeHttps + "://"
	}

	newTenant := model.Tenant{
		ID:        uuid.New(),
		Name:      name,
		Domain:    domain,
		IsActive:  true,
		CreatedAt: time.Now(),
		Config: model.TenantConfig{
			PredefinedScopes:    []string{"openid", "profile", "email", "offline_access"},
			PredefinedAudiences: []string{},
			DefaultRedirectURI:  scheme + domain,
			RedirectWhitelist:   []string{scheme + domain},
			AllowSignup:         false,
		},
	}

	if err := h.adminStorage.CreateTenant(r.Context(), newTenant); err != nil {
		errs["name"] = err.Error()
		w.Header().Set(contentTypeHeader, contentTypeHtml)
		component := admin.CreateTenantForm(errs)
		_ = component.Render(r.Context(), w)
		return
	}

	// Default Provider for new Tenant
	defaultProvider := model.IdentityProvider{
		ID:       uuid.New(),
		TenantID: newTenant.ID,
		IDPType:  model.UsernamePasswordIDPType,
		Enabled:  true,
		Alias:    "username-password",
		Config: model.IdentityProviderConfig{
			UsernameField: "preferredUsername",
		},
	}
	_ = h.adminStorage.CreateIdentityProvider(r.Context(), newTenant.ID, defaultProvider)

	w.Header().Set(hxRedirectHeader, routeAdmin+"?msg=Tenant+created+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *AdminTenantHandler) adminToggleSignup(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := chi.URLParam(r, "id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}

	// Fetch the tenant first to determine the toggled signup state
	t, err := h.storagePort.ResolveTenantByUUID(r.Context(), tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Delegate orchestration completely to the domain service
	tenant, err := h.tenantUseCase.ToggleSignup(r.Context(), tenantID, !t.Config.AllowSignup)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	var label, severity string
	if tenant.Config.AllowSignup {
		label, severity = "Active", "active"
	} else {
		label, severity = "Locked", "locked"
	}
	component := admin.Badge(label, severity)
	_ = component.Render(r.Context(), w)

	// We use HX-Redirect to natively trigger a full page refresh with the success message
	w.Header().Set(hxRedirectHeader, routeAdmin+"?msg=Registration+status+updated+successfully")
}

func (h *AdminTenantHandler) adminTenantsPage(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	isAdminTenant := tenant.Name == adminTenantName

	allTenants := []model.Tenant{}
	if isAdminTenant {
		var err error
		allTenants, err = h.adminStorage.GetAllTenants(r.Context())
		if err != nil {
			h.renderError(w, r, http.StatusInternalServerError, err.Error())
			return
		}
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	msg := r.URL.Query().Get("msg")
	props := admin.TenantsPageProps{
		ActiveTenant:  *tenant,
		IsAdminTenant: isAdminTenant,
		Tenants:       allTenants,
		Msg:           msg,
		Errors:        make(map[string]string),
	}
	if r.Header.Get(hxRequestHeader) == "true" {
		_ = admin.TenantsContent(props).Render(r.Context(), w)
	} else {
		_ = admin.TenantsPage(props).Render(r.Context(), w)
	}
}

func isPresentInWhitelist(uri string, whitelist []string) bool {
	for _, w := range whitelist {
		if w == uri {
			return true
		}
	}
	return false
}

func validateDefaultRedirectURI(uri string, whitelist []string) string {
	if uri == "" {
		return ""
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errInvalidURLFormat
	}
	if !isPresentInWhitelist(uri, whitelist) {
		return "Default Redirect URI must be present in the Redirect Whitelist"
	}
	return ""
}

func validateTenantSettingsInputs(name, domain, defaultRedirectURI string, redirectWhitelist []string) map[string]string {
	errs := make(map[string]string)
	if name == "" {
		errs["name"] = "tenant name is required"
	}
	if domain == "" {
		errs["domain"] = "canonical domain is required"
	}
	if errMsg := validateDefaultRedirectURI(defaultRedirectURI, redirectWhitelist); errMsg != "" {
		errs["default_redirect_uri"] = errMsg
	}
	return errs
}

func (h *AdminTenantHandler) adminSaveTenantSettings(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	name := r.FormValue("name")
	domain := r.FormValue("domain")
	defaultRedirectURI := r.FormValue("default_redirect_uri")
	redirectWhitelist := r.Form["redirect_whitelist"]
	if redirectWhitelist == nil {
		redirectWhitelist = []string{}
	}
	predefinedScopes := r.Form["predefined_scopes"]
	if predefinedScopes == nil {
		predefinedScopes = []string{}
	}
	predefinedAudiences := r.Form["predefined_audiences"]
	if predefinedAudiences == nil {
		predefinedAudiences = []string{}
	}

	errs := validateTenantSettingsInputs(name, domain, defaultRedirectURI, redirectWhitelist)

	config := tenant.Config
	config.DefaultRedirectURI = defaultRedirectURI
	config.RedirectWhitelist = redirectWhitelist
	config.PredefinedScopes = predefinedScopes
	config.PredefinedAudiences = predefinedAudiences

	if len(errs) > 0 {
		w.Header().Set(contentTypeHeader, contentTypeHtml)
		w.WriteHeader(http.StatusUnprocessableEntity)
		isAdminTenant := tenant.Name == adminTenantName
		allTenants := []model.Tenant{}
		if isAdminTenant {
			allTenants, _ = h.adminStorage.GetAllTenants(r.Context())
		}
		component := admin.TenantsPage(admin.TenantsPageProps{
			ActiveTenant:  *tenant,
			IsAdminTenant: isAdminTenant,
			Tenants:       allTenants,
			Errors:        errs,
		})
		_ = component.Render(r.Context(), w)
		return
	}

	_, err := h.tenantService.UpdateTenant(r.Context(), tenant.ID, name, domain, config)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	http.Redirect(w, r, "/admin/tenants?msg=Settings+saved+successfully", http.StatusFound)
}
