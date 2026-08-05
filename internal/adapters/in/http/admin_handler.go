package http

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/views"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	adminTenantName    = "Administrative Tenant"
	hxTriggerHeader    = "HX-Trigger"
	errInvalidIDPUUID  = "invalid IDP UUID"
	errInvalidUserUUID = "invalid User UUID"
)

func generateRandomVerifier() (string, string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(bytes)
	hsh := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hsh[:])
	return verifier, challenge, nil
}

func (h *HttpAdapter) adminDashboardView(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, errTenantNotResolved)
		return
	}

	cookie, err := r.Cookie("spz_admin_token")
	if err != nil || cookie.Value == "" {
		h.initiateAdminOIDC(w, r)
		return
	}

	_, err = h.cryptoPort.VerifyToken(cookie.Value)
	if err != nil {
		h.clearCookieAndRedirect(w, r, "spz_admin_token", "/admin")
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	msg := r.URL.Query().Get("msg")
	component := views.AdminDashboard(views.AdminDashboardProps{
		ActiveTenant:  *tenant,
		IsAdminTenant: tenant.Name == adminTenantName,
		Msg:           msg,
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) initiateAdminOIDC(w http.ResponseWriter, r *http.Request) {
	scheme := schemeHttp
	if r.TLS != nil || r.Header.Get(xForwardedProto) == "https" {
		scheme = schemeHttps
	}
	redirectURI := scheme + r.Host + "/admin/callback"
	state := uuid.NewString()

	verifier, challenge, err := generateRandomVerifier()
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "failed to generate secure PKCE verifier")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "spz_admin_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "spz_admin_verifier",
		Value:    verifier,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300,
	})

	authURL := fmt.Sprintf("/oauth/authorize?response_type=code&client_id=admin_ui&redirect_uri=%s&scope=openid+profile+email&state=%s&code_challenge=%s&code_challenge_method=S256",
		url.QueryEscape(redirectURI), state, challenge)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *HttpAdapter) clearCookieAndRedirect(w http.ResponseWriter, r *http.Request, cookieName, redirectPath string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, redirectPath, http.StatusFound)
}

func (h *HttpAdapter) adminCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	stateCookie, err := r.Cookie("spz_admin_state")
	if err != nil || stateCookie.Value == "" || stateCookie.Value != state {
		h.renderError(w, r, http.StatusBadRequest, "invalid state parameter")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.renderError(w, r, http.StatusBadRequest, "missing authorization code")
		return
	}

	verifierCookie, err := r.Cookie("spz_admin_verifier")
	if err != nil || verifierCookie.Value == "" {
		h.renderError(w, r, http.StatusBadRequest, "missing PKCE verifier parameter")
		return
	}

	scheme := schemeHttp
	if r.TLS != nil || r.Header.Get(xForwardedProto) == "https" {
		scheme = schemeHttps
	}
	redirectURI := scheme + r.Host + "/admin/callback"

	secret := ""
	if h.adminState != nil {
		secret = h.adminState.GetEphemeralSecret()
	}

	// Direct exchange POST back to our token endpoint
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "admin_ui")
	form.Set("client_secret", secret)
	form.Set("code", code)
	form.Set("code_verifier", verifierCookie.Value)
	form.Set("redirect_uri", redirectURI)

	tokenURL := scheme + r.Host + "/oauth/token"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "failed to exchange code: "+err.Error())
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errData map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&errData)
		h.renderError(w, r, resp.StatusCode, "token exchange rejected: "+errData["error"])
		return
	}

	var tokens model.TokenSetResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "failed to parse token response")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "spz_admin_token",
		Value:    tokens.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   resp.Request.URL.Scheme == "https",
		SameSite: http.SameSiteLaxMode,
	})

	// Clear transient flow cookies
	http.SetCookie(w, &http.Cookie{Name: "spz_admin_state", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "spz_admin_verifier", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})

	http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
}

func (h *HttpAdapter) adminNewTenantForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentTypeHeader, contentTypeHtml)
	if r.URL.Query().Get("modal") == "true" {
		component := views.Modal("Create Tenant", "/admin/tenants/new")
		_ = component.Render(r.Context(), w)
		return
	}
	component := views.CreateTenantForm(nil)
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) adminCreateTenant(w http.ResponseWriter, r *http.Request) {
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
		component := views.CreateTenantForm(errs)
		_ = component.Render(r.Context(), w)
		return
	}

	scheme := schemeHttp
	if r.TLS != nil || r.Header.Get(xForwardedProto) == "https" {
		scheme = schemeHttps
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

	if err := h.storagePort.CreateTenant(r.Context(), newTenant); err != nil {
		errs["name"] = err.Error()
		w.Header().Set(contentTypeHeader, contentTypeHtml)
		component := views.CreateTenantForm(errs)
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
	_ = h.storagePort.CreateIdentityProvider(r.Context(), newTenant.ID, defaultProvider)

	w.Header().Set("HX-Redirect", "/admin/dashboard?msg=Tenant+created+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *HttpAdapter) adminToggleSignup(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := chi.URLParam(r, "id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}

	tenant, err := h.storagePort.ResolveTenantByID(r.Context(), tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Toggle state
	tenant.Config.AllowSignup = !tenant.Config.AllowSignup

	// Save Tenant configuration (we overwrite by creating on conflict update or resolving then saving)
	// We can update tenant by calling CreateTenant since ON CONFLICT (tenant_uuid) DO UPDATE is used
	if err := h.storagePort.CreateTenant(r.Context(), *tenant); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	component := views.StatusBadge(tenant.Config.AllowSignup)
	_ = component.Render(r.Context(), w)

	// We use HX-Redirect to natively trigger a full page refresh with the success message
	w.Header().Set("HX-Redirect", "/admin/dashboard?msg=Registration+status+updated+successfully")
}

func (h *HttpAdapter) adminTenantsPage(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	isAdminTenant := tenant.Name == adminTenantName

	allTenants := []model.Tenant{}
	if isAdminTenant {
		var err error
		allTenants, err = h.tenantService.GetAllTenants(r.Context())
		if err != nil {
			h.renderError(w, r, http.StatusInternalServerError, err.Error())
			return
		}
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	msg := r.URL.Query().Get("msg")
	component := views.TenantsPage(views.TenantsPageProps{
		ActiveTenant:  *tenant,
		IsAdminTenant: isAdminTenant,
		Tenants:       allTenants,
		Msg:           msg,
		Errors:        make(map[string]string),
	})
	_ = component.Render(r.Context(), w)
}

func parseCommaSeparated(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}

func (h *HttpAdapter) adminSaveTenantSettings(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	name := r.FormValue("name")
	domain := r.FormValue("domain")
	defaultRedirectURI := r.FormValue("default_redirect_uri")
	redirectWhitelistStr := r.FormValue("redirect_whitelist")
	predefinedScopesStr := r.FormValue("predefined_scopes")
	predefinedAudiencesStr := r.FormValue("predefined_audiences")

	errs := make(map[string]string)
	if name == "" {
		errs["name"] = "tenant name is required"
	}
	if domain == "" {
		errs["domain"] = "canonical domain is required"
	}

	config := tenant.Config
	config.DefaultRedirectURI = defaultRedirectURI
	config.RedirectWhitelist = parseCommaSeparated(redirectWhitelistStr)
	config.PredefinedScopes = parseCommaSeparated(predefinedScopesStr)
	config.PredefinedAudiences = parseCommaSeparated(predefinedAudiencesStr)

	if len(errs) > 0 {
		w.Header().Set(contentTypeHeader, contentTypeHtml)
		isAdminTenant := tenant.Name == adminTenantName
		allTenants := []model.Tenant{}
		if isAdminTenant {
			allTenants, _ = h.tenantService.GetAllTenants(r.Context())
		}
		component := views.TenantsPage(views.TenantsPageProps{
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

func (h *HttpAdapter) adminClientsPage(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clients, err := h.clientService.GetClientsByTenant(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	msg := r.URL.Query().Get("msg")
	component := views.ClientsPage(views.ClientsPageProps{
		ActiveTenant: *tenant,
		Clients:      clients,
		Msg:          msg,
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) adminNewClientForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentTypeHeader, contentTypeHtml)
	if r.URL.Query().Get("modal") == "true" {
		component := views.Modal("Add Client", "/admin/clients/new")
		_ = component.Render(r.Context(), w)
		return
	}
	component := views.ClientForm(views.ClientFormProps{
		Client: model.ClientApplication{},
		Errors: make(map[string]string),
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) adminEditClientForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clientID := r.URL.Query().Get("id")

	client, err := h.storagePort.GetClient(r.Context(), tenant.ID, clientID)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, err.Error())
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	if r.URL.Query().Get("modal") == "true" {
		component := views.Modal("Edit Client", "/admin/clients/edit?id="+clientID)
		_ = component.Render(r.Context(), w)
		return
	}
	component := views.ClientForm(views.ClientFormProps{
		Client: *client,
		Errors: make(map[string]string),
		IsEdit: true,
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) adminViewClient(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clientID := r.URL.Query().Get("id")

	client, err := h.storagePort.GetClient(r.Context(), tenant.ID, clientID)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, err.Error())
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	if r.URL.Query().Get("modal") == "true" {
		component := views.Modal("Client Details", "/admin/clients/view?id="+clientID)
		_ = component.Render(r.Context(), w)
		return
	}
	component := views.ClientForm(views.ClientFormProps{
		Client:   *client,
		Errors:   make(map[string]string),
		IsEdit:   true,
		ReadOnly: true,
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) adminSaveClient(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id := r.FormValue("id")
	clientID := r.FormValue("client_id")
	clientName := r.FormValue("client_name")
	clientType := r.FormValue("client_type")
	redirectURIs := parseCommaSeparated(r.FormValue("redirect_uris"))
	postLogoutURIs := parseCommaSeparated(r.FormValue("post_logout_redirect_uris"))
	frontChannelLogoutURI := r.FormValue("front_channel_logout_uri")
	backChannelLogoutURI := r.FormValue("back_channel_logout_uri")

	errs := make(map[string]string)
	if clientID == "" {
		errs["client_id"] = "client ID is required"
	}
	if clientName == "" {
		errs["client_name"] = "client name is required"
	}

	isEdit := id != ""

	if len(errs) > 0 {
		w.Header().Set(contentTypeHeader, contentTypeHtml)
		component := views.ClientForm(views.ClientFormProps{
			Client: model.ClientApplication{ID: id, ClientID: clientID, ClientName: clientName},
			Errors: errs,
			IsEdit: isEdit,
		})
		_ = component.Render(r.Context(), w)
		return
	}

	// Validate whitelists and produce warning messages
	var warnings []string
	isWhitelisted := func(uri string) bool {
		if uri == "" {
			return true
		}
		for _, w := range tenant.Config.RedirectWhitelist {
			if strings.HasPrefix(uri, w) || uri == w {
				return true
			}
		}
		return false
	}

	for _, u := range redirectURIs {
		if !isWhitelisted(u) {
			warnings = append(warnings, fmt.Sprintf("Redirect URI '%s' is not in the Whitelist", u))
		}
	}
	for _, u := range postLogoutURIs {
		if !isWhitelisted(u) {
			warnings = append(warnings, fmt.Sprintf("Post-Logout URI '%s' is not in the Whitelist", u))
		}
	}
	if frontChannelLogoutURI != "" && !isWhitelisted(frontChannelLogoutURI) {
		warnings = append(warnings, fmt.Sprintf("Front-Channel Logout URI '%s' is not in the Whitelist", frontChannelLogoutURI))
	}
	if backChannelLogoutURI != "" && !isWhitelisted(backChannelLogoutURI) {
		warnings = append(warnings, fmt.Sprintf("Back-Channel Logout URI '%s' is not in the Whitelist", backChannelLogoutURI))
	}

	var err error
	if isEdit {
		_, err = h.clientService.UpdateClient(r.Context(), tenant.ID, model.ClientApplication{
			ClientID:               clientID,
			ClientName:             clientName,
			ClientType:             clientType,
			RedirectURIs:           redirectURIs,
			PostLogoutRedirectURIs: postLogoutURIs,
			FrontChannelLogoutURI:  frontChannelLogoutURI,
			BackChannelLogoutURI:   backChannelLogoutURI,
		})
	} else {
		_, err = h.clientService.CreateClient(r.Context(), tenant.ID, model.ClientApplication{
			ClientID:               clientID,
			ClientName:             clientName,
			ClientType:             clientType,
			RedirectURIs:           redirectURIs,
			PostLogoutRedirectURIs: postLogoutURIs,
			FrontChannelLogoutURI:  frontChannelLogoutURI,
			BackChannelLogoutURI:   backChannelLogoutURI,
		})
	}

	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	msgStr := "Application saved successfully"
	if len(warnings) > 0 {
		msgStr += ". Warning: some URIs are not in the tenant whitelist: " + strings.Join(warnings, "; ")
	}

	w.Header().Set("HX-Redirect", "/admin/clients?msg="+url.QueryEscape(msgStr))
	w.WriteHeader(http.StatusOK)
}

func (h *HttpAdapter) adminDeleteClient(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clientID := chi.URLParam(r, "id")

	if err := h.clientService.DeleteClient(r.Context(), tenant.ID, clientID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Redirect", "/admin/clients?msg=Client+deleted+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *HttpAdapter) adminIDPsPage(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	idps, err := h.idpService.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	msg := r.URL.Query().Get("msg")
	component := views.IDPsPage(views.IDPsPageProps{
		ActiveTenant: *tenant,
		Providers:    idps,
		Msg:          msg,
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) adminNewIDPForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentTypeHeader, contentTypeHtml)
	if r.URL.Query().Get("modal") == "true" {
		component := views.Modal("Add Identity Provider", "/admin/idps/new")
		_ = component.Render(r.Context(), w)
		return
	}
	component := views.IDPForm(views.IDPFormProps{
		Provider: model.IdentityProvider{},
		Errors:   make(map[string]string),
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) adminEditIDPForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	idpIDStr := r.URL.Query().Get("id")
	idpUUID, err := uuid.Parse(idpIDStr)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, errInvalidIDPUUID)
		return
	}

	providers, err := h.idpService.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	var provider *model.IdentityProvider
	for _, p := range providers {
		if p.ID == idpUUID {
			provider = &p
			break
		}
	}

	if provider == nil {
		h.renderError(w, r, http.StatusNotFound, "provider not found")
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	if r.URL.Query().Get("modal") == "true" {
		component := views.Modal("Edit Identity Provider", "/admin/idps/edit?id="+idpIDStr)
		_ = component.Render(r.Context(), w)
		return
	}
	component := views.IDPForm(views.IDPFormProps{
		Provider: *provider,
		Errors:   make(map[string]string),
		IsEdit:   true,
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) adminSaveIDP(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id := r.FormValue("id")
	idpType := r.FormValue("idp_type")
	alias := r.FormValue("alias")
	enabled := r.FormValue("enabled") == "true"
	usernameField := r.FormValue("username_field")
	ialStr := r.FormValue("ial")
	aalStr := r.FormValue("aal")

	var ial, aal int
	_, _ = fmt.Sscanf(ialStr, "%d", &ial)
	_, _ = fmt.Sscanf(aalStr, "%d", &aal)

	errs := make(map[string]string)
	if alias == "" {
		errs["alias"] = "alias is required"
	}

	isEdit := id != ""

	var idpUUID uuid.UUID
	if isEdit {
		var err error
		idpUUID, err = uuid.Parse(id)
		if err != nil {
			h.renderError(w, r, http.StatusBadRequest, errInvalidIDPUUID)
			return
		}
	}

	provider := model.IdentityProvider{
		ID:       idpUUID,
		TenantID: tenant.ID,
		IDPType:  idpType,
		Alias:    alias,
		Enabled:  enabled,
		Config: model.IdentityProviderConfig{
			UsernameField: usernameField,
			IAL:           ial,
			AAL:           aal,
		},
	}

	if len(errs) > 0 {
		w.Header().Set(contentTypeHeader, contentTypeHtml)
		component := views.IDPForm(views.IDPFormProps{
			Provider: provider,
			Errors:   errs,
			IsEdit:   isEdit,
		})
		_ = component.Render(r.Context(), w)
		return
	}

	var err error

	if isEdit {
		provider.ID = idpUUID
		_, err = h.idpService.UpdateIdentityProvider(r.Context(), tenant.ID, provider)
	} else {
		_, err = h.idpService.CreateIdentityProvider(r.Context(), tenant.ID, provider)
	}

	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/admin/idps?msg=Identity+Provider+saved+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *HttpAdapter) adminDeleteIDP(w http.ResponseWriter, r *http.Request) {
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

	w.Header().Set("HX-Redirect", "/admin/idps?msg=Identity+Provider+deleted+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *HttpAdapter) adminUsersPage(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	users, err := h.userProfileService.GetUserProfilesByTenant(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	msg := r.URL.Query().Get("msg")
	component := views.UsersPage(views.UsersPageProps{
		ActiveTenant: *tenant,
		Users:        users,
		Msg:          msg,
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) adminViewUser(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	userIDStr := r.URL.Query().Get("id")
	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, errInvalidUserUUID)
		return
	}

	user, err := h.storagePort.GetUserProfileByID(r.Context(), tenant.ID, userUUID)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, err.Error())
		return
	}

	identities, err := h.userProfileService.GetUserIdentities(r.Context(), userUUID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	providers, err := h.idpService.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	if r.URL.Query().Get("modal") == "true" {
		component := views.Modal("User Details & Identities", "/admin/users/view?id="+userIDStr)
		_ = component.Render(r.Context(), w)
		return
	}
	component := views.UserDetails(views.UserDetailsProps{
		User:       *user,
		Identities: identities,
		Providers:  providers,
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) adminEditUserForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	userIDStr := r.URL.Query().Get("id")
	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, errInvalidUserUUID)
		return
	}

	user, err := h.storagePort.GetUserProfileByID(r.Context(), tenant.ID, userUUID)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, err.Error())
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	if r.URL.Query().Get("modal") == "true" {
		component := views.Modal("Edit User Profile", "/admin/users/edit?id="+userIDStr)
		_ = component.Render(r.Context(), w)
		return
	}
	component := views.UserForm(views.UserFormProps{
		User:   *user,
		Errors: make(map[string]string),
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) adminSaveUser(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id := r.FormValue("id")
	username := r.FormValue("preferred_username")
	name := r.FormValue("name")
	email := r.FormValue("email")
	emailVerified := r.FormValue("email_verified") == "true"

	userUUID, err := uuid.Parse(id)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, errInvalidUserUUID)
		return
	}

	errs := make(map[string]string)
	if username == "" {
		errs["preferred_username"] = "username is required"
	}
	if name == "" {
		errs["name"] = "name is required"
	}
	if email == "" {
		errs["email"] = "email is required"
	}

	if len(errs) > 0 {
		w.Header().Set(contentTypeHeader, contentTypeHtml)
		component := views.UserForm(views.UserFormProps{
			User:   model.UserProfile{ID: userUUID, PreferredUsername: username, Name: name, Email: email, EmailVerified: emailVerified},
			Errors: errs,
		})
		_ = component.Render(r.Context(), w)
		return
	}

	_, err = h.userProfileService.UpdateUserProfile(r.Context(), tenant.ID, model.UserProfile{
		ID:                userUUID,
		PreferredUsername: username,
		Name:              name,
		Email:             email,
		EmailVerified:     emailVerified,
	})
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/admin/users?msg=User+saved+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *HttpAdapter) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	userIDStr := chi.URLParam(r, "id")
	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, errInvalidUserUUID, http.StatusBadRequest)
		return
	}

	if err := h.userProfileService.DeleteUserProfile(r.Context(), tenant.ID, userUUID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Redirect", "/admin/users?msg=User+deleted+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *HttpAdapter) adminDecoupleIdentity(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	userIDStr := chi.URLParam(r, "id")
	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, errInvalidUserUUID, http.StatusBadRequest)
		return
	}

	idpIDStr := chi.URLParam(r, "idp")
	idpUUID, err := uuid.Parse(idpIDStr)
	if err != nil {
		http.Error(w, errInvalidIDPUUID, http.StatusBadRequest)
		return
	}

	if err := h.userProfileService.DecoupleIdentity(r.Context(), userUUID, idpUUID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch updated details to re-render in modal body
	user, err := h.storagePort.GetUserProfileByID(r.Context(), tenant.ID, userUUID)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, err.Error())
		return
	}

	identities, err := h.userProfileService.GetUserIdentities(r.Context(), userUUID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	providers, err := h.idpService.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	component := views.UserDetails(views.UserDetailsProps{
		User:       *user,
		Identities: identities,
		Providers:  providers,
	})
	_ = component.Render(r.Context(), w)
}
