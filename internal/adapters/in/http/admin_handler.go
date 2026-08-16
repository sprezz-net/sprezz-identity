package http

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/views/admin"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	adminTenantName     = "Administrative Tenant"
	hxTriggerHeader     = "HX-Trigger"
	hxRedirectHeader    = "HX-Redirect"
	hxRequestHeader     = "HX-Request"
	errInvalidIDPUUID   = "invalid IDP UUID"
	errInvalidUserUUID  = "invalid User UUID"
	errInvalidURLFormat = "Invalid URL format (must include protocol like http:// or https://)"
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
	component := admin.AdminDashboard(admin.AdminDashboardProps{
		ActiveTenant:  *tenant,
		IsAdminTenant: tenant.Name == adminTenantName,
		Msg:           msg,
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) initiateAdminOIDC(w http.ResponseWriter, r *http.Request) {
	scheme := model.SchemeHttp
	if r.TLS != nil || r.Header.Get(xForwardedProto) == "https" {
		scheme = model.SchemeHttps
	}
	redirectURI := scheme + "://" + r.Host + "/admin/callback"
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

	scheme := model.SchemeHttp
	if r.TLS != nil || r.Header.Get(xForwardedProto) == "https" {
		scheme = model.SchemeHttps
	}
	redirectURI := scheme + "://" + r.Host + "/admin/callback"

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

	tokenURL := scheme + "://" + r.Host + "/oauth/token"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set(model.HeaderContentType, "application/x-www-form-urlencoded")

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
		component := admin.Modal("Create Tenant", "/admin/tenants/new")
		_ = component.Render(r.Context(), w)
		return
	}
	component := admin.CreateTenantForm(nil)
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

	if err := h.storagePort.CreateTenant(r.Context(), newTenant); err != nil {
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
	_ = h.storagePort.CreateIdentityProvider(r.Context(), newTenant.ID, defaultProvider)

	w.Header().Set(hxRedirectHeader, "/admin/dashboard?msg=Tenant+created+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *HttpAdapter) adminToggleSignup(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := chi.URLParam(r, "id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}

	// Delegate orchestration completely to the domain service
	tenant, err := h.tenantService.ToggleSignup(r.Context(), tenantID)
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
	w.Header().Set(hxRedirectHeader, "/admin/dashboard?msg=Registration+status+updated+successfully")
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

func (h *HttpAdapter) adminSaveTenantSettings(w http.ResponseWriter, r *http.Request) {
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
			allTenants, _ = h.tenantService.GetAllTenants(r.Context())
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

func (h *HttpAdapter) adminClientsPage(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clients, err := h.clientService.GetClientsByTenant(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	msg := r.URL.Query().Get("msg")
	props := admin.ClientsPageProps{
		ActiveTenant: *tenant,
		Clients:      clients,
		Msg:          msg,
	}
	if r.Header.Get(hxRequestHeader) == "true" {
		_ = admin.ClientsContent(props).Render(r.Context(), w)
	} else {
		_ = admin.ClientsPage(props).Render(r.Context(), w)
	}
}

func (h *HttpAdapter) adminNewClientForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	providers, err := h.idpService.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Add Client", "/admin/clients/new")
		_ = component.Render(r.Context(), w)
		return
	}
	component := admin.ClientForm(admin.ClientFormProps{
		Client: model.ClientApplication{
			AccessTokenLifetime:  900 * time.Second,
			IDTokenLifetime:      900 * time.Second,
			RefreshTokenLifetime: 1209600 * time.Second,
		},
		Errors:    make(map[string]string),
		Providers: providers,
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

	providers, err := h.idpService.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Edit Client", "/admin/clients/edit?id="+clientID)
		_ = component.Render(r.Context(), w)
		return
	}
	component := admin.ClientForm(admin.ClientFormProps{
		Client:    *client,
		Errors:    make(map[string]string),
		IsEdit:    true,
		Providers: providers,
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

	providers, err := h.idpService.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Client Details", "/admin/clients/view?id="+clientID)
		_ = component.Render(r.Context(), w)
		return
	}
	component := admin.ClientForm(admin.ClientFormProps{
		Client:    *client,
		Errors:    make(map[string]string),
		IsEdit:    true,
		ReadOnly:  true,
		Providers: providers,
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) adminResetClientSecret(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clientID := chi.URLParam(r, "id")

	client, err := h.storagePort.GetClient(r.Context(), tenant.ID, clientID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if client.ClientType != model.ClientTypeConfidential {
		http.Error(w, "Cannot reset secret of a non-confidential client", http.StatusBadRequest)
		return
	}

	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	newSecret := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)
	client.ClientSecret = &newSecret

	if err := h.storagePort.SaveClient(r.Context(), *client); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	_, _ = w.Write(fmt.Appendf(nil, `
		<div class="p-3 bg-yellow-50 border border-yellow-200 rounded-lg text-sm font-mono text-slate-800 break-all mb-4">
			<strong>New Client Secret:</strong> %s
			<p class="text-xs text-slate-500 mt-1">Copy this secret now. It will not be shown again.</p>
		</div>
	`, newSecret))
}

func parseFormStringSlice(form url.Values, key string) []string {
	vals := form[key]
	if vals == nil {
		return []string{}
	}
	return vals
}

func parseClientLifetimes(r *http.Request) (time.Duration, time.Duration, time.Duration) {
	var accessSec, idSec, refreshSec int64
	_, _ = fmt.Sscanf(r.FormValue("access_token_lifetime"), "%d", &accessSec)
	_, _ = fmt.Sscanf(r.FormValue("id_token_lifetime"), "%d", &idSec)
	_, _ = fmt.Sscanf(r.FormValue("refresh_token_lifetime"), "%d", &refreshSec)

	return time.Duration(accessSec) * time.Second,
		time.Duration(idSec) * time.Second,
		time.Duration(refreshSec) * time.Second
}

func validateClientFormURLs(redirectURI, frontChannel, backChannel string) map[string]string {
	errs := make(map[string]string)
	if redirectURI != "" {
		if u, err := url.Parse(redirectURI); err != nil || u.Scheme == "" || u.Host == "" {
			errs["redirect_uri"] = errInvalidURLFormat
		}
	}
	if frontChannel != "" {
		if u, err := url.Parse(frontChannel); err != nil || u.Scheme == "" || u.Host == "" {
			errs["front_channel_logout_uri"] = errInvalidURLFormat
		}
	}
	if backChannel != "" {
		if u, err := url.Parse(backChannel); err != nil || u.Scheme == "" || u.Host == "" {
			errs["back_channel_logout_uri"] = errInvalidURLFormat
		}
	}
	return errs
}

func validateClientFormInputs(clientID, clientName, redirectURI, frontChannel, backChannel string) map[string]string {
	errs := make(map[string]string)
	if clientID == "" {
		errs["client_id"] = "client ID is required"
	}
	if clientName == "" {
		errs["client_name"] = "client name is required"
	}
	urlErrs := validateClientFormURLs(redirectURI, frontChannel, backChannel)
	for k, v := range urlErrs {
		errs[k] = v
	}
	return errs
}

func (h *HttpAdapter) adminSaveClient(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	id := r.FormValue("id")
	clientID := r.FormValue("client_id")
	clientName := r.FormValue("client_name")
	clientType := r.FormValue("client_type")

	redirectURI := r.FormValue("redirect_uri")
	redirectURIs := parseFormStringSlice(r.Form, "redirect_uris")
	postLogoutURIs := parseFormStringSlice(r.Form, "post_logout_redirect_uris")

	frontChannelLogoutURI := r.FormValue("front_channel_logout_uri")
	backChannelLogoutURI := r.FormValue("back_channel_logout_uri")

	// Parse custom lifetimes
	accessTokenLifetime, idTokenLifetime, refreshTokenLifetime := parseClientLifetimes(r)

	// Parse IDPs
	allowedIDPs := parseFormStringSlice(r.Form, "allowed_idps")
	defaultIDP := r.FormValue("default_idp_id")

	// Parse Scopes & Audiences
	scopes := parseFormStringSlice(r.Form, "scopes")
	audiences := parseFormStringSlice(r.Form, "audiences")

	errs := validateClientFormInputs(clientID, clientName, redirectURI, frontChannelLogoutURI, backChannelLogoutURI)

	isEdit := id != ""

	enforceRtr := r.FormValue("enforce_rtr") == "true"
	if clientType == "public" {
		enforceRtr = true
	}

	if len(errs) > 0 {
		providers, _ := h.idpService.GetIdentityProviders(r.Context(), tenant.ID)
		w.Header().Set(contentTypeHeader, contentTypeHtml)
		w.WriteHeader(http.StatusUnprocessableEntity)
		component := admin.ClientForm(admin.ClientFormProps{
			Client: model.ClientApplication{
				ID:                     id,
				ClientID:               clientID,
				ClientName:             clientName,
				ClientType:             clientType,
				RedirectURI:            redirectURI,
				RedirectURIs:           redirectURIs,
				PostLogoutRedirectURIs: postLogoutURIs,
				FrontChannelLogoutURI:  frontChannelLogoutURI,
				BackChannelLogoutURI:   backChannelLogoutURI,
				AccessTokenLifetime:    accessTokenLifetime,
				IDTokenLifetime:        idTokenLifetime,
				RefreshTokenLifetime:   refreshTokenLifetime,
				AllowedIDPs:            allowedIDPs,
				DefaultIDP:             defaultIDP,
				AllowedScopes:          scopes,
				AllowedAudiences:       audiences,
				EnforceRTR:             enforceRtr,
			},
			Errors:    errs,
			IsEdit:    isEdit,
			Providers: providers,
		})
		_ = component.Render(r.Context(), w)
		return
	}

	warnings := h.validateClientWhitelists(tenant, redirectURIs, postLogoutURIs, frontChannelLogoutURI, backChannelLogoutURI)

	// Combine or handle Client Secret logic
	var clientSecret *string
	if !isEdit && clientType == model.ClientTypeConfidential {
		sec := r.FormValue("client_secret")
		if sec == "" {
			bytes := make([]byte, 32)
			_, _ = rand.Read(bytes)
			sec = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)
		}
		clientSecret = &sec
	}

	var err error
	clientApp := model.ClientApplication{
		ClientID:               clientID,
		ClientName:             clientName,
		ClientType:             clientType,
		RedirectURI:            redirectURI,
		RedirectURIs:           redirectURIs,
		PostLogoutRedirectURIs: postLogoutURIs,
		FrontChannelLogoutURI:  frontChannelLogoutURI,
		BackChannelLogoutURI:   backChannelLogoutURI,
		AccessTokenLifetime:    accessTokenLifetime,
		IDTokenLifetime:        idTokenLifetime,
		RefreshTokenLifetime:   refreshTokenLifetime,
		AllowedIDPs:            allowedIDPs,
		DefaultIDP:             defaultIDP,
		AllowedScopes:          scopes,
		DefaultScopes:          scopes,
		AllowedAudiences:       audiences,
		EnforceRTR:             enforceRtr,
	}

	if isEdit {
		_, err = h.clientService.UpdateClient(r.Context(), tenant.ID, clientApp)
	} else {
		clientApp.ClientSecret = clientSecret
		_, err = h.clientService.CreateClient(r.Context(), tenant.ID, clientApp)
	}

	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	msgStr := "Application saved successfully"
	if !isEdit && clientSecret != nil {
		msgStr += ". Initial Client Secret: " + *clientSecret + " (Please copy this now, as it will not be shown again!)"
	}
	if len(warnings) > 0 {
		msgStr += ". Warning: some URIs are not in the tenant whitelist: " + strings.Join(warnings, "; ")
	}

	w.Header().Set(hxRedirectHeader, "/admin/clients?msg="+url.QueryEscape(msgStr))
	w.WriteHeader(http.StatusOK)
}

func (h *HttpAdapter) adminDeleteClient(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clientID := chi.URLParam(r, "id")

	if err := h.clientService.DeleteClient(r.Context(), tenant.ID, clientID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set(hxRedirectHeader, "/admin/clients?msg=Client+deleted+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *HttpAdapter) adminIDPsPage(w http.ResponseWriter, r *http.Request) {
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

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	msg := r.URL.Query().Get("msg")
	props := admin.IDPsPageProps{
		ActiveTenant:      *tenant,
		Providers:         idps,
		Partitions:        partitions,
		FilterPartitionID: filterPartitionID,
		Msg:               msg,
	}
	if r.Header.Get(hxRequestHeader) == "true" {
		_ = admin.IDPsContent(props).Render(r.Context(), w)
	} else {
		_ = admin.IDPsPage(props).Render(r.Context(), w)
	}
}

func (h *HttpAdapter) adminNewIDPForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	w.Header().Set(contentTypeHeader, contentTypeHtml)
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
		Provider:   model.IdentityProvider{},
		Partitions: partitions,
		Errors:     make(map[string]string),
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

	partitions, err := h.storagePort.GetPartitions(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Edit Identity Provider", "/admin/idps/edit?id="+idpIDStr)
		_ = component.Render(r.Context(), w)
		return
	}
	component := admin.IDPForm(admin.IDPFormProps{
		Provider:   *provider,
		Partitions: partitions,
		Errors:     make(map[string]string),
		IsEdit:     true,
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) adminDiscoverIDP(w http.ResponseWriter, r *http.Request) {
	urlStr := r.URL.Query().Get("url")
	if urlStr == "" {
		http.Error(w, "missing url parameter", http.StatusBadRequest)
		return
	}
	result, err := h.idpService.DiscoverOIDC(r.Context(), urlStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(result))
}

func (h *HttpAdapter) hasDuplicateUsernamePasswordIDP(r *http.Request, tenantID uuid.UUID, idpUUID uuid.UUID, isEdit bool) bool {
	existing, err := h.idpService.GetIdentityProviders(r.Context(), tenantID)
	if err != nil {
		return false
	}
	for _, ext := range existing {
		if ext.IDPType == model.UsernamePasswordIDPType && (!isEdit || ext.ID != idpUUID) {
			return true
		}
	}
	return false
}

func parseFormSlice(form url.Values, key string) []string {
	vals := form[key]
	var result []string
	for _, val := range vals {
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		if strings.Contains(val, ",") {
			parts := strings.Split(val, ",")
			for _, part := range parts {
				p := strings.TrimSpace(part)
				if p != "" {
					result = append(result, p)
				}
			}
		} else {
			result = append(result, val)
		}
	}
	if result == nil {
		return []string{}
	}
	return result
}

func (h *HttpAdapter) adminSaveIDP(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id := r.FormValue("id")
	idpType := r.FormValue("idp_type")
	alias := r.FormValue("alias")
	name := r.FormValue("name")
	enabled := r.FormValue("enabled") == "true"
	usernameField := r.FormValue("username_field")
	ialStr := r.FormValue("ial")
	aalStr := r.FormValue("aal")

	partitionIDStr := r.FormValue("partition_id")
	var partitionID int64
	if partitionIDStr != "" {
		_, _ = fmt.Sscanf(partitionIDStr, "%d", &partitionID)
	}

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

	if idpType == model.UsernamePasswordIDPType && h.hasDuplicateUsernamePasswordIDP(r, tenant.ID, idpUUID, isEdit) {
		errs["idp_type"] = "A username-password identity provider already exists for this tenant"
	}

	provider := model.IdentityProvider{
		ID:          idpUUID,
		TenantID:    tenant.ID,
		IDPType:     idpType,
		Alias:       alias,
		Name:        name,
		PartitionID: partitionID,
		Enabled:     enabled,
		Config: model.IdentityProviderConfig{
			UsernameField: usernameField,
			IAL:           ial,
			AAL:           aal,
		},
	}

	if idpType == "oidc" {
		provider.Config.DiscoveryEndpoint = r.FormValue("discovery_endpoint")
		provider.Config.Issuer = r.FormValue("issuer")
		provider.Config.ClientID = r.FormValue("client_id")
		provider.Config.ClientSecret = r.FormValue("client_secret")
		provider.Config.AuthenticationMethod = r.FormValue("authentication_method")
		provider.Config.PkceEnabled = r.FormValue("pkce_enabled") == "true"
		provider.Config.ParEnabled = r.FormValue("par_enabled") == "true"
		provider.Config.SLOEnabled = r.FormValue("slo_enabled") == "true"
		provider.Config.Scopes = parseFormSlice(r.Form, "scopes")
		provider.Config.Claims = parseFormSlice(r.Form, "claims")
		provider.Config.ACRValues = parseFormSlice(r.Form, "acr_values")
		provider.Config.DomainAliases = parseFormSlice(r.Form, "domain_aliases")
		provider.Config.UserIdentifierClaim = r.FormValue("user_identifier_claim")
		provider.Config.DiscoveryResult = r.FormValue("discovery_result")

		// Initialize the new single unified multi-dimensional Tuple map
		provider.Config.AcrToTuple = make(map[string]model.AcrTuple)

		// Dynamic multi-key grid form binding logic loop
		for formKey, formValues := range r.Form {
			if len(formValues) == 0 || formValues[0] == "" {
				continue
			}

			// Capture matching nested form field keys: "acr_to_tuple[raw_acr][aal]" or "acr_to_tuple[raw_acr][ial]"
			if strings.HasPrefix(formKey, "acr_to_tuple[") && strings.HasSuffix(formKey, "]") {
				// Strip external wrappers to isolate inner string parameters
				innerPath := formKey[len("acr_to_tuple[") : len(formKey)-1]

				// Separate raw_acr payload from vector target identifiers by isolating sub-bracket boundaries
				splitIdx := strings.LastIndex(innerPath, "][")
				if splitIdx == -1 {
					continue
				}

				rawAcrKey := innerPath[:splitIdx]
				tupleField := innerPath[splitIdx+2:] // Yields exactly "aal" or "ial"

				var levelVal int
				if _, err := fmt.Sscanf(formValues[0], "%d", &levelVal); err != nil {
					continue
				}

				// Fetch existing tuple or create a fresh zero-initialized coordinates pair
				currentTuple := provider.Config.AcrToTuple[rawAcrKey]

				// Apply targeted modifications dynamically across independent system metrics
				switch tupleField {
				case "aal":
					currentTuple.AAL = levelVal
				case "ial":
					currentTuple.IAL = levelVal
				}

				// Persist modification shifts back into the structural configuration map
				provider.Config.AcrToTuple[rawAcrKey] = currentTuple
			}
		}

		// Keep existing AMR factor parsing configurations unchanged
		provider.Config.AmrToAAL = make(map[string]int)
		standardAMRs := []string{"pwd", "mfa", "hwk", "otp", "sms"}
		for _, amr := range standardAMRs {
			formKey := fmt.Sprintf("amr_to_aal[%s]", amr)
			if val := r.FormValue(formKey); val != "" {
				var targetAAL int
				if _, err := fmt.Sscanf(val, "%d", &targetAAL); err == nil && targetAAL > 0 {
					provider.Config.AmrToAAL[amr] = targetAAL
				}
			}
		}

		customAMRKeys := r.Form["custom_amr_keys"]
		customAMRValues := r.Form["custom_amr_values"]
		if len(customAMRKeys) == len(customAMRValues) {
			for i, key := range customAMRKeys {
				trimmedKey := strings.TrimSpace(key)
				if trimmedKey == "" {
					continue
				}
				var targetAAL int
				if _, err := fmt.Sscanf(customAMRValues[i], "%d", &targetAAL); err == nil && targetAAL > 0 {
					provider.Config.AmrToAAL[trimmedKey] = targetAAL
				}
			}
		}
	}

	if len(errs) > 0 {
		partitions, err := h.storagePort.GetPartitions(r.Context(), tenant.ID)
		if err != nil {
			h.renderError(w, r, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set(contentTypeHeader, contentTypeHtml)
		w.WriteHeader(http.StatusUnprocessableEntity)
		component := admin.IDPForm(admin.IDPFormProps{
			Provider:   provider,
			Partitions: partitions,
			Errors:     errs,
			IsEdit:     isEdit,
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

	w.Header().Set(hxRedirectHeader, "/admin/idps?msg=Identity+Provider+saved+successfully")
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

	w.Header().Set(hxRedirectHeader, "/admin/idps?msg=Identity+Provider+deleted+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *HttpAdapter) adminUsersPage(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	users, err := h.userProfileService.GetUserProfilesByTenant(r.Context(), tenant.ID)
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
		var filtered []model.UserProfile
		for _, u := range users {
			if u.PartitionID == filterPartitionID {
				filtered = append(filtered, u)
			}
		}
		users = filtered
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	msg := r.URL.Query().Get("msg")
	props := admin.UsersPageProps{
		ActiveTenant:      *tenant,
		Users:             users,
		Partitions:        partitions,
		FilterPartitionID: filterPartitionID,
		Msg:               msg,
	}
	if r.Header.Get(hxRequestHeader) == "true" {
		_ = admin.UsersContent(props).Render(r.Context(), w)
	} else {
		_ = admin.UsersPage(props).Render(r.Context(), w)
	}
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
		component := admin.Modal("User Details & Identities", "/admin/users/view?id="+userIDStr)
		_ = component.Render(r.Context(), w)
		return
	}
	component := admin.UserDetails(admin.UserDetailsProps{
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

	partitions, err := h.storagePort.GetPartitions(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Edit User Profile", "/admin/users/edit?id="+userIDStr)
		_ = component.Render(r.Context(), w)
		return
	}
	component := admin.UserForm(admin.UserFormProps{
		User:       *user,
		Partitions: partitions,
		Errors:     make(map[string]string),
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
	partitionIDStr := r.FormValue("partition_id")

	var partitionID int64
	if partitionIDStr != "" {
		partitionID, _ = strconv.ParseInt(partitionIDStr, 10, 64)
	}

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
		w.WriteHeader(http.StatusUnprocessableEntity)
		partitions, _ := h.storagePort.GetPartitions(r.Context(), tenant.ID)
		component := admin.UserForm(admin.UserFormProps{
			User:       model.UserProfile{ID: userUUID, PreferredUsername: username, Name: name, Email: email, EmailVerified: emailVerified, PartitionID: partitionID},
			Partitions: partitions,
			Errors:     errs,
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
		PartitionID:       partitionID,
	})
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(hxRedirectHeader, "/admin/users?msg=User+saved+successfully")
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

	w.Header().Set(hxRedirectHeader, "/admin/users?msg=User+deleted+successfully")
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

	if err := h.userProfileService.DecoupleIdentity(r.Context(), tenant.ID, userUUID, idpUUID); err != nil {
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
	component := admin.UserDetails(admin.UserDetailsProps{
		User:       *user,
		Identities: identities,
		Providers:  providers,
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) isWhitelisted(tenant *model.Tenant, uri string) bool {
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

func (h *HttpAdapter) validateClientWhitelists(tenant *model.Tenant, redirectURIs, postLogoutURIs []string, frontChannelLogoutURI, backChannelLogoutURI string) []string {
	var warnings []string

	for _, u := range redirectURIs {
		if !h.isWhitelisted(tenant, u) {
			warnings = append(warnings, fmt.Sprintf("Redirect URI '%s' is not in the Whitelist", u))
		}
	}
	for _, u := range postLogoutURIs {
		if !h.isWhitelisted(tenant, u) {
			warnings = append(warnings, fmt.Sprintf("Post-Logout URI '%s' is not in the Whitelist", u))
		}
	}
	if frontChannelLogoutURI != "" && !h.isWhitelisted(tenant, frontChannelLogoutURI) {
		warnings = append(warnings, fmt.Sprintf("Front-Channel Logout URI '%s' is not in the Whitelist", frontChannelLogoutURI))
	}
	if backChannelLogoutURI != "" && !h.isWhitelisted(tenant, backChannelLogoutURI) {
		warnings = append(warnings, fmt.Sprintf("Back-Channel Logout URI '%s' is not in the Whitelist", backChannelLogoutURI))
	}
	return warnings
}

func (h *HttpAdapter) adminGenerateSecret(w http.ResponseWriter, r *http.Request) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		http.Error(w, "Failed to generate secure random bytes", http.StatusInternalServerError)
		return
	}
	secret := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(secret))
}
