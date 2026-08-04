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

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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

	allTenants, err := h.storagePort.GetAllTenants(r.Context())
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	msg := r.URL.Query().Get("msg")
	component := views.AdminDashboard(tenant.ID.String(), tenant.Config.AllowSignup, allTenants, msg)
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

	w.Header().Set("HX-Trigger", "reloadDashboard")
	_, _ = w.Write([]byte(`<script nonce="` + templ.GetNonce(r.Context()) + `">window.location.href="/admin/dashboard?msg=Tenant+created+successfully"</script>`))
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

	// We also return a script to trigger a reload or visually update the toggle button state
	// In the dashboard we have hx-swap="outerHTML" targeting the button/badge wrapper, but let's do a simple full page refresh to show the updated message/state correctly
	_, _ = w.Write([]byte(`<script nonce="` + templ.GetNonce(r.Context()) + `">window.location.href="/admin/dashboard?msg=Registration+status+updated+successfully"</script>`))
}
