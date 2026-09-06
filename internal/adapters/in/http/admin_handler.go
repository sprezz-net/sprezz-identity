package http

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"

	"github.com/go-chi/chi/v5"
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

type AdminHandler struct {
	*HttpAdapter
	tenantHandler      *AdminTenantHandler
	applicationHandler *AdminApplicationHandler
	idpHandler         *AdminIDPHandler
	userHandler        *AdminUserHandler
}

func NewAdminHandler(adapter *HttpAdapter) *AdminHandler {
	return &AdminHandler{
		HttpAdapter:        adapter,
		tenantHandler:      NewAdminTenantHandler(adapter),
		applicationHandler: NewAdminApplicationHandler(adapter),
		idpHandler:         NewAdminIDPHandler(adapter),
		userHandler:        NewAdminUserHandler(adapter),
	}
}

func (h *AdminHandler) Routes(r chi.Router) {
	r.Route(port.RouteAdmin, func(r chi.Router) {
		r.Get("/", h.adminDashboardView)
		r.Get(port.RouteAdminDashboard, h.adminDashboardView)

		h.tenantHandler.Routes(r)
		h.applicationHandler.Routes(r)
		h.idpHandler.Routes(r)
		h.userHandler.Routes(r)
	})
}

func (h *AdminHandler) adminDashboardView(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, errTenantNotResolved)
		return
	}

	// 1. Resolve the expected namespaced session cookie dynamically from the SSO use case
	cookieSpec, err := h.ssoUseCase.BuildSessionCookie(r.Context(), port.CookieIntentCommand{
		TenantID:       tenant.ID,
		LifecycleStage: "clear", // Resolves bearer cookie name
		RequestHost:    r.Host,
	})
	if err != nil {
		h.initiateAdminOIDC(w, r)
		return
	}

	cookie, err := r.Cookie(cookieSpec.CookieName)
	if err != nil || cookie.Value == "" {
		h.initiateAdminOIDC(w, r)
		return
	}

	// 2. Parse colon string format to extract the local user token asset safely
	parts := strings.Split(cookie.Value, ":")
	if len(parts) != 3 || parts[0] != "bearer" || parts[1] == "" {
		h.initiateAdminOIDC(w, r)
		return
	}
	accessToken := parts[1]

	// 3. Verify the access token extracted out of the unified tracking session slot
	_, err = h.cryptoPort.VerifyToken(accessToken)
	if err != nil {
		h.clearCookieAndRedirect(w, r, cookieSpec.CookieName, port.RouteAdmin)
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	msg := r.URL.Query().Get("msg")
	component := admin.AdminDashboard(admin.AdminDashboardProps{
		ActiveTenant:  *tenant,
		IsAdminTenant: tenant.Name == adminTenantName,
		Msg:           msg,
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) initiateAdminOIDC(w http.ResponseWriter, r *http.Request) {
	// 1. Resolve multi-tenant and layout boundaries safely
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, errTenantNotResolved)
		return
	}

	// Dynamic Resolution: Sourced from canonical tenant configuration instead of hardcoded headers
	tenantBaseURI := tenant.GetBaseURI()
	redirectURI := tenantBaseURI + port.RouteFederationCallback

	providers, err := h.storagePort.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "failed to load provider configurations")
		return
	}

	// Dynamic Resolution: Lookup the explicit outbound provider enforcing all 3 mandatory criteria
	var adminIDP *model.IdentityProvider
	for _, p := range providers {
		if p.Alias == "admin-sso" && p.IDPType == "oidc" && p.Enabled {
			adminIDP = &p
			break
		}
	}

	if adminIDP == nil {
		h.renderError(w, r, http.StatusInternalServerError, "system outbound administrative identity provider context is missing or misconfigured")
		return
	}

	// 2. Trigger our clean data-driven administrative logon usecase that coordinates dynamic DCR setup on-demand
	response, err := h.adminLogonUseCase.InitiateAdminLogon(r.Context(), tenant.ID, redirectURI, tenantBaseURI+port.RouteAdmin)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "failed to initiate secure administrative session: "+err.Error())
		return
	}

	// 4. Provision the namespaced transient handshake session cookie on the browser
	cookieSpec, err := h.ssoUseCase.BuildSessionCookie(r.Context(), port.CookieIntentCommand{
		TenantID:       tenant.ID,
		LifecycleStage: "handshake",
		PayloadValue:   response.StateToken,
		RequestHost:    r.Host,
	})
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "failed to structure transient handshake session cookie")
		return
	}

	cookie := &http.Cookie{
		Name:     cookieSpec.CookieName,
		Value:    cookieSpec.CookieValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   cookieSpec.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	}

	http.SetCookie(w, cookie)

	// 6. Direct browser outbound leg to the intent URL generated by the core service
	http.Redirect(w, r, response.TargetRedirectURL, http.StatusFound)
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
