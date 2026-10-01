package http

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"
	"sprezz-identity/internal/views/public"

	"github.com/go-chi/chi/v5"
)

const (
	AdminTenantName     = "Administrative Tenant"
	ErrInvalidIDPUUID   = "invalid IDP UUID"
	ErrMalformedPayload = "malformed payload parameters submitted"
	ErrOIDCDiscoveryURL = "OIDC discovery URL is required"
)

// parseFormStringSlice extracts a raw string array from incoming form values.
// If the key is missing from the payload map, it returns an empty, non-nil slice block.
func parseFormStringSlice(form url.Values, key string) []string {
	vals := form[key]
	if vals == nil {
		return []string{}
	}
	return vals
}

// CleanBoundaryStringSlice executes a zero-allocation, in-place filtration sweep
// that trims peripheral whitespace and completely evicts empty string fragments.
func CleanBoundaryStringSlice(slice []string) []string {
	if len(slice) == 0 {
		return slice
	}

	// In-place filtration reuse loop avoids duplicating the underlying block array
	writeIdx := 0
	for _, val := range slice {
		cleaned := strings.TrimSpace(val)
		if cleaned != "" {
			slice[writeIdx] = cleaned
			writeIdx++
		}
	}

	// Explicitly slice off any trailing index trash to release pointers for garbage collection
	return slice[:writeIdx]
}

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
		// Front-channel logout is called by the identity provider from a hidden iframe without an admin
		// session, so it stays outside the session guard. It only clears the caller's own cookie.
		r.Get(port.RouteAdminLogout, h.HandleAdminLogoutRequest)

		// Everything else in the console requires a verified administrator session.
		r.Group(func(r chi.Router) {
			r.Use(h.requireAdminSession)

			r.Get("/", h.adminDashboardView)
			r.Get(port.RouteAdminDashboard, h.adminDashboardView)

			h.tenantHandler.Routes(r)
			h.applicationHandler.Routes(r)
			h.idpHandler.Routes(r)
			h.userHandler.Routes(r)
		})
	})
}

// HandleAdminLogoutRequest clears out the administrative partition session.
// It detects and supports both OIDC front-channel iframe sweeps and manual user clicks.
func (h *AdminHandler) HandleAdminLogoutRequest(w http.ResponseWriter, r *http.Request) {
	// 1. Establish a secure baseline default matching max production profiles
	isSecure := h.appEnv != "local"

	// 2. READ CURRENT COOKIE: Attempt to load the active privileged token block
	if adminCookie, err := r.Cookie("spz_session_sprezz_admin"); err == nil {
		// TARGET FOUND: Dynamically mirror the exact secure flag from the live cookie instance
		isSecure = adminCookie.Secure
	}

	// 3. EXECUTE EVICTION: Clear out the admin token cleanly using the verified secure flag state
	http.SetCookie(w, &http.Cookie{
		Name:     "spz_session_sprezz_admin",
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Forces immediate native browser-level erasure
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})

	// 2. ADAPTIVE RESPONSE PATHWAY:
	// If the request contains an OIDC 'state' or 'id_token_hint' query parameter, or if the
	// User-Agent/Headers indicate a background iframe fetch, satisfy the OIDC spec with a 200 OK.
	if r.URL.Query().Get("state") != "" || r.Header.Get("Sec-Fetch-Dest") == "iframe" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
		return
	}

	// 3. MANUAL CLICK FALLBACK:
	// If an admin manually clicked "Sign Out" from within the admin dashboard,
	// send them directly to the clean unauthenticated admin login wall route.
	http.Redirect(w, r, port.RouteAdmin, http.StatusFound)
}

// adminDashboardView renders the landing page. The session has already been verified by requireAdminSession.
func (h *AdminHandler) adminDashboardView(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, port.ErrTenantNotFound.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	component := admin.AdminDashboard(admin.AdminDashboardProps{
		ActiveTenant:  *tenant,
		IsAdminTenant: tenant.IsSystem,
		Msg:           r.URL.Query().Get("msg"),
	})
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) initiateAdminOIDC(w http.ResponseWriter, r *http.Request) {
	// 1. Resolve multi-tenant and layout boundaries safely
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, port.ErrTenantNotFound.Error())
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

func (h *HttpAdapter) renderError(w http.ResponseWriter, r *http.Request, status int, errorMessage string) {
	slog.Error("Rendering admin visual error page", "status", status, "error", errorMessage, "path", r.URL.Path)
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	w.WriteHeader(status)
	component := public.Error(errorMessage)
	_ = component.Render(r.Context(), w)
}
