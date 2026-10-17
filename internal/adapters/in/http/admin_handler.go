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

// HandleAdminLogoutRequest ends the administrative session: the server-side record is revoked, so a copied cookie
// is worthless afterwards, and the cookie is evicted from the browser.
// It detects and supports both OIDC front-channel iframe sweeps and manual user clicks.
func (h *AdminHandler) HandleAdminLogoutRequest(w http.ResponseWriter, r *http.Request) {
	cookieName, isSecure := h.revokeAdminSession(r)

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Forces immediate native browser-level erasure
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})

	// ADAPTIVE RESPONSE PATHWAY:
	// If the request contains an OIDC 'state' or 'id_token_hint' query parameter, or if the
	// User-Agent/Headers indicate a background iframe fetch, satisfy the OIDC spec with a 200 OK.
	if r.URL.Query().Get("state") != "" || r.Header.Get("Sec-Fetch-Dest") == "iframe" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
		return
	}

	// MANUAL CLICK FALLBACK:
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

// adminSignInUnavailable is what the browser sees when the console cannot start its sign-in.
const adminSignInUnavailable = "The administrative sign-in is not available right now. Please contact the operator of this server."

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

	// 2. The pending session binds this sign-in to this browser: only a browser holding its cookie can complete the
	// callback. The admin console signs in to the administrative partition.
	partition, err := h.storagePort.GetPartitionByAlias(r.Context(), tenant.ID, model.AdminPartitionAliasName)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "failed to resolve the administrative partition")
		return
	}
	flow, err := h.ssoUseCase.StartFlow(r.Context(), port.StartFlowCommand{
		TenantID:    tenant.ID,
		PartitionID: partition.ID,
		Cookies:     requestCookies(r),
		RequestHost: r.Host,
	})
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "failed to start the administrative sign-in")
		return
	}

	// 3. Trigger our clean data-driven administrative logon usecase that coordinates dynamic DCR setup on-demand
	response, err := h.adminLogonUseCase.InitiateAdminLogon(r.Context(), tenant.ID, flow.Session.ID, redirectURI, tenantBaseURI+port.RouteAdmin)
	if err != nil {
		// The reason (a missing, disabled or misplaced admin-sso provider, an unreachable admin tenant) is for the
		// operator's log, not for the browser.
		slog.Error("admin sign-in could not be started", "tenant_id", tenant.ID, "err", err)
		h.renderError(w, r, http.StatusInternalServerError, adminSignInUnavailable)
		return
	}

	// 4. Hand the browser the cookie of its pending session, if it did not already have one
	if flow.Cookie != nil {
		writeSessionCookie(w, flow.Cookie)
	}

	// 5. Direct browser outbound leg to the intent URL generated by the core service
	http.Redirect(w, r, response.TargetRedirectURL, http.StatusFound)
}

func (h *HttpAdapter) renderError(w http.ResponseWriter, r *http.Request, status int, errorMessage string) {
	slog.Error("Rendering admin visual error page", "status", status, "error", errorMessage, "path", r.URL.Path)
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	w.WriteHeader(status)
	component := public.Error(errorMessage)
	_ = component.Render(r.Context(), w)
}

// revokeAdminSession ends the server-side session behind the administrative cookie, when there is one, and returns
// the cookie name and Secure flag to evict. The name comes from the domain, so it carries the __Host- prefix in
// production; the local name is the fallback when the tenant or partition cannot be resolved.
func (h *AdminHandler) revokeAdminSession(r *http.Request) (string, bool) {
	cookieName, isSecure := sessionCookiePrefix+model.AdminPartitionAliasName, h.appEnv != "local"

	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		return cookieName, isSecure
	}
	partition, err := h.storagePort.GetPartitionByAlias(r.Context(), tenant.ID, model.AdminPartitionAliasName)
	if err != nil {
		return cookieName, isSecure
	}
	spec, err := sessionCookieName(r, h.ssoUseCase, tenant.ID, partition.ID)
	if err != nil {
		return cookieName, isSecure
	}
	cookieName, isSecure = spec.CookieName, spec.Secure

	if session := sessionFromCookie(r, h.ssoUseCase, tenant.ID, cookieName); session != nil {
		if err := h.ssoUseCase.RevokeSession(r.Context(), tenant.ID, session.ID); err != nil {
			slog.Error("admin logout: failed to revoke the session", "session_id", session.ID, "err", err)
		}
	}
	return cookieName, isSecure
}
