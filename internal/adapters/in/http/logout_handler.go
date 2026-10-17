package http

import (
	"net/http"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/public"

	"github.com/go-chi/chi/v5"
)

type LogoutHandler struct {
	authUseCase port.AuthUseCase
	ssoUseCase  port.SSOSessionUseCase
}

func NewLogoutHandler(auc port.AuthUseCase, suc port.SSOSessionUseCase) *LogoutHandler {
	return &LogoutHandler{
		authUseCase: auc,
		ssoUseCase:  suc,
	}
}

func (h *LogoutHandler) Routes(r chi.Router) {
	r.Get(port.RouteLogout, h.HandleLogoutRequest)
	r.Get(port.RouteWebLogout, h.HandleLogoutRequest)
}

func (h *LogoutHandler) HandleLogoutRequest(w http.ResponseWriter, r *http.Request) {
	tenantUUID := TenantIDFromContext(r.Context())

	// 1. Find the live session of this request: custom partitions (e.g. sprezz_admin) first, then the default one.
	// The cookie that carried it is the one to evict.
	var activeSession *model.SSOSession
	var targetCookieToEvict string
	var targetCookieIsSecure bool
	if found := anyPartitionSession(r, h.ssoUseCase, tenantUUID); found != nil {
		activeSession = found.session
		targetCookieToEvict = found.cookie.Name
		targetCookieIsSecure = found.cookie.Secure
	}

	// 4. Map transport data parameters into the Port Command envelope object
	cmd := port.LogoutRequestCommand{
		TenantID:              tenantUUID,
		ActiveSession:         activeSession,
		IDTokenHint:           r.URL.Query().Get("id_token_hint"),
		PostLogoutRedirectURI: r.URL.Query().Get("post_logout_redirect_uri"),
		State:                 r.URL.Query().Get("state"),
		RequestHost:           r.Host,
	}

	// 5. Fire use-case execution to mark this specific discovered session tracking ID as revoked server-side
	result, err := h.authUseCase.ProcessLogoutRequest(r.Context(), cmd)
	if err != nil {
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusBadRequest)
		_ = public.Error(err.Error()).Render(r.Context(), w)
		return
	}

	// 6. SURGICAL CONTEXT-TARGETED COOKIE EVICTION
	// We clear out the active session cookie calculated by the core domain if ProcessLogoutRequest dictates it,
	// OR we explicitly evict the target cookie identified during our prioritized scanning passes.
	cookieNameToKill := result.CookieName
	cookieIsSecure := result.CookieSecure
	if cookieNameToKill == "" {
		cookieNameToKill = targetCookieToEvict
		cookieIsSecure = targetCookieIsSecure
	}

	if cookieNameToKill != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieNameToKill,
			Value:    "",
			Path:     "/",
			MaxAge:   -1, // Forces immediate native browser-level erasure of only this specific target cookie
			HttpOnly: true,
			Secure:   cookieIsSecure,
			SameSite: http.SameSiteLaxMode,
		})
	}

	if result.PostLogoutRedirectURI == "" {
		result.PostLogoutRedirectURI = port.RouteWebLogin // Fallback to the login wall if no explicit redirect is provided
	}

	// 7. Spec Compliance Section 7.1: Handle front-channel iframe web cleanups if apps are bound
	if len(result.FrontChannelLogoutURIs) > 0 {
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusOK)

		component := public.Logout(result.FrontChannelLogoutURIs, result.PostLogoutRedirectURI)
		_ = component.Render(r.Context(), w)
		return
	}

	// 8. Hard immutable destination override straight back to the securely resolved endpoint
	http.Redirect(w, r, result.PostLogoutRedirectURI, http.StatusFound)
}
