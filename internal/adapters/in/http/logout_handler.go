package http

import (
	"net/http"
	"strings"

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

	// 1. Calculate the exact standard public consumer fallback cookie name spec
	defaultSpec, _ := h.ssoUseCase.BuildSessionCookie(r.Context(), port.CookieIntentCommand{
		TenantID:       tenantUUID,
		LifecycleStage: "clear",
		RequestHost:    r.Host,
	})

	var activeSessionPayload string
	var targetCookieToEvict string
	var targetCookieIsSecure bool

	// 2. PASS 1: Prioritize parsing custom partitions (e.g., sprezz_admin or other partitions) over the default fallback
	for _, cookie := range r.Cookies() {
		// Skip any cookies that don't match the expected session cookie prefix
		if !strings.HasPrefix(cookie.Name, "spz_session_") {
			continue
		}
		// Skip the default cookie name to find any custom partition cookies in the first pass
		if cookie.Name == defaultSpec.CookieName {
			continue
		}

		stage, payload, parseErr := h.ssoUseCase.ParseSessionCookie(r.Context(), cookie.Value)
		if parseErr == nil && stage == "bearer" {
			activeSessionPayload = payload
			targetCookieToEvict = cookie.Name // TARGET FOUND: Lock eviction to this specific custom partition key
			targetCookieIsSecure = cookie.Secure
			break
		}
	}

	// 3. PASS 2: Fall back to parsing the default partition session if no custom partitions matched
	if activeSessionPayload == "" {
		if defaultCookie, err := r.Cookie(defaultSpec.CookieName); err == nil && defaultCookie.Value != "" {
			stage, payload, parseErr := h.ssoUseCase.ParseSessionCookie(r.Context(), defaultCookie.Value)
			if parseErr == nil && stage == "bearer" {
				activeSessionPayload = payload
				targetCookieToEvict = defaultSpec.CookieName // TARGET FOUND: Lock eviction strictly to the default fallback key
				targetCookieIsSecure = defaultCookie.Secure
			}
		}
	}

	// 4. Map transport data parameters into the Port Command envelope object
	cmd := port.LogoutRequestCommand{
		TenantID:              tenantUUID,
		ActiveSessionID:       activeSessionPayload,
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
