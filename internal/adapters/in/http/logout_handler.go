package http

import (
	"context"
	"net/http"

	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/public"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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
	r.Get("/oauth/logout", h.HandleLogoutRequest)
	r.Get("/logout", h.HandleLogoutRequest)
}

func (h *LogoutHandler) HandleLogoutRequest(w http.ResponseWriter, r *http.Request) {
	tenantUUID := h.mustResolveTenant(r.Context())

	// 1. Harvest active bearer session contexts from namespaced cookies via port contracts
	var activeSessionPayload string
	cookieSpec, err := h.ssoUseCase.BuildSessionCookie(r.Context(), port.CookieIntentCommand{
		TenantID:       tenantUUID,
		LifecycleStage: "clear",
		RequestHost:    r.Host,
	})
	if err == nil {
		if cookie, cookieErr := r.Cookie(cookieSpec.CookieName); cookieErr == nil {
			stage, payload, parseErr := h.ssoUseCase.ParseSessionCookie(r.Context(), cookie.Value)
			if parseErr == nil && stage == "bearer" {
				activeSessionPayload = payload
			}
		}
	}

	// 2. Map transport query values straight into the pure Port Command envelope object
	// We capture the optional id_token_hint from the query string for the OIDC spec path
	cmd := port.LogoutRequestCommand{
		TenantID:              tenantUUID,
		ActiveSessionID:       activeSessionPayload,
		IDTokenHint:           r.URL.Query().Get("id_token_hint"),
		PostLogoutRedirectURI: r.URL.Query().Get("post_logout_redirect_uri"),
		State:                 r.URL.Query().Get("state"),
		RequestHost:           r.Host,
	}

	// 3. Pure Corporate Delegation: Fire use case execution across the driving perimeter
	result, err := h.authUseCase.ProcessLogoutRequest(r.Context(), cmd)
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = public.Error(err.Error()).Render(r.Context(), w)
		return
	}

	// 4. Enforce cookie eviction parameters explicitly dictated by domain service calculation
	if result.HasCookieIntent {
		http.SetCookie(w, &http.Cookie{
			Name:     result.CookieName,
			Value:    result.CookieValue,
			Path:     "/",
			MaxAge:   result.CookieMaxAge,
			HttpOnly: true,
			Secure:   result.CookieSecure,
			SameSite: http.SameSiteLaxMode,
		})
	}

	// 5. Spec Compliance Section 7.1: If front-channel iframe URIs exist, render a hidden frame block page
	if len(result.FrontChannelLogoutURIs) > 0 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		component := public.Logout(result.FrontChannelLogoutURIs, result.PostLogoutRedirectURI)
		_ = component.Render(r.Context(), w)
		return
	}

	// Default fallback to direct redirection if zero front-channel apps are listening
	http.Redirect(w, r, result.PostLogoutRedirectURI, http.StatusFound)
}

func (h *LogoutHandler) mustResolveTenant(ctx context.Context) uuid.UUID {
	if val := ctx.Value(tenantIDCtxKey); val != nil {
		if uid, ok := val.(uuid.UUID); ok {
			return uid
		}
	}
	return uuid.Nil
}
