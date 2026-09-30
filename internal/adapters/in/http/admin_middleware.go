package http

import (
	"context"
	"log/slog"
	"net/http"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

// requireAdminSession guards every /admin route behind a verified administrator session and rejects
// cross-site state changes. The front-channel logout route is registered outside of this guard.
func (h *HttpAdapter) requireAdminSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := TenantFromContext(r.Context())
		if !ok {
			h.renderError(w, r, http.StatusBadRequest, port.ErrTenantNotFound.Error())
			return
		}

		// Administrative pages show privileged, per-user data and must never be cached.
		w.Header().Set("Cache-Control", "no-store")

		if isCrossSiteStateChange(r) {
			slog.Warn("admin request rejected: cross-site state change", "path", r.URL.Path, "method", r.Method)
			h.renderError(w, r, http.StatusForbidden, "cross-site requests are not permitted")
			return
		}

		result, err := h.resolveAdminSession(r, tenant)
		if err != nil {
			slog.Error("admin session resolution failed", "path", r.URL.Path, "err", err)
			h.renderError(w, r, http.StatusInternalServerError, "unable to verify the administrative session")
			return
		}

		switch result.state {
		case adminSessionValid:
			ctx := context.WithValue(r.Context(), AdminSessionContextKey, result.session)
			next.ServeHTTP(w, r.WithContext(ctx))
		case adminSessionDenied:
			h.clearAdminCookie(w, result.cookieName)
			h.renderError(w, r, http.StatusForbidden, "this account is not permitted to use the administrative console")
		default:
			h.rejectUnauthenticatedAdmin(w, r, result.cookieName)
		}
	})
}

// rejectUnauthenticatedAdmin answers a request that carries no valid administrator session.
// Browser navigations start the OIDC login, HTMX requests are redirected with a full-page navigation,
// and every other request receives a plain 401.
func (h *HttpAdapter) rejectUnauthenticatedAdmin(w http.ResponseWriter, r *http.Request, staleCookie string) {
	h.clearAdminCookie(w, staleCookie)

	if r.Header.Get(model.HeaderHxRequest) == "true" {
		w.Header().Set(model.HeaderHxRedirect, port.RouteAdmin)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		h.initiateAdminOIDC(w, r)
		return
	}

	h.renderError(w, r, http.StatusUnauthorized, "authentication is required")
}

func (h *HttpAdapter) clearAdminCookie(w http.ResponseWriter, cookieName string) {
	if cookieName == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.appEnv != "local",
		SameSite: http.SameSiteLaxMode,
	})
}
