package http

import (
	"context"
	"fmt"
	"net/http"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type CallbackHandler struct {
	federatedUseCase port.FederatedLoginUseCase
	authUseCase      port.AuthUseCase
	ssoUseCase       port.SSOSessionUseCase
}

func NewCallbackHandler(fuc port.FederatedLoginUseCase, auc port.AuthUseCase, suc port.SSOSessionUseCase) *CallbackHandler {
	return &CallbackHandler{
		federatedUseCase: fuc,
		authUseCase:      auc,
		ssoUseCase:       suc,
	}
}

// Routes registers both the inbound local application and outbound federation callback vectors.
func (h *CallbackHandler) Routes(r chi.Router) {
	r.Get(port.RouteCallback, h.HandleOAuthCallbackRequest)
	r.Get(port.RouteFederationCallback, h.HandleFederationCallback)
}

// HandleFederationCallback processes incoming responses from upstream external Identity Providers (egress loop).
func (h *CallbackHandler) HandleFederationCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	tenantUUID := h.mustResolveTenant(r.Context())

	if state == "" || code == "" {
		h.writeWebError(w, http.StatusBadRequest, "invalid_request", "mandatory federation transaction query variables missing")
		return
	}

	cmd := port.FederatedCallbackCommand{
		TenantID:      tenantUUID,
		IncomingState: state,
		IncomingCode:  code,
		SessionID:     uuid.NewString(),
		RequestURL:    r.URL.String(),
		HTTPMethod:    r.Method,
	}

	response, err := h.federatedUseCase.ExecuteFederatedCallback(r.Context(), cmd)
	if err != nil {
		h.writeWebError(w, http.StatusForbidden, "access_denied", err.Error())
		return
	}

	intent, err := h.ssoUseCase.BuildSessionCookie(r.Context(), port.CookieIntentCommand{
		TenantID:       tenantUUID,
		PartitionID:    response.PartitionID,
		PayloadValue:   fmt.Sprintf("%s:%d", response.UpstreamAccessToken, response.PartitionID),
		LifecycleStage: "bearer",
		RequestHost:    r.Host,
	})
	if err != nil {
		h.writeWebError(w, http.StatusInternalServerError, "server_error", "failed to structure authorization session cookie")
		return
	}

	h.applyCookieIntent(w, intent)
	h.clearTransientHandshakeCookie(w)

	redirectTarget := response.TargetLandingURI
	if redirectTarget == "" {
		redirectTarget = "/"
	}

	if r.Header.Get("HX-Request") != "" {
		w.Header().Set("HX-Redirect", redirectTarget)
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, redirectTarget, http.StatusFound)
}

// HandleOAuthCallbackRequest processes the internal redirection loop for local web portal applications (ingress loop).
func (h *CallbackHandler) HandleOAuthCallbackRequest(w http.ResponseWriter, r *http.Request) {
	tenantUUID := h.mustResolveTenant(r.Context())

	cookie, err := r.Cookie("spz_auth_session_id")
	if err != nil || cookie.Value == "" {
		h.writeWebError(w, http.StatusBadRequest, "invalid_request", "transient handshake interaction session tracker missing")
		return
	}

	sessionUUID, err := uuid.Parse(cookie.Value)
	if err != nil {
		h.writeWebError(w, http.StatusBadRequest, "invalid_request", "malformed handshake token value format")
		return
	}

	// Leverage ssoUseCase strictly as a lookup tool to resolve the namespaced cookie name config
	cookieSpec, err := h.ssoUseCase.BuildSessionCookie(r.Context(), port.CookieIntentCommand{
		TenantID:       tenantUUID,
		LifecycleStage: "clear",
		RequestHost:    r.Host,
	})

	var activeSessionPayload string
	if err == nil {
		if ssoCookie, ssoErr := r.Cookie(cookieSpec.CookieName); ssoErr == nil {
			stage, payload, parseErr := h.ssoUseCase.ParseSessionCookie(r.Context(), ssoCookie.Value)
			if parseErr == nil && stage == "bearer" {
				activeSessionPayload = payload
			}
		}
	}

	if activeSessionPayload == "" {
		h.writeWebError(w, http.StatusUnauthorized, "access_denied", "no authenticated session exists for this partition loop")
		return
	}

	cmd := port.AuthorizeRequestCommand{
		TenantID:        tenantUUID,
		ActiveSessionID: activeSessionPayload,
		State:           r.URL.Query().Get("state"),
		RequestHost:     r.Host,
		RequestURI:      "urn:ietf:params:oauth:request_uri:" + sessionUUID.String(),
	}

	result, err := h.authUseCase.ProcessAuthorizeRequest(r.Context(), cmd)
	if err != nil {
		h.writeWebError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Clear out the handshake identifier; the active SSO session cookie remains valid and untouched
	h.clearTransientHandshakeCookie(w)

	if r.Header.Get("HX-Request") != "" {
		w.Header().Set("HX-Redirect", result.RedirectURL)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Authenticated"))
		return
	}

	http.Redirect(w, r, result.RedirectURL, http.StatusFound)
}

func (h *CallbackHandler) mustResolveTenant(ctx context.Context) uuid.UUID {
	if val := ctx.Value(tenantIDCtxKey); val != nil {
		if uid, ok := val.(uuid.UUID); ok {
			return uid
		}
	}
	return uuid.Nil
}

func (h *CallbackHandler) applyCookieIntent(w http.ResponseWriter, intent *port.CookieIntentResponse) {
	http.SetCookie(w, &http.Cookie{
		Name:     intent.CookieName,
		Value:    intent.CookieValue,
		Path:     "/",
		MaxAge:   intent.MaxAge,
		HttpOnly: true,
		Secure:   intent.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *CallbackHandler) clearTransientHandshakeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "spz_auth_session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *CallbackHandler) writeWebError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set(model.HeaderContentType, "text/plain")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "%s: %s", code, desc)
}
