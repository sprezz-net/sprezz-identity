package http

import (
	"context"
	"net/http"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type AuthorizeHandler struct {
	authUseCase port.AuthUseCase
	ssoUseCase  port.SSOSessionUseCase
}

func NewAuthorizeHandler(auc port.AuthUseCase, suc port.SSOSessionUseCase) *AuthorizeHandler {
	return &AuthorizeHandler{
		authUseCase: auc,
		ssoUseCase:  suc,
	}
}

func (h *AuthorizeHandler) Routes(r chi.Router) {
	r.Get("/oauth/authorize", h.HandleAuthorize)
	r.Post("/oauth/authorize", h.HandleAuthorize)
}

func (h *AuthorizeHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.writeWebPlainError(w, http.StatusBadRequest, "invalid_request", "malformed form parameters")
		return
	}

	tenantUUID := h.mustResolveTenant(r.Context())

	// 1. Scan for an active namespaced session cookie using pure port orchestration
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

	var scopes []string
	if scopeFormVal := r.FormValue("scope"); scopeFormVal != "" {
		scopes = strings.Fields(scopeFormVal)
	}

	// 2. Map transport layer parameters into the pure driving port command object
	cmd := port.AuthorizeRequestCommand{
		TenantID:        tenantUUID,
		ClientID:        r.FormValue("client_id"),
		RedirectURI:     r.FormValue("redirect_uri"),
		CodeChallenge:   r.FormValue("code_challenge"),
		ChallengeMethod: r.FormValue("code_challenge_method"),
		IDPHint:         r.FormValue("idp_hint"),
		State:           r.FormValue("state"),
		Nonce:           r.FormValue("nonce"),
		ACRValues:       r.FormValue("acr_values"),
		ClaimsJSON:      r.FormValue("claims"),
		RequestURI:      r.FormValue("request_uri"), // When PAR is used
		Scopes:          scopes,
		ActiveSessionID: activeSessionPayload,
		RequestHost:     r.Host,
	}

	// 3. Pure Delegation: Run validations and lifecycle states inside the core use case
	result, err := h.authUseCase.ProcessAuthorizeRequest(r.Context(), cmd)
	if err != nil {
		h.writeWebPlainError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// 4. Apply side-effects explicitly dictated by the domain outcome
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

	http.Redirect(w, r, result.RedirectURL, http.StatusFound)
}

func (h *AuthorizeHandler) mustResolveTenant(ctx context.Context) uuid.UUID {
	if val := ctx.Value(tenantIDCtxKey); val != nil {
		if uid, ok := val.(uuid.UUID); ok {
			return uid
		}
	}
	return uuid.Nil
}

func (h *AuthorizeHandler) writeWebPlainError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypePlainText)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(code + ": " + desc))
}
