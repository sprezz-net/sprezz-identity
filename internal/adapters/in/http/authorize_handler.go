package http

import (
	"net/http"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/go-chi/chi/v5"
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
	r.Get(port.RouteAuthorize, h.HandleAuthorize)
	r.Post(port.RouteAuthorize, h.HandleAuthorize)
}

func (h *AuthorizeHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.writeWebPlainError(w, http.StatusBadRequest, "invalid_request", "malformed form parameters")
		return
	}

	tenantUUID := TenantIDFromContext(r.Context())

	var scopes []string
	if scopeFormVal := r.FormValue("scope"); scopeFormVal != "" {
		scopes = strings.Fields(scopeFormVal)
	}

	// 1. Map transport layer parameters into the pure driving port command object
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
		Cookies:         requestCookies(r), // the domain finds the session in the cookie of the client's partition
		RequestHost:     r.Host,
	}

	// 2. Pure Delegation: Run validations and lifecycle states inside the core use case
	result, err := h.authUseCase.ProcessAuthorizeRequest(r.Context(), cmd)
	if err != nil {
		h.writeWebPlainError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// 3. Apply side-effects explicitly dictated by the domain outcome
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

func (h *AuthorizeHandler) writeWebPlainError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypePlainText)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(code + ": " + desc))
}
