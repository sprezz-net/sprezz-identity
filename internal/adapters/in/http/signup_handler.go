package http

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/public"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const routeAuthorize = "/oauth/authorize"

type SignupHandler struct {
	registrationUseCase port.UserRegistrationUseCase
	ssoUseCase          port.SSOSessionUseCase
}

func NewSignupHandler(ruc port.UserRegistrationUseCase, suc port.SSOSessionUseCase) *SignupHandler {
	return &SignupHandler{
		registrationUseCase: ruc,
		ssoUseCase:          suc,
	}
}

func (h *SignupHandler) Routes(r chi.Router) {
	r.Get("/signup", h.HandleSignUpForm)
	r.Post("/signup", h.HandleSignUpSubmit)
}

func (h *SignupHandler) HandleSignUpForm(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		http.Error(w, errTenantNotResolved, http.StatusBadRequest)
		return
	}

	interactionID := h.parseInteractionCookie(r, tenant.ID)

	ctxResp, err := h.registrationUseCase.GetSignupContext(r.Context(), port.GetSignupContextCommand{
		TenantID:       tenant.ID,
		InteractionID:  interactionID,
		ConsumeSession: false,
	})
	if err != nil || ctxResp.Provider == nil {
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusForbidden)
		_ = public.Error("Self-service signup is not configured or enabled for this partition").Render(r.Context(), w)
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	component := public.SignUp("", ctxResp.Provider, "", "", "")
	_ = component.Render(r.Context(), w)
}

func (h *SignupHandler) HandleSignUpSubmit(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(errTenantNotResolved))
		return
	}

	interactionID := h.parseInteractionCookie(r, tenant.ID)

	ctxResp, err := h.registrationUseCase.GetSignupContext(r.Context(), port.GetSignupContextCommand{
		TenantID:       tenant.ID,
		InteractionID:  interactionID,
		ConsumeSession: false,
	})
	if err != nil || ctxResp.Provider == nil {
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusForbidden)
		_ = public.Error("Self-service signup is not configured or enabled for this partition").Render(r.Context(), w)
		return
	}
	provider := ctxResp.Provider

	if err := r.ParseForm(); err != nil {
		h.renderInlineFormError(w, r, provider, "Malformed sign-up payload parameters submitted")
		return
	}

	fullName := r.FormValue("name")
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if password != confirmPassword {
		h.renderInlineFormError(w, r, provider, "Passwords provided do not match")
		return
	}

	nameParts := strings.Fields(fullName)
	var firstName, lastName string
	if len(nameParts) > 0 {
		firstName = nameParts[0]
	}
	if len(nameParts) > 1 {
		lastName = strings.Join(nameParts[1:], " ")
	}

	profile, err := h.registrationUseCase.RegisterUser(r.Context(), port.RegisterUserCommand{
		TenantID:   tenant.ID,
		ProviderID: provider.ID,
		FirstName:  firstName,
		LastName:   lastName,
		Username:   username,
		Email:      email,
		Password:   password,
	})

	_ = profile // Avoid unused variable warning if not used further

	if err != nil {
		slog.Error("Self-service registration submission failed", "error", err, "tenant_id", tenant.ID, "username", username)
		h.renderInlineFormError(w, r, provider, err.Error())
		return
	}

	// 3. Delegate single sign-on cookie building completely to the use case port
	cookieIntent, err := h.ssoUseCase.BuildSessionCookie(r.Context(), port.CookieIntentCommand{
		TenantID:       tenant.ID,
		PartitionID:    provider.PartitionID,
		LifecycleStage: "bearer",
		RequestHost:    r.Host,
	})
	if err == nil {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieIntent.CookieName,
			Value:    cookieIntent.CookieValue,
			Path:     "/",
			MaxAge:   cookieIntent.MaxAge,
			HttpOnly: true,
			Secure:   cookieIntent.Secure,
			SameSite: http.SameSiteLaxMode,
		})
	}

	targetURL := h.resolveSignUpRedirectURL(r, tenant, interactionID)
	w.Header().Set("HX-Redirect", targetURL)
	w.WriteHeader(http.StatusOK)
}

func (h *SignupHandler) renderInlineFormError(w http.ResponseWriter, r *http.Request, provider *model.IdentityProvider, message string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	w.WriteHeader(http.StatusOK)
	component := public.SignUp(message, provider, r.FormValue("email"), r.FormValue("username"), r.FormValue("name"))
	_ = component.Render(r.Context(), w)
}

func (h *SignupHandler) resolveSignUpRedirectURL(r *http.Request, tenant *model.Tenant, interactionID string) string {
	targetURL := r.FormValue("redirect_uri")
	if targetURL != "" {
		return targetURL
	}

	if interactionID != "" {
		ctxResp, err := h.registrationUseCase.GetSignupContext(r.Context(), port.GetSignupContextCommand{
			TenantID:       tenant.ID,
			InteractionID:  interactionID,
			ConsumeSession: true,
		})
		if err == nil && ctxResp.InteractionSession != nil {
			return h.reconstructAuthorizeURL(ctxResp.InteractionSession)
		}
	}

	return tenant.Config.DefaultRedirectURI
}

func (h *SignupHandler) reconstructAuthorizeURL(session *model.InteractionSession) string {
	var sb strings.Builder
	sb.WriteString(routeAuthorize)
	sb.WriteString("?client_id=")
	sb.WriteString(url.QueryEscape(session.ClientID))
	sb.WriteString("&redirect_uri=")
	sb.WriteString(url.QueryEscape(session.RedirectURI))

	if session.CodeChallenge != "" {
		sb.WriteString("&code_challenge=")
		sb.WriteString(url.QueryEscape(session.CodeChallenge))
	}
	if session.ChallengeMethod != "" {
		sb.WriteString("&code_challenge_method=")
		sb.WriteString(url.QueryEscape(session.ChallengeMethod))
	}
	if session.IDPHint != "" {
		sb.WriteString("&idp_hint=")
		sb.WriteString(url.QueryEscape(session.IDPHint))
	}
	if session.State != "" {
		sb.WriteString("&state=")
		sb.WriteString(url.QueryEscape(session.State))
	}
	if session.Nonce != "" {
		sb.WriteString("&nonce=")
		sb.WriteString(url.QueryEscape(session.Nonce))
	}
	return sb.String()
}

func (h *SignupHandler) parseInteractionCookie(r *http.Request, tenantID uuid.UUID) string {
	cookieSpec, err := h.ssoUseCase.BuildSessionCookie(r.Context(), port.CookieIntentCommand{
		TenantID:       tenantID,
		LifecycleStage: "handshake",
		RequestHost:    r.Host,
	})
	if err != nil {
		return ""
	}

	cookie, err := r.Cookie(cookieSpec.CookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}

	_, payload, err := h.ssoUseCase.ParseSessionCookie(r.Context(), cookie.Value)
	if err != nil {
		return ""
	}

	return payload
}
