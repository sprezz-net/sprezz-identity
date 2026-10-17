package http

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/public"

	"github.com/go-chi/chi/v5"
)

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
	r.Get(port.RouteWebSignUp, h.HandleSignUpForm)
	r.Post(port.RouteWebSignUp, h.HandleSignUpSubmit)
}

func (h *SignupHandler) HandleSignUpForm(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		http.Error(w, port.ErrTenantNotFound.Error(), http.StatusBadRequest)
		return
	}

	tx := r.URL.Query().Get("tx")
	ctxResp, _, result := h.bindSignup(w, r, tenant, tx, true)
	if result != flowOK {
		h.refuseSignup(w, r, tenant, ctxResp, result)
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	component := public.SignUp(make(map[string]string), ctxResp.Provider, "", "", "", tx)
	_ = component.Render(r.Context(), w)
}

// bindSignup loads the signup context and checks that the browser owns the sign-in it belongs to.
func (h *SignupHandler) bindSignup(w http.ResponseWriter, r *http.Request, tenant *model.Tenant, tx string, mayStart bool) (*port.SignupContextResponse, *model.SSOSession, flowResult) {
	ctxResp, err := h.registrationUseCase.GetSignupContext(r.Context(), port.GetSignupContextCommand{
		TenantID:       tenant.ID,
		InteractionID:  tx,
		ConsumeSession: false,
	})
	if err != nil || ctxResp.Provider == nil {
		return nil, nil, flowRefused
	}
	// A ?tx= that names no live interaction is an expired sign-in, not a direct visit.
	if tx != "" && ctxResp.InteractionSession == nil {
		return nil, nil, flowRefused
	}

	session, result := resolveFlow(w, r, h.ssoUseCase, tenant.ID, ctxResp.InteractionSession, directPartitionOf(tenant), mayStart)
	return ctxResp, session, result
}

// refuseSignup answers a signup page or submit that does not belong to the browser's flow.
func (h *SignupHandler) refuseSignup(w http.ResponseWriter, r *http.Request, tenant *model.Tenant, ctxResp *port.SignupContextResponse, result flowResult) {
	if result == flowSignedIn && ctxResp != nil {
		http.Redirect(w, r, signedInRedirectURL(tenant, ctxResp.InteractionSession), http.StatusFound)
		return
	}
	if ctxResp == nil {
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusForbidden)
		_ = public.Error("Self-service signup is not configured, enabled for this partition, or this sign-in is no longer valid").Render(r.Context(), w)
		return
	}
	renderFlowRefused(w, r)
}

func (h *SignupHandler) HandleSignUpSubmit(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(port.ErrTenantNotFound.Error()))
		return
	}

	tx := r.FormValue("tx")
	ctxResp, session, result := h.bindSignup(w, r, tenant, tx, false)
	switch result {
	case flowRefused:
		if ctxResp != nil {
			h.renderInlineFormError(w, r, ctxResp.Provider, tx, map[string]string{"global": flowMessageRefused})
			return
		}
		h.refuseSignup(w, r, tenant, nil, result)
		return
	case flowSignedIn:
		w.Header().Set(model.HeaderHxRedirect, signedInRedirectURL(tenant, ctxResp.InteractionSession))
		w.WriteHeader(http.StatusOK)
		return
	case flowOK:
	}
	provider := ctxResp.Provider

	if err := r.ParseForm(); err != nil {
		// Wraps input error into a structured map dictionary context envelope
		h.renderInlineFormError(w, r, provider, tx, map[string]string{"global": "Malformed sign-up payload parameters submitted"})
		return
	}

	fullName := r.FormValue("name")
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if password != confirmPassword {
		// Maps targeted confirmation failures straight onto the appropriate element key
		h.renderInlineFormError(w, r, provider, tx, map[string]string{"confirm_password": "Passwords provided do not match"})
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

	newProfile, err := h.registrationUseCase.RegisterUser(r.Context(), port.RegisterUserCommand{
		TenantID:   tenant.ID,
		ProviderID: provider.ID,
		FirstName:  firstName,
		LastName:   lastName,
		Username:   username,
		Email:      email,
		Password:   password,
	})
	if err != nil {
		// Dynamic type assertion intercepts our structured field validation envelope smoothly
		var valErr *port.ValidationError
		if errors.As(err, &valErr) {
			h.renderInlineFormError(w, r, provider, tx, valErr.Fields)
			return
		}
		slog.Error("Self-service registration submission failed", "error", err, "tenant_id", tenant.ID, "username", username)
		// Fallback for flat database errors or unique constraint blocks and wrap into a structured dictionary
		h.renderInlineFormError(w, r, provider, tx, map[string]string{"global": err.Error()})
		return
	}

	// Signing up signs in: the pending session of this flow is promoted, with a fresh secret.
	created, err := h.ssoUseCase.PromoteSession(r.Context(), port.PromoteSessionCommand{
		TenantID:           tenant.ID,
		SessionID:          session.ID,
		PartitionID:        session.PartitionID,
		UserProfileID:      newProfile.ID,
		IdentityProviderID: provider.ID,
		RequestHost:        r.Host,
	})
	if err != nil {
		slog.Error("Self-service registration: failed to promote the session", "error", err, "tenant_id", tenant.ID)
		h.renderInlineFormError(w, r, provider, tx, map[string]string{"global": "Your account was created, but we could not sign you in. Please sign in."})
		return
	}
	writeSessionCookie(w, &created.Cookie)

	targetURL := h.resolveSignUpRedirectURL(r, tenant, tx)
	w.Header().Set(model.HeaderHxRedirect, targetURL)
	w.WriteHeader(http.StatusOK)
}

func (h *SignupHandler) renderInlineFormError(w http.ResponseWriter, r *http.Request, provider *model.IdentityProvider, interactionID string, fieldErrors map[string]string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)

	// Clean 200 OK means standard out-of-the-box HTMX swaps execute instantly
	w.WriteHeader(http.StatusOK)

	// Render ONLY the inner form template block to prevent duplicate nesting loops
	component := public.SignUpForm(fieldErrors, provider, r.FormValue("email"), r.FormValue("username"), r.FormValue("name"), interactionID)
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
			return reconstructAuthorizeURL(ctxResp.InteractionSession)
		}
	}

	return tenant.Config.DefaultRedirectURI
}
