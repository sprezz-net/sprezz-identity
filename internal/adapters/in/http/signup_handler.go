package http

import (
	"errors"
	"net/http"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/views"

	"github.com/google/uuid"
)

const (
	contentTypeHtml = "text/html; charset=utf-8"
)

func (h *HttpAdapter) signUpForm(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		http.Error(w, errTenantNotResolved, http.StatusBadRequest)
		return
	}

	provider, err := h.storagePort.GetIdentityProviderByType(r.Context(), tenant.ID, model.UsernamePasswordIDPType)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Self-service signup is not configured/enabled for this tenant"))
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	component := views.SignUp("", provider, "", "", "")
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) processSignUpRegistration(r *http.Request, tenant *model.Tenant, provider *model.IdentityProvider) error {
	name := r.FormValue("name")
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if password != confirmPassword {
		return errors.New("passwords do not match")
	}

	// In email-as-username mode, copy email to username
	if provider.Config.UsernameField == "email" {
		username = email
	}

	// Trigger domain registration service logic
	_, err := h.signupService.RegisterUser(r.Context(), tenant.ID, name, username, email, password)
	return err
}

func (h *HttpAdapter) resolveSignUpRedirectURL(r *http.Request, tenant *model.Tenant) string {
	targetURL := r.FormValue("redirect_uri")
	if targetURL == "" {
		if cookie, err := r.Cookie("spz_auth_session_id"); err == nil && cookie.Value != "" {
			if sessionUUID, parseErr := uuid.Parse(cookie.Value); parseErr == nil {
				if session, loadErr := h.storagePort.GetAndConsumeInteractionSession(r.Context(), tenant.ID, sessionUUID); loadErr == nil {
					targetURL = session.RedirectURI
				}
			}
		}
	}

	if targetURL == "" {
		targetURL = tenant.Config.DefaultRedirectURI
	}
	return targetURL
}

func (h *HttpAdapter) signUpSubmit(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(errTenantNotResolved))
		return
	}

	provider, err := h.storagePort.GetIdentityProviderByType(r.Context(), tenant.ID, model.UsernamePasswordIDPType)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Self-service signup is not configured/enabled for this tenant"))
		return
	}

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("malformed sign-up payload"))
		return
	}

	if err := h.processSignUpRegistration(r, tenant, provider); err != nil {
		w.Header().Set(contentTypeHeader, contentTypeHtml)
		w.WriteHeader(http.StatusOK) // Return HTML back to HTMX or browser with the error message rendered
		component := views.SignUp(err.Error(), provider, r.FormValue("email"), r.FormValue("username"), r.FormValue("name"))
		_ = component.Render(r.Context(), w)
		return
	}

	targetURL := h.resolveSignUpRedirectURL(r, tenant)
	w.Header().Set("HX-Redirect", targetURL)
	http.Redirect(w, r, targetURL, http.StatusSeeOther)
}
