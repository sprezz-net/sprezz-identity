package http

import (
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

	name := r.FormValue("name")
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	renderErr := func(msg string) {
		w.Header().Set(contentTypeHeader, contentTypeHtml)
		w.WriteHeader(http.StatusOK) // Return HTML back to HTMX or browser with the error message rendered
		component := views.SignUp(msg, provider, email, username, name)
		_ = component.Render(r.Context(), w)
	}

	if password != confirmPassword {
		renderErr("Passwords do not match")
		return
	}

	// In email-as-username mode, copy email to username
	if provider.Config.UsernameField == "email" {
		username = email
	}

	// Trigger domain registration service logic
	_, err = h.signupService.RegisterUser(r.Context(), tenant.ID, name, username, email, password)
	if err != nil {
		renderErr(err.Error())
		return
	}

	// Resolve targetURL
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

	w.Header().Set("HX-Redirect", targetURL)
	http.Redirect(w, r, targetURL, http.StatusSeeOther)
}
