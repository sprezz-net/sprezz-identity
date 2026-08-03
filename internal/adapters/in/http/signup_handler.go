package http

import (
	"net/http"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/views"
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

	// Check if we have an original authorization context redirect
	redirectURL := "/login?registered=true"
	w.Header().Set("HX-Redirect", redirectURL)
	w.WriteHeader(http.StatusSeeOther)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}
