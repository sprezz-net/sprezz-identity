package http

import (
	"errors"
	"net/http"
	"net/url"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/views"

	"github.com/google/uuid"
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

func (h *HttpAdapter) processSignUpRegistration(r *http.Request, tenant *model.Tenant, provider *model.IdentityProvider) (*model.UserProfile, error) {
	name := r.FormValue("name")
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if password != confirmPassword {
		return nil, errors.New("passwords do not match")
	}

	// In email-as-username mode, copy email to username
	if provider.Config.UsernameField == "email" {
		username = email
	}

	// Trigger domain registration service logic
	return h.signupService.RegisterUser(r.Context(), tenant.ID, name, username, email, password)
}

func (h *HttpAdapter) resolveSignUpRedirectURL(r *http.Request, tenant *model.Tenant) string {
	targetURL := r.FormValue("redirect_uri")
	if targetURL == "" {
		if cookie, err := r.Cookie("spz_auth_session_id"); err == nil && cookie.Value != "" {
			if sessionUUID, parseErr := uuid.Parse(cookie.Value); parseErr == nil {
				if session, loadErr := h.storagePort.GetAndConsumeInteractionSession(r.Context(), tenant.ID, sessionUUID); loadErr == nil {
					// Reconstruct the /oauth/authorize redirect URL with all preserved parameters!
					targetURL = routeAuthorize + "?client_id=" + url.QueryEscape(session.ClientID) + "&redirect_uri=" + url.QueryEscape(session.RedirectURI)
					if session.CodeChallenge != "" {
						targetURL += "&code_challenge=" + url.QueryEscape(session.CodeChallenge)
					}
					if session.ChallengeMethod != "" {
						targetURL += "&code_challenge_method=" + url.QueryEscape(session.ChallengeMethod)
					}
					if session.IDPHint != "" {
						targetURL += "&idp_hint=" + url.QueryEscape(session.IDPHint)
					}
					if session.State != "" {
						targetURL += "&state=" + url.QueryEscape(session.State)
					}
					if session.Nonce != "" {
						targetURL += "&nonce=" + url.QueryEscape(session.Nonce)
					}
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

	profile, err := h.processSignUpRegistration(r, tenant, provider)
	if err != nil {
		w.Header().Set(contentTypeHeader, contentTypeHtml)
		w.WriteHeader(http.StatusOK) // Return HTML back to HTMX or browser with the error message rendered
		component := views.SignUp(err.Error(), provider, r.FormValue("email"), r.FormValue("username"), r.FormValue("name"))
		_ = component.Render(r.Context(), w)
		return
	}

	// Auto-login after successful registration!
	h.setSSOSessionCookie(w, ssoSession{
		SubjectID:  profile.ID.String(),
		ProviderID: provider.ID.String(),
		SessionID:  uuid.NewString(),
	})

	targetURL := h.resolveSignUpRedirectURL(r, tenant)
	w.Header().Set("HX-Redirect", targetURL)
	http.Redirect(w, r, targetURL, http.StatusSeeOther)
}
