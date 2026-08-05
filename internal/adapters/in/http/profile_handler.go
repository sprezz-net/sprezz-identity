package http

import (
	"net/http"
	"net/url"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/views/public"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	errNoPasswordIDP           = "A username-password identity provider is not coupled to your profile."
	errMalformedForm           = "Malformed form submission"
	redirectProfilePasswordErr = "/profile/password?err="
	redirectProfileEmailErr    = "/profile/email?err="
	redirectProfileNameErr     = "/profile/name?err="
	redirectProfileMsg         = "/profile?msg="
)

func (h *HttpAdapter) getActiveProvider(providers []model.IdentityProvider, providerID string) *model.IdentityProvider {
	for _, p := range providers {
		if p.ID.String() == providerID {
			return &p
		}
	}
	return nil
}

func (h *HttpAdapter) hasUsernamePasswordCoupled(identities []model.UserIdentity, providers []model.IdentityProvider) bool {
	for _, ident := range identities {
		for _, p := range providers {
			if p.ID == ident.IdentityProviderID && p.IDPType == model.UsernamePasswordIDPType {
				return true
			}
		}
	}
	return false
}

func (h *HttpAdapter) checkProfileAuth(w http.ResponseWriter, r *http.Request, requiredAAL int) (*model.Tenant, *model.UserProfile, []model.UserIdentity, []model.IdentityProvider, bool, bool) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, errTenantNotResolved)
		return nil, nil, nil, nil, false, false
	}

	sso := h.getSSOSessionCookie(r)
	if sso == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return nil, nil, nil, nil, false, false
	}

	userUUID, err := uuid.Parse(sso.SubjectID)
	if err != nil {
		h.clearSSOSessionCookie(w, r)
		http.Redirect(w, r, "/", http.StatusFound)
		return nil, nil, nil, nil, false, false
	}

	user, err := h.storagePort.GetUserProfileByID(r.Context(), tenant.ID, userUUID)
	if err != nil {
		h.clearSSOSessionCookie(w, r)
		http.Redirect(w, r, "/", http.StatusFound)
		return nil, nil, nil, nil, false, false
	}

	providers, err := h.idpService.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return nil, nil, nil, nil, false, false
	}

	activeProvider := h.getActiveProvider(providers, sso.ProviderID)
	if activeProvider == nil {
		h.clearSSOSessionCookie(w, r)
		http.Redirect(w, r, "/", http.StatusFound)
		return nil, nil, nil, nil, false, false
	}

	aal := activeProvider.Config.AAL
	if aal <= 0 {
		aal = 1
	}
	ial := activeProvider.Config.IAL
	if ial <= 0 {
		ial = 1
	}

	if aal < requiredAAL || ial < tenant.Config.GetDefaultIAL() {
		h.renderError(w, r, http.StatusForbidden, "Your authentication level is insufficient to access this page.")
		return nil, nil, nil, nil, false, false
	}

	identities, err := h.userProfileService.GetUserIdentities(r.Context(), userUUID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return nil, nil, nil, nil, false, false
	}

	hasPasswordIdp := h.hasUsernamePasswordCoupled(identities, providers)
	return tenant, user, identities, providers, hasPasswordIdp, true
}

func (h *HttpAdapter) profileDashboard(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, errTenantNotResolved)
		return
	}

	requiredAAL := tenant.Config.GetProfileAAL()
	_, user, identities, providers, hasPasswordIdp, ok := h.checkProfileAuth(w, r, requiredAAL)
	if !ok {
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	msg := r.URL.Query().Get("msg")
	errStr := r.URL.Query().Get("err")
	component := public.ProfileDashboard(*user, identities, providers, hasPasswordIdp, errStr, msg)
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) changePasswordForm(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, errTenantNotResolved)
		return
	}

	requiredAAL := tenant.Config.GetPasswordAAL()
	_, user, _, _, hasPasswordIdp, ok := h.checkProfileAuth(w, r, requiredAAL)
	if !ok {
		return
	}

	if !hasPasswordIdp {
		h.renderError(w, r, http.StatusForbidden, errNoPasswordIDP)
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	msg := r.URL.Query().Get("msg")
	errStr := r.URL.Query().Get("err")
	component := public.ChangePasswordPage(*user, errStr, msg)
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) changePasswordSubmit(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, errTenantNotResolved)
		return
	}

	requiredAAL := tenant.Config.GetPasswordAAL()
	_, user, _, _, hasPasswordIdp, ok := h.checkProfileAuth(w, r, requiredAAL)
	if !ok {
		return
	}

	if !hasPasswordIdp {
		h.renderError(w, r, http.StatusForbidden, errNoPasswordIDP)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, redirectProfilePasswordErr+url.QueryEscape(errMalformedForm), http.StatusFound)
		return
	}

	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	if currentPassword == "" || newPassword == "" || confirmPassword == "" {
		http.Redirect(w, r, redirectProfilePasswordErr+url.QueryEscape("All fields are required"), http.StatusFound)
		return
	}

	if newPassword != confirmPassword {
		http.Redirect(w, r, redirectProfilePasswordErr+url.QueryEscape("New passwords do not match"), http.StatusFound)
		return
	}

	if len(newPassword) < 8 {
		http.Redirect(w, r, redirectProfilePasswordErr+url.QueryEscape("New password must be at least 8 characters long"), http.StatusFound)
		return
	}

	err := h.idpService.ChangePassword(r.Context(), tenant.ID, user.ID, currentPassword, newPassword)
	if err != nil {
		http.Redirect(w, r, redirectProfilePasswordErr+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}

	http.Redirect(w, r, redirectProfileMsg+url.QueryEscape("Password updated successfully"), http.StatusFound)
}

func (h *HttpAdapter) changeEmailForm(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, errTenantNotResolved)
		return
	}

	requiredAAL := tenant.Config.GetEmailAAL()
	_, user, _, _, hasPasswordIdp, ok := h.checkProfileAuth(w, r, requiredAAL)
	if !ok {
		return
	}

	if !hasPasswordIdp {
		h.renderError(w, r, http.StatusForbidden, errNoPasswordIDP)
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	msg := r.URL.Query().Get("msg")
	errStr := r.URL.Query().Get("err")
	component := public.ChangeEmailPage(*user, errStr, msg)
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) changeEmailSubmit(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, errTenantNotResolved)
		return
	}

	requiredAAL := tenant.Config.GetEmailAAL()
	_, user, _, _, hasPasswordIdp, ok := h.checkProfileAuth(w, r, requiredAAL)
	if !ok {
		return
	}

	if !hasPasswordIdp {
		h.renderError(w, r, http.StatusForbidden, errNoPasswordIDP)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, redirectProfileEmailErr+url.QueryEscape(errMalformedForm), http.StatusFound)
		return
	}

	currentPassword := r.FormValue("current_password")
	newEmail := strings.TrimSpace(r.FormValue("new_email"))
	confirmEmail := strings.TrimSpace(r.FormValue("confirm_email"))

	if currentPassword == "" || newEmail == "" || confirmEmail == "" {
		http.Redirect(w, r, redirectProfileEmailErr+url.QueryEscape("All fields are required"), http.StatusFound)
		return
	}

	if newEmail != confirmEmail {
		http.Redirect(w, r, redirectProfileEmailErr+url.QueryEscape("New email addresses do not match"), http.StatusFound)
		return
	}

	valid, err := h.idpService.VerifyPassword(r.Context(), tenant.ID, user.ID, currentPassword)
	if err != nil || !valid {
		http.Redirect(w, r, redirectProfileEmailErr+url.QueryEscape("Invalid username or password"), http.StatusFound)
		return
	}

	err = h.userProfileService.ChangeEmail(r.Context(), tenant.ID, user.ID, newEmail)
	if err != nil {
		http.Redirect(w, r, redirectProfileEmailErr+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}

	http.Redirect(w, r, redirectProfileMsg+url.QueryEscape("Email updated successfully"), http.StatusFound)
}

func (h *HttpAdapter) changeNameForm(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, errTenantNotResolved)
		return
	}

	requiredAAL := tenant.Config.GetNameAAL()
	_, user, _, _, hasPasswordIdp, ok := h.checkProfileAuth(w, r, requiredAAL)
	if !ok {
		return
	}

	if !hasPasswordIdp {
		h.renderError(w, r, http.StatusForbidden, errNoPasswordIDP)
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHtml)
	msg := r.URL.Query().Get("msg")
	errStr := r.URL.Query().Get("err")
	component := public.ChangeNamePage(*user, errStr, msg)
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) changeNameSubmit(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, errTenantNotResolved)
		return
	}

	requiredAAL := tenant.Config.GetNameAAL()
	_, user, _, _, hasPasswordIdp, ok := h.checkProfileAuth(w, r, requiredAAL)
	if !ok {
		return
	}

	if !hasPasswordIdp {
		h.renderError(w, r, http.StatusForbidden, errNoPasswordIDP)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, redirectProfileNameErr+url.QueryEscape(errMalformedForm), http.StatusFound)
		return
	}

	newName := strings.TrimSpace(r.FormValue("new_name"))

	if newName == "" {
		http.Redirect(w, r, redirectProfileNameErr+url.QueryEscape("New name is required"), http.StatusFound)
		return
	}

	err := h.userProfileService.ChangeName(r.Context(), tenant.ID, user.ID, newName)
	if err != nil {
		http.Redirect(w, r, redirectProfileNameErr+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}

	http.Redirect(w, r, redirectProfileMsg+url.QueryEscape("Name updated successfully"), http.StatusFound)
}

func (h *HttpAdapter) decoupleIdentitySubmit(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, errTenantNotResolved)
		return
	}

	requiredAAL := tenant.Config.GetProfileAAL()
	_, user, _, _, _, ok := h.checkProfileAuth(w, r, requiredAAL)
	if !ok {
		return
	}

	idpIDStr := chi.URLParam(r, "idp")
	idpUUID, err := uuid.Parse(idpIDStr)
	if err != nil {
		w.Header().Set(hxRedirectHeader, "/profile?err=Invalid+IDP+ID")
		w.WriteHeader(http.StatusOK)
		return
	}

	// We must prevent decoupling the last username-password credential if they have no other way to sign in, but let's decouple as requested
	if err := h.userProfileService.DecoupleIdentity(r.Context(), tenant.ID, user.ID, idpUUID); err != nil {
		w.Header().Set(hxRedirectHeader, "/profile?err="+url.QueryEscape(err.Error()))
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set(hxRedirectHeader, "/profile?msg=Identity+decoupled+successfully")
	w.WriteHeader(http.StatusOK)
}
