package http

import (
	"net/http"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"
)

// defaultProfile holds the secure starting values of a new profile.
func defaultProfile() *model.ApplicationProfile {
	return &model.ApplicationProfile{
		TokenEndpointAuthMethod: model.AuthMethodClientSecretPost,
		SigningAlgorithm:        model.AlgRS256,
		GrantTypes:              []model.GrantType{model.GrantTypeAuthorizationCode, model.GrantTypeRefreshToken},
		EnforceRTR:              true,
		AccessTokenLifetime:     15 * time.Minute,
		IDTokenLifetime:         15 * time.Minute,
		RefreshTokenLifetime:    14 * 24 * time.Hour,
	}
}

func (h *AdminProfileHandler) newForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	props := admin.CreateFormProps{ActiveTenant: *tenant, Errors: map[string]string{}, Values: map[string]string{}}
	profile := defaultProfile()
	h.renderAdminPage(w, r, admin.NewProfileContent(props, profile), admin.NewProfilePage(props, profile))
}

// create makes a profile from secure defaults plus the submitted authentication settings.
func (h *AdminProfileHandler) create(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}

	def := defaultProfile()
	profile, err := h.adminApplicationUseCase.CreateProfile(r.Context(), port.CreateProfileCommand{
		TenantID:                tenant.ID,
		ProfileName:             strings.TrimSpace(r.FormValue("profile_name")),
		TokenEndpointAuthMethod: model.TokenEndpointAuthMethod(r.FormValue("token_endpoint_auth_method")),
		SigningAlgorithm:        model.SignatureAlgorithm(r.FormValue("signing_algorithm")),
		GrantTypes:              parseGrantTypes(r.Form["grant_types"]),
		ResponseTypes:           []model.ResponseType{model.ResponseTypeCode},
		EnforceRTR:              r.FormValue("enforce_rtr") == "true",
		AccessTokenLifetime:     def.AccessTokenLifetime,
		IDTokenLifetime:         def.IDTokenLifetime,
		RefreshTokenLifetime:    def.RefreshTokenLifetime,
	})
	if err != nil {
		h.renderCreateProfileError(w, r, tenant, err)
		return
	}
	redirectTo(w, r, flashURL(profileURL(profile.ID), "Profile created. Review the token lifetimes below."))
}

func (h *AdminProfileHandler) renderCreateProfileError(w http.ResponseWriter, r *http.Request, tenant *model.Tenant, err error) {
	errs := map[string]string{}
	mergeFieldErrors(err, errs)
	if len(errs) == 0 {
		h.renderDomainError(w, r, err)
		return
	}
	// Re-render with what was typed, so nothing is lost on a validation error.
	profile := defaultProfile()
	profile.ProfileName = strings.TrimSpace(r.FormValue("profile_name"))
	profile.TokenEndpointAuthMethod = model.TokenEndpointAuthMethod(r.FormValue("token_endpoint_auth_method"))
	profile.SigningAlgorithm = model.SignatureAlgorithm(r.FormValue("signing_algorithm"))
	profile.GrantTypes = parseGrantTypes(r.Form["grant_types"])
	profile.EnforceRTR = r.FormValue("enforce_rtr") == "true"

	props := admin.CreateFormProps{ActiveTenant: *tenant, Errors: errs, Values: map[string]string{"profile_name": profile.ProfileName}}
	h.renderFragment(w, r, http.StatusUnprocessableEntity, admin.NewProfileContent(props, profile))
}
