package http

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"
	"sprezz-identity/internal/views/public"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type AdminApplicationHandler struct {
	*HttpAdapter
}

func NewAdminApplicationHandler(adapter *HttpAdapter) *AdminApplicationHandler {
	return &AdminApplicationHandler{HttpAdapter: adapter}
}

func (h *AdminApplicationHandler) Routes(r chi.Router) {
	r.Route(port.RouteAdminApplications, func(r chi.Router) {
		r.Get("/generate-secret", h.adminGenerateSecret)
		r.Get("/", h.adminApplicationsPage)
		r.Get("/new", h.adminNewApplicationForm)
		r.Get("/edit", h.adminEditApplicationForm)
		r.Get("/view", h.adminViewApplication)
		r.Post("/", h.adminSaveApplication)
		r.Post("/{id}/toggle-status", h.adminToggleApplicationStatus)
		r.Post("/{id}/reset-secret", h.adminResetApplicationSecret)
		r.Delete("/{id}", h.adminDeleteApplication)

		r.Route(port.RouteAdminApplicationsProfiles, func(r chi.Router) {
			r.Get("/new", h.adminNewProfileForm)
			r.Get("/edit", h.adminEditProfileForm)
			r.Post("/", h.adminSaveProfile)
		})

		r.Route(port.RouteAdminApplicationsGroups, func(r chi.Router) {
			r.Get("/new", h.adminNewGroupForm)
			r.Get("/edit", h.adminEditGroupForm)
			r.Post("/", h.adminSaveGroup)
		})
	})
}

func (h *AdminApplicationHandler) adminApplicationsPage(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	summaries, profiles, groups, err := h.adminApplicationUseCase.GetApplicationDashboard(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.Header.Get("HX-Request") == "true" {
		component := admin.ApplicationsContent(admin.ApplicationsPageProps{
			ActiveTenant: *tenant,
			Applications: summaries,
			Profiles:     profiles,
			Groups:       groups,
			Msg:          r.URL.Query().Get("msg"),
		})
		_ = component.Render(r.Context(), w)
		return
	}

	component := admin.ApplicationsPage(admin.ApplicationsPageProps{
		ActiveTenant: *tenant,
		Applications: summaries,
		Profiles:     profiles,
		Groups:       groups,
		Msg:          r.URL.Query().Get("msg"),
	})
	_ = component.Render(r.Context(), w)
}

func (h *AdminApplicationHandler) adminNewApplicationForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	profiles, err := h.adminApplicationUseCase.GetProfiles(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	groups, err := h.adminApplicationUseCase.GetGroups(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Add Application", "/admin/applications/new")
		_ = component.Render(r.Context(), w)
		return
	}

	component := admin.ApplicationForm(admin.ApplicationFormProps{
		Application: &model.Application{},
		Profiles:    profiles,
		Groups:      groups,
		Errors:      make(map[string]string),
	})
	_ = component.Render(r.Context(), w)
}

func (h *AdminApplicationHandler) adminEditApplicationForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clientID := r.URL.Query().Get("id")

	details, err := h.adminApplicationUseCase.GetApplicationDetails(r.Context(), tenant.ID, clientID)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, err.Error())
		return
	}

	profiles, err := h.adminApplicationUseCase.GetProfiles(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	groups, err := h.adminApplicationUseCase.GetGroups(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Edit Application", "/admin/applications/edit?id="+clientID)
		_ = component.Render(r.Context(), w)
		return
	}

	component := admin.ApplicationForm(admin.ApplicationFormProps{
		Application: details.Application,
		Profiles:    profiles,
		Groups:      groups,
		Errors:      make(map[string]string),
		IsEdit:      true,
	})
	_ = component.Render(r.Context(), w)
}

func (h *AdminApplicationHandler) adminViewApplication(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clientID := r.URL.Query().Get("id")

	details, err := h.adminApplicationUseCase.GetApplicationDetails(r.Context(), tenant.ID, clientID)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Application Details", "/admin/applications/view?id="+clientID)
		_ = component.Render(r.Context(), w)
		return
	}

	component := admin.ApplicationForm(admin.ApplicationFormProps{
		Application: details.Application,
		Profiles:    []model.ApplicationProfile{*details.ApplicationProfile},
		Groups:      []model.ApplicationGroup{*details.ApplicationGroup},
		Errors:      make(map[string]string),
		ReadOnly:    true,
		IsEdit:      true,
	})
	_ = component.Render(r.Context(), w)
}

func (h *AdminApplicationHandler) adminToggleApplicationStatus(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clientID := chi.URLParam(r, "id")

	app, err := h.adminApplicationUseCase.ToggleApplicationStatus(r.Context(), tenant.ID, clientID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	component := admin.StatusBadge(app.IsEnabled)
	_ = component.Render(r.Context(), w)
}

func (h *AdminApplicationHandler) adminResetApplicationSecret(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clientID := chi.URLParam(r, "id")

	plainSecret, err := h.adminApplicationUseCase.ResetApplicationSecret(r.Context(), tenant.ID, clientID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	component := admin.ApplicationCredentialsResetPanel(clientID, plainSecret)
	_ = component.Render(r.Context(), w)
}

func (h *AdminApplicationHandler) adminDeleteApplication(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clientID := chi.URLParam(r, "id")

	if err := h.adminApplicationUseCase.DeleteApplication(r.Context(), tenant.ID, clientID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Redirect", "/admin/applications?msg=Application+deleted+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *AdminApplicationHandler) adminSaveApplication(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	clientID := r.FormValue("client_id")
	applicationName := r.FormValue("application_name")
	isEdit := r.FormValue("is_edit") == "true"

	profileIDStr := r.FormValue("profile_id")
	groupIDStr := r.FormValue("group_id")

	errs := make(map[string]string)
	if clientID == "" {
		errs["client_id"] = "client ID is required"
	}
	if applicationName == "" {
		errs["application_name"] = "application name is required"
	}

	profileID, err := uuid.Parse(profileIDStr)
	if err != nil {
		errs["profile_id"] = "invalid or missing security profile"
	}

	groupID, err := uuid.Parse(groupIDStr)
	if err != nil {
		errs["group_id"] = "invalid or missing authorization group"
	}

	if len(errs) > 0 {
		profiles, _ := h.adminApplicationUseCase.GetProfiles(r.Context(), tenant.ID)
		groups, _ := h.adminApplicationUseCase.GetGroups(r.Context(), tenant.ID)
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusUnprocessableEntity)

		component := admin.ApplicationForm(admin.ApplicationFormProps{
			Application: &model.Application{
				ClientID:        clientID,
				ApplicationName: applicationName,
				ProfileID:       profileID,
				GroupID:         groupID,
			},
			Profiles: profiles,
			Groups:   groups,
			Errors:   errs,
			IsEdit:   isEdit,
		})
		_ = component.Render(r.Context(), w)
		return
	}

	if isEdit {
		cmd := port.UpdateApplicationCommand{
			TenantID:        tenant.ID,
			ClientID:        clientID,
			ApplicationName: applicationName,
			ProfileID:       profileID,
			GroupID:         groupID,
			IsEnabled:       true,
		}

		if err := h.adminApplicationUseCase.UpdateApplication(r.Context(), cmd); err != nil {
			h.renderError(w, r, http.StatusInternalServerError, err.Error())
			return
		}

		w.Header().Set("HX-Redirect", "/admin/applications?msg=Application+updated+successfully")
		w.WriteHeader(http.StatusOK)
		return
	}

	cmd := port.CreateApplicationCommand{
		TenantID:        tenant.ID,
		ClientID:        clientID,
		ApplicationName: applicationName,
		ProfileID:       profileID,
		GroupID:         groupID,
	}

	app, secret, err := h.adminApplicationUseCase.CreateApplication(r.Context(), cmd)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	profile, _ := h.adminApplicationUseCase.GetProfile(r.Context(), tenant.ID, profileID)
	if profile.TokenEndpointAuthMethod != model.AuthMethodNone {
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		component := admin.Modal("Application Created Successfully", "/admin/applications")
		_ = component.Render(r.Context(), w)

		// Overwrite modal with clean credentials warning box carrying plaintext secret
		_, _ = fmt.Fprintf(w, "<div id=\"modal-container\" hx-swap-oob=\"true\">")
		componentSecret := admin.ApplicationCredentialsResetPanel(app.ClientID, secret)
		_ = componentSecret.Render(r.Context(), w)
		_, _ = fmt.Fprintf(w, "</div>")
		return
	}

	w.Header().Set("HX-Redirect", "/admin/applications?msg=Application+created+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *AdminApplicationHandler) adminNewProfileForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Add Profile Policy", "/admin/applications/profiles/new")
		_ = component.Render(r.Context(), w)
		return
	}

	component := admin.ProfileForm(admin.ProfileFormProps{
		Profile: &model.ApplicationProfile{
			AccessTokenLifetime:  900 * time.Second,
			IDTokenLifetime:      900 * time.Second,
			RefreshTokenLifetime: 1209600 * time.Second,
			SigningAlgorithm:     model.AlgRS256,
		},
		Errors: make(map[string]string),
	})
	_ = component.Render(r.Context(), w)
}

func (h *AdminApplicationHandler) adminEditProfileForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	idStr := r.URL.Query().Get("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "invalid profile id")
		return
	}

	profile, err := h.adminApplicationUseCase.GetProfile(r.Context(), tenant.ID, id)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Edit Profile Policy", "/admin/applications/profiles/edit?id="+idStr)
		_ = component.Render(r.Context(), w)
		return
	}

	component := admin.ProfileForm(admin.ProfileFormProps{
		Profile: profile,
		Errors:  make(map[string]string),
		IsEdit:  true,
	})
	_ = component.Render(r.Context(), w)
}

func (h *AdminApplicationHandler) adminSaveProfile(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	profileName := r.FormValue("profile_name")
	authMethod := r.FormValue("token_endpoint_auth_method")
	signingAlg := r.FormValue("signing_algorithm")
	idStr := r.FormValue("id")
	isEdit := idStr != ""

	accessTokenLifetime, idTokenLifetime, refreshTokenLifetime := parseClientLifetimes(r)

	errs := make(map[string]string)
	if profileName == "" {
		errs["profile_name"] = "profile name is required"
	}

	if len(errs) > 0 {
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusUnprocessableEntity)

		var parsedID uuid.UUID
		if isEdit {
			parsedID, _ = uuid.Parse(idStr)
		}

		component := admin.ProfileForm(admin.ProfileFormProps{
			Profile: &model.ApplicationProfile{
				ID:                      parsedID,
				ProfileName:             profileName,
				TokenEndpointAuthMethod: model.TokenEndpointAuthMethod(authMethod),
				AccessTokenLifetime:     accessTokenLifetime,
				IDTokenLifetime:         idTokenLifetime,
				RefreshTokenLifetime:    refreshTokenLifetime,
				SigningAlgorithm:        model.SignatureAlgorithm(signingAlg),
			},
			Errors: errs,
			IsEdit: isEdit,
		})
		_ = component.Render(r.Context(), w)
		return
	}

	grantTypesRaw := r.Form["grant_types"]
	var grantTypes []model.GrantType
	for _, gt := range grantTypesRaw {
		grantTypes = append(grantTypes, model.GrantType(gt))
	}
	if len(grantTypes) == 0 {
		grantTypes = []model.GrantType{model.GrantTypeAuthorizationCode}
	}

	responseTypesRaw := r.Form["response_types"]
	var responseTypes []model.ResponseType
	for _, rt := range responseTypesRaw {
		responseTypes = append(responseTypes, model.ResponseType(rt))
	}
	if len(responseTypes) == 0 {
		responseTypes = []model.ResponseType{model.ResponseTypeCode}
	}

	if isEdit {
		id, _ := uuid.Parse(idStr)
		cmd := port.UpdateProfileCommand{
			TenantID:                tenant.ID,
			ID:                      id,
			ProfileName:             profileName,
			TokenEndpointAuthMethod: model.TokenEndpointAuthMethod(authMethod),
			GrantTypes:              grantTypes,
			ResponseTypes:           responseTypes,
			AccessTokenLifetime:     accessTokenLifetime,
			RefreshTokenLifetime:    refreshTokenLifetime,
			IDTokenLifetime:         idTokenLifetime,
			SigningAlgorithm:        model.SignatureAlgorithm(signingAlg),
		}

		if err := h.adminApplicationUseCase.UpdateProfile(r.Context(), cmd); err != nil {
			h.renderError(w, r, http.StatusInternalServerError, err.Error())
			return
		}

		w.Header().Set("HX-Redirect", "/admin/applications?msg=Security+profile+updated+successfully")
		w.WriteHeader(http.StatusOK)
		return
	}

	cmd := port.CreateProfileCommand{
		TenantID:                tenant.ID,
		ProfileName:             profileName,
		TokenEndpointAuthMethod: model.TokenEndpointAuthMethod(authMethod),
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		AccessTokenLifetime:     accessTokenLifetime,
		RefreshTokenLifetime:    refreshTokenLifetime,
		IDTokenLifetime:         idTokenLifetime,
		SigningAlgorithm:        model.SignatureAlgorithm(signingAlg),
	}

	if err := h.adminApplicationUseCase.CreateProfile(r.Context(), cmd); err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/admin/applications?msg=Security+profile+created+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *AdminApplicationHandler) adminNewGroupForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	providers, err := h.storagePort.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Add Authorization Group", "/admin/applications/groups/new")
		_ = component.Render(r.Context(), w)
		return
	}

	component := admin.GroupForm(admin.GroupFormProps{
		Group:     &model.ApplicationGroup{},
		Errors:    make(map[string]string),
		Providers: providers,
	})
	_ = component.Render(r.Context(), w)
}

func (h *AdminApplicationHandler) adminEditGroupForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	idStr := r.URL.Query().Get("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "invalid group id")
		return
	}

	group, err := h.adminApplicationUseCase.GetGroup(r.Context(), tenant.ID, id)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, err.Error())
		return
	}

	providers, err := h.storagePort.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Edit Authorization Group", "/admin/applications/groups/edit?id="+idStr)
		_ = component.Render(r.Context(), w)
		return
	}

	component := admin.GroupForm(admin.GroupFormProps{
		Group:     group,
		Errors:    make(map[string]string),
		IsEdit:    true,
		Providers: providers,
	})
	_ = component.Render(r.Context(), w)
}

func (h *AdminApplicationHandler) adminSaveGroup(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	groupName := r.FormValue("group_name")
	idStr := r.FormValue("id")
	isEdit := idStr != ""

	redirectURIs := parseFormStringSlice(r.Form, "redirect_uris")
	postLogoutURIs := parseFormStringSlice(r.Form, "post_logout_redirect_uris")
	frontChannelLogoutURI := r.FormValue("front_channel_logout_uri")
	backChannelLogoutURI := r.FormValue("back_channel_logout_uri")

	scopes := parseFormStringSlice(r.Form, "scopes")
	audiences := parseFormStringSlice(r.Form, "audiences")

	allowedIDPsRaw := parseFormStringSlice(r.Form, "allowed_idps")
	var allowedIDPIDs []uuid.UUID
	for _, rawID := range allowedIDPsRaw {
		if parsed, err := uuid.Parse(rawID); err == nil {
			allowedIDPIDs = append(allowedIDPIDs, parsed)
		}
	}

	var defaultIDPID *uuid.UUID
	if defaultIDPRaw := r.FormValue("default_idp_id"); defaultIDPRaw != "" {
		if parsed, err := uuid.Parse(defaultIDPRaw); err == nil {
			defaultIDPID = &parsed
		}
	}

	errs := make(map[string]string)
	if groupName == "" {
		errs["group_name"] = "group name is required"
	}

	if len(errs) > 0 {
		providers, _ := h.storagePort.GetIdentityProviders(r.Context(), tenant.ID)
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusUnprocessableEntity)

		var parsedID uuid.UUID
		if isEdit {
			parsedID, _ = uuid.Parse(idStr)
		}

		component := admin.GroupForm(admin.GroupFormProps{
			Group: &model.ApplicationGroup{
				ID:                     parsedID,
				GroupName:              groupName,
				RedirectURIs:           redirectURIs,
				PostLogoutRedirectURIs: postLogoutURIs,
				FrontChannelLogoutURI:  frontChannelLogoutURI,
				BackChannelLogoutURI:   backChannelLogoutURI,
				AllowedScopes:          scopes,
				AllowedAudiences:       audiences,
				AllowedIDPIDs:          allowedIDPIDs,
				DefaultIDPID:           defaultIDPID,
			},
			Errors:    errs,
			IsEdit:    isEdit,
			Providers: providers,
		})
		_ = component.Render(r.Context(), w)
		return
	}

	if isEdit {
		id, _ := uuid.Parse(idStr)
		cmd := port.UpdateGroupCommand{
			TenantID:               tenant.ID,
			ID:                     id,
			GroupName:              groupName,
			RedirectURIs:           redirectURIs,
			PostLogoutRedirectURIs: postLogoutURIs,
			FrontChannelLogoutURI:  frontChannelLogoutURI,
			BackChannelLogoutURI:   backChannelLogoutURI,
			AllowedScopes:          scopes,
			DefaultScopes:          scopes,
			AllowedAudiences:       audiences,
			AllowedIDPIDs:          allowedIDPIDs,
			DefaultIDPID:           defaultIDPID,
		}

		if err := h.adminApplicationUseCase.UpdateGroup(r.Context(), cmd); err != nil {
			h.renderError(w, r, http.StatusInternalServerError, err.Error())
			return
		}

		w.Header().Set("HX-Redirect", "/admin/applications?msg=Authorization+group+updated+successfully")
		w.WriteHeader(http.StatusOK)
		return
	}

	cmd := port.CreateGroupCommand{
		TenantID:               tenant.ID,
		GroupName:              groupName,
		RedirectURIs:           redirectURIs,
		PostLogoutRedirectURIs: postLogoutURIs,
		FrontChannelLogoutURI:  frontChannelLogoutURI,
		BackChannelLogoutURI:   backChannelLogoutURI,
		AllowedScopes:          scopes,
		DefaultScopes:          scopes,
		AllowedAudiences:       audiences,
		AllowedIDPIDs:          allowedIDPIDs,
		DefaultIDPID:           defaultIDPID,
	}

	if err := h.adminApplicationUseCase.CreateGroup(r.Context(), cmd); err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/admin/applications?msg=Authorization+group+created+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *HttpAdapter) renderError(w http.ResponseWriter, r *http.Request, status int, errorMessage string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	w.WriteHeader(status)
	component := public.Error(errorMessage)
	_ = component.Render(r.Context(), w)
}

func (h *AdminApplicationHandler) adminGenerateSecret(w http.ResponseWriter, r *http.Request) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		http.Error(w, "Failed to generate secure random bytes", http.StatusInternalServerError)
		return
	}
	secret := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)
	w.Header().Set(model.HeaderContentType, model.ContentTypePlainText)
	_, _ = w.Write([]byte(secret))
}
