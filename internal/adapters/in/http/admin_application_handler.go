package http

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// =========================================================================
// 1. APPLICATION BOUNDARY DTO
// =========================================================================
type SaveApplicationPayload struct {
	ClientID        string
	ApplicationName string
	ProfileIDStr    string
	GroupIDStr      string
	IsEdit          bool
}

func NewSaveApplicationPayload(r *http.Request) *SaveApplicationPayload {
	return &SaveApplicationPayload{
		ClientID:        strings.TrimSpace(r.FormValue("client_id")),
		ApplicationName: strings.TrimSpace(r.FormValue("application_name")),
		ProfileIDStr:    r.FormValue("profile_id"),
		GroupIDStr:      r.FormValue("group_id"),
		IsEdit:          r.FormValue("is_edit") == "true",
	}
}

func (p *SaveApplicationPayload) Validate() (uuid.UUID, uuid.UUID, map[string]string) {
	errs := make(map[string]string)

	if p.ClientID == "" {
		errs["client_id"] = "client ID identifier constraint is required"
	}
	if p.ApplicationName == "" {
		errs["application_name"] = "application descriptive metadata label is required"
	}

	profileID, err := uuid.Parse(p.ProfileIDStr)
	if err != nil {
		errs["profile_id"] = "invalid or missing security profile token allocation"
	}

	groupID, err := uuid.Parse(p.GroupIDStr)
	if err != nil {
		errs["group_id"] = "invalid or missing routing authorization group mapping"
	}

	return profileID, groupID, errs
}

func (h *AdminApplicationHandler) adminSaveApplication(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}

	payload := NewSaveApplicationPayload(r)
	profileID, groupID, errs := payload.Validate()

	if len(errs) > 0 {
		profiles, errProfiles := h.adminApplicationUseCase.GetProfiles(r.Context(), tenant.ID)
		if errProfiles != nil {
			h.renderDomainError(w, r, errProfiles)
			return
		}
		groups, errGroups := h.adminApplicationUseCase.GetGroups(r.Context(), tenant.ID)
		if errGroups != nil {
			h.renderDomainError(w, r, errGroups)
			return
		}

		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusUnprocessableEntity) // Rigid 422 hypermedia compliance invariant

		component := admin.ApplicationForm(admin.ApplicationFormProps{
			Application: &model.Application{
				ClientID:        payload.ClientID,
				ApplicationName: payload.ApplicationName,
				ProfileID:       profileID,
				GroupID:         groupID,
			},
			Profiles: profiles,
			Groups:   groups,
			Errors:   errs, // UI maps fields dynamically via targeted swaps
			IsEdit:   payload.IsEdit,
		})
		_ = component.Render(r.Context(), w)
		return
	}

	if payload.IsEdit {
		cmd := port.UpdateApplicationCommand{
			TenantID:        tenant.ID,
			ClientID:        payload.ClientID,
			ApplicationName: payload.ApplicationName,
			ProfileID:       profileID,
			GroupID:         groupID,
		}
		if err := h.adminApplicationUseCase.UpdateApplication(r.Context(), cmd); err != nil {
			h.renderDomainError(w, r, err)
			return
		}
		w.Header().Set(model.HeaderHxRedirect, port.RouteAdmin+port.RouteAdminApplications+"?msg=Application+updated+successfully")
		w.WriteHeader(http.StatusOK)
		return
	}

	cmd := port.CreateApplicationCommand{
		TenantID:        tenant.ID,
		ClientID:        payload.ClientID,
		ApplicationName: payload.ApplicationName,
		ProfileID:       profileID,
		GroupID:         groupID,
		OnDelivery: func(plaintextSecret string) error {
			profile, errProfile := h.adminApplicationUseCase.GetProfile(r.Context(), tenant.ID, profileID)
			if errProfile != nil {
				// Returning an error here forces the domain layer to roll back the pending application row.
				return fmt.Errorf("resolve profile for delivery: %w", errProfile)
			}
			w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)

			// Track A: Public Client application requires zero back-channel secret generation
			if profile.TokenEndpointAuthMethod == model.AuthMethodNone {
				w.Header().Set(model.HeaderHxRedirect, port.RouteAdmin+port.RouteAdminApplications+"?msg=Application+created+successfully")
				w.WriteHeader(http.StatusOK)
				return nil
			}

			// Track B: Confidential Client application profile. Stream plaintext secret directly into network socket
			w.WriteHeader(http.StatusOK)
			component := admin.ApplicationCredentialsResetPanel(payload.ClientID, plaintextSecret)

			// Critical Invariant: If network stream socket breaks mid-write, Render returns an error, forcing a hard DB ROLLBACK
			return component.Render(r.Context(), w)
		},
	}
	// Dispatch across the use-case boundary ports layer
	_, err := h.adminApplicationUseCase.CreateApplication(r.Context(), cmd)
	if err != nil {
		slog.Error("Transactional application provisioning failed", "err", err)
		h.renderError(w, r, http.StatusInternalServerError, "Storage transaction rolled back: client delivery channel interrupted.")
		return
	}
}

// =========================================================================
// 2. PROFILE POLICY BOUNDARY DTO
// =========================================================================
type SaveProfilePayload struct {
	IDStr            string
	ProfileName      string
	AuthMethod       string
	SigningAlg       string
	AccessTokenRaw   string
	IDTokenRaw       string
	RefreshTokenRaw  string
	GrantTypesRaw    []string
	ResponseTypesRaw []string
}

func NewSaveProfilePayload(r *http.Request) *SaveProfilePayload {
	return &SaveProfilePayload{
		IDStr:            r.FormValue("id"),
		ProfileName:      strings.TrimSpace(r.FormValue("profile_name")),
		AuthMethod:       r.FormValue("token_endpoint_auth_method"),
		SigningAlg:       r.FormValue("signing_algorithm"),
		AccessTokenRaw:   r.FormValue("access_token_lifetime"),
		IDTokenRaw:       r.FormValue("id_token_lifetime"),
		RefreshTokenRaw:  r.FormValue("refresh_token_lifetime"),
		GrantTypesRaw:    r.Form["grant_types"],
		ResponseTypesRaw: r.Form["response_types"],
	}
}

func (p *SaveProfilePayload) MapLifetimes(errs map[string]string) (time.Duration, time.Duration, time.Duration) {
	parseSec := func(raw string, fieldKey string, defaultSec int64) time.Duration {
		if raw == "" {
			return time.Duration(defaultSec) * time.Second
		}
		sec, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || sec <= 0 {
			errs[fieldKey] = "temporal configuration must express a positive non-zero whole integer count"
			return time.Duration(defaultSec) * time.Second
		}
		return time.Duration(sec) * time.Second
	}

	return parseSec(p.AccessTokenRaw, "access_token_lifetime", 900),
		parseSec(p.IDTokenRaw, "id_token_lifetime", 900),
		parseSec(p.RefreshTokenRaw, "refresh_token_lifetime", 1209600)
}

func (h *AdminApplicationHandler) adminSaveProfile(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}

	payload := NewSaveProfilePayload(r)
	isEdit := payload.IDStr != ""
	errs := make(map[string]string)

	if payload.ProfileName == "" {
		errs["profile_name"] = "security profile metadata label name field is required"
	}

	accessTokenLifetime, idTokenLifetime, refreshTokenLifetime := payload.MapLifetimes(errs)

	if len(errs) > 0 {
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusUnprocessableEntity)

		var parsedID uuid.UUID
		if isEdit {
			parsedID, _ = uuid.Parse(payload.IDStr)
		}

		component := admin.ProfileForm(admin.ProfileFormProps{
			Profile: &model.ApplicationProfile{
				ID:                      parsedID,
				ProfileName:             payload.ProfileName,
				TokenEndpointAuthMethod: model.TokenEndpointAuthMethod(payload.AuthMethod),
				AccessTokenLifetime:     accessTokenLifetime,
				IDTokenLifetime:         idTokenLifetime,
				RefreshTokenLifetime:    refreshTokenLifetime,
				SigningAlgorithm:        model.SignatureAlgorithm(payload.SigningAlg),
			},
			Errors: errs,
			IsEdit: isEdit,
		})
		_ = component.Render(r.Context(), w)
		return
	}

	var grantTypes []model.GrantType
	for _, gt := range payload.GrantTypesRaw {
		grantTypes = append(grantTypes, model.GrantType(gt))
	}
	if len(grantTypes) == 0 {
		grantTypes = []model.GrantType{model.GrantTypeAuthorizationCode}
	}

	var responseTypes []model.ResponseType
	for _, rt := range payload.ResponseTypesRaw {
		responseTypes = append(responseTypes, model.ResponseType(rt))
	}
	if len(responseTypes) == 0 {
		responseTypes = []model.ResponseType{model.ResponseTypeCode}
	}

	if isEdit {
		id, _ := uuid.Parse(payload.IDStr)
		cmd := port.UpdateProfileCommand{
			TenantID:                tenant.ID,
			ID:                      id,
			ProfileName:             payload.ProfileName,
			TokenEndpointAuthMethod: model.TokenEndpointAuthMethod(payload.AuthMethod),
			GrantTypes:              grantTypes,
			ResponseTypes:           responseTypes,
			AccessTokenLifetime:     accessTokenLifetime,
			RefreshTokenLifetime:    refreshTokenLifetime,
			IDTokenLifetime:         idTokenLifetime,
			SigningAlgorithm:        model.SignatureAlgorithm(payload.SigningAlg),
		}
		if err := h.adminApplicationUseCase.UpdateProfile(r.Context(), cmd); err != nil {
			h.renderDomainError(w, r, err)
			return
		}
		w.Header().Set(model.HeaderHxRedirect, port.RouteAdmin+port.RouteAdminApplications+"?msg=Security+profile+updated+successfully")
		w.WriteHeader(http.StatusOK)
		return
	}

	cmd := port.CreateProfileCommand{
		TenantID:                tenant.ID,
		ProfileName:             payload.ProfileName,
		TokenEndpointAuthMethod: model.TokenEndpointAuthMethod(payload.AuthMethod),
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		AccessTokenLifetime:     accessTokenLifetime,
		RefreshTokenLifetime:    refreshTokenLifetime,
		IDTokenLifetime:         idTokenLifetime,
		SigningAlgorithm:        model.SignatureAlgorithm(payload.SigningAlg),
	}
	if err := h.adminApplicationUseCase.CreateProfile(r.Context(), cmd); err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	w.Header().Set(model.HeaderHxRedirect, port.RouteAdmin+port.RouteAdminApplications+"?msg=Security+profile+created+successfully")
	w.WriteHeader(http.StatusOK)
}

// =========================================================================
// 3. AUTHORIZATION GROUP BOUNDARY DTO
// =========================================================================
type SaveGroupPayload struct {
	IDStr                 string
	GroupName             string
	DefaultRedirectURI    string
	RedirectURIs          []string
	PostLogoutURIs        []string
	FrontChannelLogoutURI string
	BackChannelLogoutURI  string
	Scopes                []string
	Audiences             []string
	AllowedIDPsRaw        []string
	DefaultIDPRaw         string
}

func NewSaveGroupPayload(r *http.Request) *SaveGroupPayload {
	return &SaveGroupPayload{
		IDStr:                 r.FormValue("id"),
		GroupName:             strings.TrimSpace(r.FormValue("group_name")),
		DefaultRedirectURI:    strings.TrimSpace(r.FormValue("default_redirect_uri")),
		RedirectURIs:          CleanBoundaryStringSlice(parseFormStringSlice(r.Form, "redirect_uris")),
		PostLogoutURIs:        CleanBoundaryStringSlice(parseFormStringSlice(r.Form, "post_logout_redirect_uris")),
		FrontChannelLogoutURI: strings.TrimSpace(r.FormValue("front_channel_logout_uri")),
		BackChannelLogoutURI:  strings.TrimSpace(r.FormValue("back_channel_logout_uri")),
		Scopes:                CleanBoundaryStringSlice(parseFormStringSlice(r.Form, "scopes")),
		Audiences:             CleanBoundaryStringSlice(parseFormStringSlice(r.Form, "audiences")),
		AllowedIDPsRaw:        CleanBoundaryStringSlice(parseFormStringSlice(r.Form, "allowed_idps")),
		DefaultIDPRaw:         r.FormValue("default_idp_id"),
	}
}

// parseGroupIDPs converts the submitted sign-in method identifiers into typed UUIDs.
// Malformed identifiers are reported as validation errors instead of being silently dropped.
func parseGroupIDPs(payload *SaveGroupPayload, errs map[string]string) ([]uuid.UUID, *uuid.UUID) {
	allowed := []uuid.UUID{}
	for _, rawID := range payload.AllowedIDPsRaw {
		parsed, err := uuid.Parse(rawID)
		if err != nil {
			errs["allowed_idps"] = "one or more selected sign-in methods are invalid"
			continue
		}
		allowed = append(allowed, parsed)
	}

	if payload.DefaultIDPRaw == "" {
		return allowed, nil
	}
	parsedDefault, err := uuid.Parse(payload.DefaultIDPRaw)
	if err != nil {
		errs["default_idp_id"] = "the default sign-in method is invalid"
		return allowed, nil
	}
	return allowed, &parsedDefault
}

// groupFromPayload builds the view model used to re-render the form with the submitted values.
func groupFromPayload(payload *SaveGroupPayload, allowed []uuid.UUID, def *uuid.UUID) *model.ApplicationGroup {
	id, _ := uuid.Parse(payload.IDStr)
	return &model.ApplicationGroup{
		ID:                     id,
		GroupName:              payload.GroupName,
		RedirectURI:            payload.DefaultRedirectURI,
		RedirectURIs:           payload.RedirectURIs,
		PostLogoutRedirectURIs: payload.PostLogoutURIs,
		FrontChannelLogoutURI:  payload.FrontChannelLogoutURI,
		BackChannelLogoutURI:   payload.BackChannelLogoutURI,
		AllowedScopes:          payload.Scopes,
		AllowedAudiences:       payload.Audiences,
		AllowedIDPIDs:          allowed,
		DefaultIDPID:           def,
	}
}

// renderGroupFormErrors re-renders the group form with field errors and the semantic 422 status.
func (h *AdminApplicationHandler) renderGroupFormErrors(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, group *model.ApplicationGroup, errs map[string]string, isEdit bool) {
	partitionsWithIdps, err := h.idpService.GetPartitionsWithProviders(r.Context(), tenantID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	component := admin.GroupForm(admin.GroupFormProps{
		Group:              group,
		Errors:             errs,
		IsEdit:             isEdit,
		PartitionsWithIdps: partitionsWithIdps,
	})
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	w.WriteHeader(http.StatusUnprocessableEntity) // Explicit 422 for form error targeting
	_ = component.Render(r.Context(), w)
}

func (h *AdminApplicationHandler) adminSaveGroup(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}

	payload := NewSaveGroupPayload(r)
	isEdit := payload.IDStr != ""
	errs := make(map[string]string)

	if payload.GroupName == "" {
		errs["group_name"] = "authorization gateway routing group label is required"
	}
	allowedIDPIDs, defaultIDPID := parseGroupIDPs(payload, errs)
	view := groupFromPayload(payload, allowedIDPIDs, defaultIDPID)

	if len(errs) > 0 {
		h.renderGroupFormErrors(w, r, tenant.ID, view, errs, isEdit)
		return
	}

	var err error
	msg := "Authorization+group+created+successfully"
	if isEdit {
		msg = "Authorization+group+updated+successfully"
		err = h.adminApplicationUseCase.UpdateGroup(r.Context(), port.UpdateGroupCommand{
			TenantID:               tenant.ID,
			ID:                     view.ID,
			GroupName:              payload.GroupName,
			DefaultRedirectURI:     payload.DefaultRedirectURI,
			RedirectURIs:           payload.RedirectURIs,
			PostLogoutRedirectURIs: payload.PostLogoutURIs,
			FrontChannelLogoutURI:  payload.FrontChannelLogoutURI,
			BackChannelLogoutURI:   payload.BackChannelLogoutURI,
			AllowedScopes:          payload.Scopes,
			DefaultScopes:          payload.Scopes,
			AllowedAudiences:       payload.Audiences,
			AllowedIDPIDs:          allowedIDPIDs,
			DefaultIDPID:           defaultIDPID,
		})
	} else {
		err = h.adminApplicationUseCase.CreateGroup(r.Context(), port.CreateGroupCommand{
			TenantID:               tenant.ID,
			GroupName:              payload.GroupName,
			DefaultRedirectURI:     payload.DefaultRedirectURI,
			RedirectURIs:           payload.RedirectURIs,
			PostLogoutRedirectURIs: payload.PostLogoutURIs,
			FrontChannelLogoutURI:  payload.FrontChannelLogoutURI,
			BackChannelLogoutURI:   payload.BackChannelLogoutURI,
			AllowedScopes:          payload.Scopes,
			DefaultScopes:          payload.Scopes,
			AllowedAudiences:       payload.Audiences,
			AllowedIDPIDs:          allowedIDPIDs,
			DefaultIDPID:           defaultIDPID,
		})
	}

	var validationErr *port.ValidationError
	if errors.As(err, &validationErr) {
		h.renderGroupFormErrors(w, r, tenant.ID, view, validationErr.Fields, isEdit)
		return
	}
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	w.Header().Set(model.HeaderHxRedirect, port.RouteAdmin+port.RouteAdminApplications+"?msg="+msg)
	w.WriteHeader(http.StatusOK)
}

// =========================================================================
// 4. STRUCT, ROUTER & DISPLAY FORM LIFECYCLE GETTERS
// =========================================================================

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
		h.renderDomainError(w, r, err)
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
		h.renderDomainError(w, r, err)
		return
	}
	groups, err := h.adminApplicationUseCase.GetGroups(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Add Application", port.RouteAdmin+port.RouteAdminApplications+"/new")
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
		h.renderDomainError(w, r, err)
		return
	}

	profiles, err := h.adminApplicationUseCase.GetProfiles(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	groups, err := h.adminApplicationUseCase.GetGroups(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Edit Application", port.RouteAdmin+port.RouteAdminApplications+"/edit?id="+clientID)
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
		h.renderDomainError(w, r, err)
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Application Details", port.RouteAdmin+port.RouteAdminApplications+"/view?id="+clientID)
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
		h.renderDomainError(w, r, err)
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	component := admin.StatusBadge(app.IsEnabled)
	_ = component.Render(r.Context(), w)
}

func (h *AdminApplicationHandler) adminResetApplicationSecret(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clientID := chi.URLParam(r, "id")

	// 1. Package variables into the transaction-locked command contract wrapper
	cmd := port.ResetApplicationSecretCommand{
		TenantID: tenant.ID,
		ClientID: clientID,
		OnDelivery: func(plaintextSecret string) error {
			// Set response headers and status inside the transaction boundary
			w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
			w.WriteHeader(http.StatusOK)

			// Stream the out-of-band component panel directly into the live socket buffer
			component := admin.ApplicationCredentialsResetPanel(clientID, plaintextSecret)
			return component.Render(r.Context(), w)
		},
	}

	// 2. Dispatch the command across the driving use-case boundary
	err := h.adminApplicationUseCase.ResetApplicationSecret(r.Context(), cmd)
	if err != nil {
		slog.Error("Transactional secret rotation failed", "err", err)
		h.renderError(w, r, http.StatusInternalServerError, "Storage transaction rolled back: client delivery channel interrupted.")
		return
	}

	// 3. Exit cleanly. The OnDelivery callback has already successfully finalized the network stream states.
}

func (h *AdminApplicationHandler) adminDeleteApplication(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clientID := chi.URLParam(r, "id")

	if err := h.adminApplicationUseCase.DeleteApplication(r.Context(), tenant.ID, clientID); err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	w.Header().Set(model.HeaderHxRedirect, port.RouteAdmin+port.RouteAdminApplications+"?msg=Application+deleted+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *AdminApplicationHandler) adminNewProfileForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Add Profile Policy", port.RouteAdmin+port.RouteAdminApplications+port.RouteAdminApplicationsProfiles+"/new")
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
		h.renderDomainError(w, r, err)
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Edit Profile Policy", port.RouteAdmin+port.RouteAdminApplications+port.RouteAdminApplicationsProfiles+"/edit?id="+idStr)
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

func (h *AdminApplicationHandler) adminNewGroupForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())

	partitionsWithIdps, err := h.idpService.GetPartitionsWithProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	component := admin.GroupForm(admin.GroupFormProps{
		Group:              &model.ApplicationGroup{},
		Errors:             make(map[string]string),
		IsEdit:             false,
		PartitionsWithIdps: partitionsWithIdps,
	})

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	_ = component.Render(r.Context(), w)
}

func (h *AdminApplicationHandler) adminEditGroupForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		h.renderError(w, r, http.StatusBadRequest, "Missing mandatory 'id' parameter.")
		return
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "invalid group id")
		return
	}

	group, err := h.adminApplicationUseCase.GetGroup(r.Context(), tenant.ID, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	partitionsWithIdps, err := h.idpService.GetPartitionsWithProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	props := admin.GroupFormProps{
		Group:              group,
		Errors:             make(map[string]string),
		IsEdit:             true,
		PartitionsWithIdps: partitionsWithIdps,
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	// If HTMX is calling this endpoint via the inner modal body load-trigger,
	// stream the fully hydrated GroupForm layout using our props variable!
	if r.URL.Query().Get("render_body") == "true" {
		_ = admin.GroupForm(props).Render(r.Context(), w)
		return
	}

	// When the user clicks the Edit button in the main table list row, return the outer modal layout container.
	// This tells the modal wrapper to execute a back-fetch hitting 'render_body=true' right above.
	modalFetchURL := fmt.Sprintf("/admin/applications/groups/edit?id=%s&render_body=true", idStr)
	component := admin.Modal("Edit Authorization Group", modalFetchURL)
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
