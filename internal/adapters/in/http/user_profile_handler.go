package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/public"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type ProfileHandler struct {
	ssoUseCase         port.SSOSessionUseCase
	userProfileUseCase port.UserProfileUseCase
}

func NewProfileHandler(suc port.SSOSessionUseCase, upuc port.UserProfileUseCase) *ProfileHandler {
	return &ProfileHandler{
		ssoUseCase:         suc,
		userProfileUseCase: upuc,
	}
}

func (h *ProfileHandler) Routes(r chi.Router) {
	r.Route(port.RouteWebProfile, func(r chi.Router) {
		r.Get("/", h.HandleViewDashboard)
		r.Get(port.RouteWebProfilePassword, h.HandleChangePasswordForm)
		r.Post(port.RouteWebProfilePassword, h.HandleChangePasswordSubmit)
		r.Get(port.RouteWebProfileEmail, h.HandleChangeEmailForm)
		r.Post(port.RouteWebProfileEmail, h.HandleChangeEmailSubmit)
		r.Get(port.RouteWebProfileName, h.HandleChangeNameForm)
		r.Post(port.RouteWebProfileName, h.HandleChangeNameSubmit)
		r.Delete(port.RouteWebProfileIdentities+"/{idpID}", h.HandleDecoupleIdentitySubmit)
	})
}

func (h *ProfileHandler) HandleViewDashboard(w http.ResponseWriter, r *http.Request) {
	tenantUUID := TenantIDFromContext(r.Context())
	subjectID, partitionID, err := h.authenticateSessionUser(r, tenantUUID)
	if err != nil {
		http.Redirect(w, r, port.RouteRoot, http.StatusSeeOther)
		return
	}

	parsedUserUUID, err := uuid.Parse(subjectID)
	if err != nil {
		h.writeWebHTMLError(w, http.StatusBadRequest, "Invalid session security credentials format")
		return
	}

	dashboardResp, err := h.userProfileUseCase.GetUserProfileDashboard(r.Context(), port.GetUserProfileDashboardCommand{
		TenantID:      tenantUUID,
		PartitionID:   partitionID,
		UserProfileID: parsedUserUUID,
	})
	if err != nil {
		h.writeWebHTMLError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	w.WriteHeader(http.StatusOK)

	component := public.ProfileDashboard(dashboardResp.UserProfile, dashboardResp.Identities, dashboardResp.Providers, dashboardResp.HasPasswordIDP, "", "")
	_ = component.Render(r.Context(), w)
}

func (h *ProfileHandler) HandleChangePasswordForm(w http.ResponseWriter, r *http.Request) {
	tenantUUID := TenantIDFromContext(r.Context())
	_, _, err := h.resolveAuthenticatedUser(r, tenantUUID)
	if err != nil {
		http.Redirect(w, r, port.RouteRoot, http.StatusSeeOther)
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	_ = public.ChangePasswordPage(make(map[string]string), "").Render(r.Context(), w)
}

func (h *ProfileHandler) HandleChangePasswordSubmit(w http.ResponseWriter, r *http.Request) {
	tenantUUID := TenantIDFromContext(r.Context())
	userProfile, partitionID, err := h.resolveAuthenticatedUser(r, tenantUUID)
	if err != nil {
		http.Redirect(w, r, port.RouteRoot, http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderPasswordPageStatus(w, map[string]string{"global": "Malformed payload parameters submitted"}, "")
		return
	}

	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")
	currentPassword := r.FormValue("current_password")

	if newPassword != confirmPassword {
		h.renderPasswordPageStatus(w, map[string]string{"confirm_password": "New password fields do not match"}, "")
		return
	}

	// Map elements straight into a type-safe Command struct
	cmd := port.ChangePasswordCommand{
		TenantID:        tenantUUID,
		PartitionID:     partitionID,
		UserProfileID:   userProfile.ID,
		CurrentPassword: currentPassword,
		NewPassword:     newPassword,
	}

	err = h.userProfileUseCase.ChangeUserPassword(r.Context(), cmd)
	if err != nil {
		var valErr *port.ValidationError
		if errors.As(err, &valErr) {
			h.renderPasswordPageStatus(w, valErr.Fields, "")
			return
		}
		h.renderPasswordPageStatus(w, map[string]string{"global": err.Error()}, "")
		return
	}

	// 1. Fetch updated workspace state details to populate the fresh dashboard layout view safely
	dashboardResp, err := h.userProfileUseCase.GetUserProfileDashboard(r.Context(), port.GetUserProfileDashboardCommand{
		TenantID:      tenantUUID,
		PartitionID:   partitionID,
		UserProfileID: userProfile.ID,
	})
	if err != nil {
		h.writeWebHTMLError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)

	// 2. Instruct HTMX to push the target dashboard URL straight into browser history
	w.Header().Set(model.HeaderHxPushUrl, port.RouteWebProfile)
	w.WriteHeader(http.StatusOK)

	// 3. Stream the full refreshed dashboard, explicitly passing the text string down down-funnel
	successConfirmation := "Password credentials successfully updated."
	component := public.ProfileDashboard(dashboardResp.UserProfile, dashboardResp.Identities, dashboardResp.Providers, dashboardResp.HasPasswordIDP, "", successConfirmation)
	_ = component.Render(r.Context(), w)
}

func (h *ProfileHandler) HandleChangeEmailForm(w http.ResponseWriter, r *http.Request) {
	tenantUUID := TenantIDFromContext(r.Context())
	userProfile, _, err := h.resolveAuthenticatedUser(r, tenantUUID)
	if err != nil {
		http.Redirect(w, r, port.RouteRoot, http.StatusSeeOther)
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	_ = public.ChangeEmailPage(userProfile.Email, make(map[string]string), "").Render(r.Context(), w)
}

func (h *ProfileHandler) HandleChangeEmailSubmit(w http.ResponseWriter, r *http.Request) {
	tenantUUID := TenantIDFromContext(r.Context())
	userProfile, partitionID, err := h.resolveAuthenticatedUser(r, tenantUUID)
	if err != nil {
		http.Redirect(w, r, port.RouteRoot, http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderEmailPageStatus(w, userProfile.Email, r.FormValue("new_email"), r.FormValue("confirm_email"), map[string]string{"global": "Malformed payload parameters submitted"}, "")
		return
	}

	newEmail := r.FormValue("new_email")
	confirmEmail := r.FormValue("confirm_email")
	currentPassword := r.FormValue("current_password")

	if newEmail != confirmEmail {
		h.renderEmailPageStatus(w, userProfile.Email, newEmail, confirmEmail, map[string]string{"confirm_email": "New email addresses do not match"}, "")
		return
	}

	// Map elements straight into a type-safe Command struct
	cmd := port.ChangeEmailCommand{
		TenantID:        tenantUUID,
		PartitionID:     partitionID,
		UserProfileID:   userProfile.ID,
		CurrentPassword: currentPassword,
		NewEmail:        newEmail,
	}

	err = h.userProfileUseCase.ChangeUserEmail(r.Context(), cmd)
	if err != nil {
		var valErr *port.ValidationError
		if errors.As(err, &valErr) {
			h.renderEmailPageStatus(w, userProfile.Email, newEmail, confirmEmail, valErr.Fields, "")
			return
		}
		h.renderEmailPageStatus(w, userProfile.Email, newEmail, confirmEmail, map[string]string{"global": err.Error()}, "")
		return
	}

	// 1. Fetch updated workspace state details to populate the fresh dashboard layout view safely
	dashboardResp, err := h.userProfileUseCase.GetUserProfileDashboard(r.Context(), port.GetUserProfileDashboardCommand{
		TenantID:      tenantUUID,
		PartitionID:   partitionID,
		UserProfileID: userProfile.ID,
	})
	if err != nil {
		h.writeWebHTMLError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)

	// 2. Instruct HTMX to push the target dashboard URL straight into browser history
	w.Header().Set(model.HeaderHxPushUrl, port.RouteWebProfile)
	w.WriteHeader(http.StatusOK)

	// 3. Stream the full refreshed dashboard, explicitly passing the text string down down-funnel
	successConfirmation := "Email address successfully updated."
	component := public.ProfileDashboard(dashboardResp.UserProfile, dashboardResp.Identities, dashboardResp.Providers, dashboardResp.HasPasswordIDP, "", successConfirmation)
	_ = component.Render(r.Context(), w)
}

func (h *ProfileHandler) HandleChangeNameForm(w http.ResponseWriter, r *http.Request) {
	tenantUUID := TenantIDFromContext(r.Context())
	userProfile, _, err := h.resolveAuthenticatedUser(r, tenantUUID)
	if err != nil {
		http.Redirect(w, r, port.RouteRoot, http.StatusSeeOther)
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	_ = public.ChangeNamePage(userProfile.Name, make(map[string]string), "").Render(r.Context(), w)
}

func (h *ProfileHandler) HandleChangeNameSubmit(w http.ResponseWriter, r *http.Request) {
	tenantUUID := TenantIDFromContext(r.Context())
	userProfile, partitionID, err := h.resolveAuthenticatedUser(r, tenantUUID)
	if err != nil {
		http.Redirect(w, r, port.RouteRoot, http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderNamePageStatus(w, userProfile.Name, r.FormValue("new_name"), map[string]string{"global": "Malformed payload parameters submitted"}, "")
		return
	}

	newName := r.FormValue("new_name")

	cmd := port.ChangeNameCommand{
		TenantID:      tenantUUID,
		PartitionID:   partitionID,
		UserProfileID: userProfile.ID,
		NewName:       newName,
	}

	err = h.userProfileUseCase.ChangeUserName(r.Context(), cmd)
	if err != nil {
		var valErr *port.ValidationError
		if errors.As(err, &valErr) {
			h.renderNamePageStatus(w, userProfile.Name, newName, valErr.Fields, "")
			return
		}
		h.renderNamePageStatus(w, userProfile.Name, newName, map[string]string{"global": err.Error()}, "")
		return
	}

	// 1. Fetch updated workspace state details to populate the fresh dashboard layout view safely
	dashboardResp, err := h.userProfileUseCase.GetUserProfileDashboard(r.Context(), port.GetUserProfileDashboardCommand{
		TenantID:      tenantUUID,
		PartitionID:   partitionID,
		UserProfileID: userProfile.ID,
	})
	if err != nil {
		h.writeWebHTMLError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)

	// 2. Instruct HTMX to push the target dashboard URL straight into browser history
	w.Header().Set(model.HeaderHxPushUrl, port.RouteWebProfile)
	w.WriteHeader(http.StatusOK)

	// 3. Stream the full refreshed dashboard, explicitly passing the text string down down-funnel
	successConfirmation := "Display name successfully updated."
	component := public.ProfileDashboard(dashboardResp.UserProfile, dashboardResp.Identities, dashboardResp.Providers, dashboardResp.HasPasswordIDP, "", successConfirmation)
	_ = component.Render(r.Context(), w)
}

func (h *ProfileHandler) HandleDecoupleIdentitySubmit(w http.ResponseWriter, r *http.Request) {
	tenantUUID := TenantIDFromContext(r.Context())
	userProfile, partitionID, err := h.resolveAuthenticatedUser(r, tenantUUID)
	if err != nil {
		w.Header().Set(model.HeaderHxRedirect, port.RouteRoot)
		w.WriteHeader(http.StatusOK)
		return
	}

	idpIDStr := chi.URLParam(r, "idpID")
	targetProviderUUID, err := uuid.Parse(idpIDStr)
	if err != nil {
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<script>alert("Invalid identity provider identifier constraint");</script>`))
		return
	}

	cmd := port.DecoupleIdentityCommand{
		TenantID:           tenantUUID,
		PartitionID:        partitionID,
		UserProfileID:      userProfile.ID,
		IdentityProviderID: targetProviderUUID,
	}

	err = h.userProfileUseCase.DecoupleUserIdentity(r.Context(), cmd)
	if err != nil {
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `<script>alert("%s");</script>`, err.Error())
		return
	}

	w.Header().Set(model.HeaderHxRedirect, port.RouteWebProfile)
	w.WriteHeader(http.StatusOK)
}

func (h *ProfileHandler) authenticateSessionUser(r *http.Request, tenantID uuid.UUID) (string, int64, error) {
	// 1. INTENTIONAL PASS 1: Calculate the exact dynamic cookie name expected for this specific request context.
	// If the user is navigating from an administrative workspace, we fetch that specification first.
	defaultSpec, _ := h.ssoUseCase.BuildSessionCookie(r.Context(), port.CookieIntentCommand{
		TenantID:       tenantID,
		LifecycleStage: "clear", // Resolves to spz_session_default
		RequestHost:    r.Host,
	})

	// 2. Loop over cookies but prioritize non-default partition keys first (like sprezz_admin or others)
	for _, cookie := range r.Cookies() {
		if !strings.HasPrefix(cookie.Name, "spz_session_") && !strings.HasPrefix(cookie.Name, "sprezz_") {
			continue
		}
		// Skip the default fallback cookie on Pass 1 to allow privileged keys to claim priority
		if cookie.Name == defaultSpec.CookieName {
			continue
		}

		stage, payload, parseErr := h.ssoUseCase.ParseSessionCookie(r.Context(), cookie.Value)
		if parseErr == nil && stage == "bearer" {
			if parts := strings.Split(payload, ":"); len(parts) >= 2 {
				if partitionID, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
					return parts[0], partitionID, nil
				}
			}
		}
	}

	// 3. INTENTIONAL PASS 2: Fall back to checking the default consumer session cookie
	if defaultCookie, err := r.Cookie(defaultSpec.CookieName); err == nil && defaultCookie.Value != "" {
		stage, payload, parseErr := h.ssoUseCase.ParseSessionCookie(r.Context(), defaultCookie.Value)
		if parseErr == nil && stage == "bearer" {
			if parts := strings.Split(payload, ":"); len(parts) >= 2 {
				if partitionID, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
					return parts[0], partitionID, nil
				}
			}
		}
	}

	return "", 0, port.ErrInvalidGrant
}

func (h *ProfileHandler) resolveAuthenticatedUser(r *http.Request, tenantID uuid.UUID) (*model.UserProfile, int64, error) {
	subjectID, partitionID, err := h.authenticateSessionUser(r, tenantID)
	if err != nil {
		return nil, 0, err
	}

	parsedUserUUID, err := uuid.Parse(subjectID)
	if err != nil {
		return nil, 0, err
	}

	profile, err := h.userProfileUseCase.GetUserProfile(r.Context(), port.GetUserProfileCommand{
		TenantID:      tenantID,
		PartitionID:   partitionID,
		UserProfileID: parsedUserUUID,
	})
	if err != nil {
		return nil, 0, err
	}

	return profile, partitionID, nil
}

func (h *ProfileHandler) renderPasswordPageStatus(w http.ResponseWriter, fieldErrors map[string]string, success string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	w.WriteHeader(http.StatusOK)
	_ = public.ChangePasswordForm(fieldErrors, success).Render(context.Background(), w)
}

func (h *ProfileHandler) renderEmailPageStatus(w http.ResponseWriter, currentEmail, typedNewEmail, typedConfirmEmail string, fieldErrors map[string]string, success string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	w.WriteHeader(http.StatusOK)
	_ = public.ChangeEmailForm(currentEmail, typedNewEmail, typedConfirmEmail, fieldErrors, success).Render(context.Background(), w)
}

func (h *ProfileHandler) renderNamePageStatus(w http.ResponseWriter, currentName, typedNewName string, fieldErrors map[string]string, success string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	w.WriteHeader(http.StatusOK)
	_ = public.ChangeNameForm(currentName, typedNewName, fieldErrors, success).Render(context.Background(), w)
}

func (h *ProfileHandler) writeWebHTMLError(w http.ResponseWriter, status int, desc string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	w.WriteHeader(status)
	_ = public.Error(desc).Render(context.Background(), w)
}
