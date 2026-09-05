package http

import (
	"context"
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
	r.Route("/profile", func(r chi.Router) {
		r.Get("/", h.HandleViewDashboard)
		r.Get("/password", h.HandleChangePasswordForm)
		r.Post("/password", h.HandleChangePasswordSubmit)
		r.Get("/email", h.HandleChangeEmailForm)
		r.Post("/email", h.HandleChangeEmailSubmit)
		r.Get("/name", h.HandleChangeNameForm)
		r.Post("/name", h.HandleChangeNameSubmit)
		r.Delete("/identities/{idpID}", h.HandleDecoupleIdentitySubmit)
	})
}

func (h *ProfileHandler) HandleViewDashboard(w http.ResponseWriter, r *http.Request) {
	tenantUUID := h.mustResolveTenant(r.Context())
	subjectID, partitionID, err := h.authenticateSessionUser(r, tenantUUID)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
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

	w.Header().Set(model.HeaderContentType, "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	component := public.ProfileDashboard(dashboardResp.UserProfile, dashboardResp.Identities, dashboardResp.Providers, dashboardResp.HasPasswordIDP, "", "")
	_ = component.Render(r.Context(), w)
}

func (h *ProfileHandler) HandleChangePasswordForm(w http.ResponseWriter, r *http.Request) {
	tenantUUID := h.mustResolveTenant(r.Context())
	userProfile, _, err := h.resolveAuthenticatedUser(r, tenantUUID)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = public.ChangePasswordPage(*userProfile, "", "").Render(r.Context(), w)
}

func (h *ProfileHandler) HandleChangePasswordSubmit(w http.ResponseWriter, r *http.Request) {
	tenantUUID := h.mustResolveTenant(r.Context())
	userProfile, partitionID, err := h.resolveAuthenticatedUser(r, tenantUUID)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderPasswordPageStatus(w, r, *userProfile, "Malformed payload parameters submitted", "")
		return
	}

	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")
	currentPassword := r.FormValue("current_password")

	if newPassword != confirmPassword {
		h.renderPasswordPageStatus(w, r, *userProfile, "New password fields do not match", "")
		return
	}

	// 🌟 FIXED: Map elements straight into a type-safe Command struct
	cmd := port.ChangePasswordCommand{
		TenantID:        tenantUUID,
		PartitionID:     partitionID,
		UserProfileID:   userProfile.ID,
		CurrentPassword: currentPassword,
		NewPassword:     newPassword,
	}

	err = h.userProfileUseCase.ChangeUserPassword(r.Context(), cmd)
	if err != nil {
		h.renderPasswordPageStatus(w, r, *userProfile, err.Error(), "")
		return
	}

	h.renderPasswordPageStatus(w, r, *userProfile, "", "Password credentials successfully updated.")
}

func (h *ProfileHandler) HandleChangeEmailForm(w http.ResponseWriter, r *http.Request) {
	tenantUUID := h.mustResolveTenant(r.Context())
	userProfile, _, err := h.resolveAuthenticatedUser(r, tenantUUID)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = public.ChangeEmailPage(*userProfile, "", "").Render(r.Context(), w)
}

func (h *ProfileHandler) HandleChangeEmailSubmit(w http.ResponseWriter, r *http.Request) {
	tenantUUID := h.mustResolveTenant(r.Context())
	userProfile, partitionID, err := h.resolveAuthenticatedUser(r, tenantUUID)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderEmailPageStatus(w, r, *userProfile, "Malformed payload parameters submitted", "")
		return
	}

	newEmail := r.FormValue("new_email")
	confirmEmail := r.FormValue("confirm_email")
	currentPassword := r.FormValue("current_password")

	if newEmail != confirmEmail {
		h.renderEmailPageStatus(w, r, *userProfile, "New email addresses do not match", "")
		return
	}

	// 🌟 FIXED: Map elements straight into a type-safe Command struct
	cmd := port.ChangeEmailCommand{
		TenantID:        tenantUUID,
		PartitionID:     partitionID,
		UserProfileID:   userProfile.ID,
		CurrentPassword: currentPassword,
		NewEmail:        newEmail,
	}

	err = h.userProfileUseCase.ChangeUserEmail(r.Context(), cmd)
	if err != nil {
		h.renderEmailPageStatus(w, r, *userProfile, err.Error(), "")
		return
	}

	userProfile.Email = newEmail
	h.renderEmailPageStatus(w, r, *userProfile, "", "Email address successfully updated.")
}

func (h *ProfileHandler) HandleChangeNameForm(w http.ResponseWriter, r *http.Request) {
	tenantUUID := h.mustResolveTenant(r.Context())
	userProfile, _, err := h.resolveAuthenticatedUser(r, tenantUUID)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = public.ChangeNamePage(*userProfile, "", "").Render(r.Context(), w)
}

func (h *ProfileHandler) HandleChangeNameSubmit(w http.ResponseWriter, r *http.Request) {
	tenantUUID := h.mustResolveTenant(r.Context())
	userProfile, partitionID, err := h.resolveAuthenticatedUser(r, tenantUUID)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderNamePageStatus(w, r, *userProfile, "Malformed payload parameters submitted", "")
		return
	}

	newName := r.FormValue("new_name")

	// 🌟 FIXED: Map elements straight into a type-safe Command struct
	cmd := port.ChangeNameCommand{
		TenantID:      tenantUUID,
		PartitionID:   partitionID,
		UserProfileID: userProfile.ID,
		NewName:       newName,
	}

	err = h.userProfileUseCase.ChangeUserName(r.Context(), cmd)
	if err != nil {
		h.renderNamePageStatus(w, r, *userProfile, err.Error(), "")
		return
	}

	userProfile.Name = newName
	h.renderNamePageStatus(w, r, *userProfile, "", "Display name successfully updated.")
}

func (h *ProfileHandler) HandleDecoupleIdentitySubmit(w http.ResponseWriter, r *http.Request) {
	tenantUUID := h.mustResolveTenant(r.Context())
	userProfile, partitionID, err := h.resolveAuthenticatedUser(r, tenantUUID)
	if err != nil {
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
		return
	}

	idpIDStr := chi.URLParam(r, "idpID")
	targetProviderUUID, err := uuid.Parse(idpIDStr)
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<script>alert("Invalid identity provider identifier constraint");</script>`))
		return
	}

	// 🌟 FIXED: Map elements straight into a type-safe Command struct
	cmd := port.DecoupleIdentityCommand{
		TenantID:           tenantUUID,
		PartitionID:        partitionID,
		UserProfileID:      userProfile.ID,
		IdentityProviderID: targetProviderUUID,
	}

	err = h.userProfileUseCase.DecoupleUserIdentity(r.Context(), cmd)
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `<script>alert("%s");</script>`, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/profile")
	w.WriteHeader(http.StatusOK)
}

func (h *ProfileHandler) authenticateSessionUser(r *http.Request, tenantID uuid.UUID) (string, int64, error) {
	cookieSpec, err := h.ssoUseCase.BuildSessionCookie(r.Context(), port.CookieIntentCommand{
		TenantID:       tenantID,
		LifecycleStage: "clear",
		RequestHost:    r.Host,
	})
	if err != nil {
		return "", 0, err
	}

	cookie, err := r.Cookie(cookieSpec.CookieName)
	if err != nil {
		return "", 0, err
	}

	stage, payload, err := h.ssoUseCase.ParseSessionCookie(r.Context(), cookie.Value)
	if err != nil || stage != "bearer" {
		return "", 0, port.ErrInvalidGrant
	}

	parts := strings.Split(payload, ":")
	if len(parts) < 2 {
		return "", 0, port.ErrInvalidGrant
	}

	partitionID, parseErr := strconv.ParseInt(parts[1], 10, 64)
	if parseErr != nil {
		return "", 0, port.ErrInvalidGrant
	}

	return parts[0], partitionID, nil
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

func (h *ProfileHandler) renderPasswordPageStatus(w http.ResponseWriter, r *http.Request, user model.UserProfile, err, success string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = public.ChangePasswordPage(user, err, success).Render(r.Context(), w)
}

func (h *ProfileHandler) renderEmailPageStatus(w http.ResponseWriter, r *http.Request, user model.UserProfile, err, success string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = public.ChangeEmailPage(user, err, success).Render(r.Context(), w)
}

func (h *ProfileHandler) renderNamePageStatus(w http.ResponseWriter, r *http.Request, user model.UserProfile, err, success string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = public.ChangeNamePage(user, err, success).Render(r.Context(), w)
}

func (h *ProfileHandler) mustResolveTenant(ctx context.Context) uuid.UUID {
	if val := ctx.Value(tenantIDCtxKey); val != nil {
		if uid, ok := val.(uuid.UUID); ok {
			return uid
		}
	}
	return uuid.Nil
}

func (h *ProfileHandler) writeWebHTMLError(w http.ResponseWriter, status int, desc string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = public.Error(desc).Render(context.Background(), w)
}
