package http

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type AdminUserHandler struct {
	*HttpAdapter
}

func NewAdminUserHandler(adapter *HttpAdapter) *AdminUserHandler {
	return &AdminUserHandler{HttpAdapter: adapter}
}

func (h *AdminUserHandler) Routes(r chi.Router) {
	r.Route(port.RouteAdminUsers, func(r chi.Router) {
		r.Get("/", h.adminUsersPage)
		r.Get("/view", h.adminViewUser)
		r.Get("/edit", h.adminEditUserForm)
		r.Post("/", h.adminSaveUser)
		r.Delete("/{id}", h.adminDeleteUser)
		r.Delete("/{id}/"+port.RouteAdminUsersIdentities+"/{idp}", h.adminDecoupleIdentity)
	})
}

func (h *AdminUserHandler) adminUsersPage(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())

	var filterPartitionID int64
	if pStr := r.URL.Query().Get("partition_id"); pStr != "" {
		filterPartitionID, _ = strconv.ParseInt(pStr, 10, 64)
	}

	partitions, err := h.storagePort.GetPartitions(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	var users []model.UserProfile
	if filterPartitionID > 0 {
		usrs, err := h.adminStorage.GetUserProfilesByTenant(r.Context(), tenant.ID, filterPartitionID)
		if err != nil {
			h.renderError(w, r, http.StatusInternalServerError, err.Error())
			return
		}
		users = usrs
	} else {
		for _, p := range partitions {
			usrs, err := h.adminStorage.GetUserProfilesByTenant(r.Context(), tenant.ID, p.ID)
			if err == nil {
				users = append(users, usrs...)
			}
		}
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	msg := r.URL.Query().Get("msg")
	props := admin.UsersPageProps{
		ActiveTenant:      *tenant,
		Users:             users,
		Partitions:        partitions,
		FilterPartitionID: filterPartitionID,
		Msg:               msg,
	}
	if r.Header.Get(model.HeaderHXRequest) == "true" {
		_ = admin.UsersContent(props).Render(r.Context(), w)
	} else {
		_ = admin.UsersPage(props).Render(r.Context(), w)
	}
}

func (h *AdminUserHandler) adminViewUser(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	userIDStr := r.URL.Query().Get("id")
	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, errInvalidUserUUID)
		return
	}

	partitionIDStr := r.URL.Query().Get("partition_id")
	partitionID, _ := strconv.ParseInt(partitionIDStr, 10, 64)

	user, err := h.storagePort.GetUserProfileByID(r.Context(), tenant.ID, partitionID, userUUID)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, err.Error())
		return
	}

	identities, err := h.adminStorage.GetUserIdentities(r.Context(), userUUID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	providers, err := h.idpService.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal(user.Name, fmt.Sprintf("/admin/users/view?id=%s&partition_id=%d", userIDStr, partitionID))
		_ = component.Render(r.Context(), w)
		return
	}
	component := admin.UserDetails(admin.UserDetailsProps{
		User:       *user,
		Identities: identities,
		Providers:  providers,
	})
	_ = component.Render(r.Context(), w)
}

func (h *AdminUserHandler) adminEditUserForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	userIDStr := r.URL.Query().Get("id")
	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, errInvalidUserUUID)
		return
	}

	partitionIDStr := r.URL.Query().Get("partition_id")
	partitionID, _ := strconv.ParseInt(partitionIDStr, 10, 64)

	user, err := h.storagePort.GetUserProfileByID(r.Context(), tenant.ID, partitionID, userUUID)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, err.Error())
		return
	}

	partitions, err := h.storagePort.GetPartitions(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if r.URL.Query().Get("modal") == "true" {
		component := admin.Modal("Edit User", fmt.Sprintf("/admin/users/edit?id=%s&partition_id=%d", userIDStr, partitionID))
		_ = component.Render(r.Context(), w)
		return
	}
	component := admin.UserForm(admin.UserFormProps{
		User:       *user,
		Partitions: partitions,
		Errors:     nil,
	})
	_ = component.Render(r.Context(), w)
}

func (h *AdminUserHandler) adminSaveUser(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id := r.FormValue("id")
	userUUID, err := uuid.Parse(id)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, errInvalidUserUUID)
		return
	}

	partitionIDStr := r.FormValue("partition_id")
	partitionID, _ := strconv.ParseInt(partitionIDStr, 10, 64)

	user, err := h.storagePort.GetUserProfileByID(r.Context(), tenant.ID, partitionID, userUUID)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, err.Error())
		return
	}

	fullName := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")

	errs := make(map[string]string)
	if fullName == "" {
		errs["name"] = "Full name is required"
	}
	if email == "" {
		errs["email"] = "Email address is required"
	}

	if len(errs) > 0 {
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusUnprocessableEntity)
		partitions, _ := h.storagePort.GetPartitions(r.Context(), tenant.ID)
		component := admin.UserForm(admin.UserFormProps{
			User:       *user,
			Partitions: partitions,
			Errors:     errs,
		})
		_ = component.Render(r.Context(), w)
		return
	}

	user.Name = fullName
	user.Email = email

	if password != "" {
		hash, err := h.cryptoPort.HashCredential(password)
		if err != nil {
			h.renderError(w, r, http.StatusInternalServerError, "failed to hash password")
			return
		}
		// Try to find the local username-password provider for this user's partition
		providers, err := h.storagePort.GetIdentityProviders(r.Context(), tenant.ID)
		if err == nil {
			var localIDP *model.IdentityProvider
			for _, p := range providers {
				if p.IDPType == model.UsernamePasswordIDPType && p.PartitionID == user.PartitionID {
					localIDP = &p
					break
				}
			}
			if localIDP != nil {
				// Get or create password credential
				passwordCred, err := h.storagePort.GetPasswordCredentialByProfileID(r.Context(), tenant.ID, user.PartitionID, user.ID, localIDP.ID)
				if err != nil {
					// Create new
					passwordCred = &model.PasswordCredential{
						UserProfileID:      user.ID,
						IdentityProviderID: localIDP.ID,
						Argon2Hash:         hash,
					}
				} else {
					passwordCred.Argon2Hash = hash
				}
				_ = h.storagePort.SavePasswordCredential(r.Context(), *passwordCred)
			}
		}
	}

	err = h.adminStorage.UpdateUserProfile(r.Context(), tenant.ID, *user)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(model.HeaderHXRedirect, fmt.Sprintf("/admin/users?msg=User+%s+updated+successfully", url.QueryEscape(user.Name)))
	w.WriteHeader(http.StatusOK)
}

func (h *AdminUserHandler) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	userIDStr := chi.URLParam(r, "id")
	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, errInvalidUserUUID, http.StatusBadRequest)
		return
	}

	partitionIDStr := r.URL.Query().Get("partition_id")
	partitionID, _ := strconv.ParseInt(partitionIDStr, 10, 64)

	if err := h.adminStorage.DeleteUserProfile(r.Context(), tenant.ID, partitionID, userUUID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set(hxRedirectHeader, "/admin/users?msg=User+deleted+successfully")
	w.WriteHeader(http.StatusOK)
}

func (h *AdminUserHandler) adminDecoupleIdentity(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	userIDStr := chi.URLParam(r, "id")
	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, errInvalidUserUUID, http.StatusBadRequest)
		return
	}

	idpIDStr := chi.URLParam(r, "idp")
	idpUUID, err := uuid.Parse(idpIDStr)
	if err != nil {
		http.Error(w, errInvalidIDPUUID, http.StatusBadRequest)
		return
	}

	partitionIDStr := r.URL.Query().Get("partition_id")
	partitionID, _ := strconv.ParseInt(partitionIDStr, 10, 64)

	cmd := port.DecoupleIdentityCommand{
		TenantID:           tenant.ID,
		PartitionID:        partitionID,
		UserProfileID:      userUUID,
		IdentityProviderID: idpUUID,
	}

	if err := h.userProfileUseCase.DecoupleUserIdentity(r.Context(), cmd); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch updated details to re-render in modal body
	user, err := h.storagePort.GetUserProfileByID(r.Context(), tenant.ID, partitionID, userUUID)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, err.Error())
		return
	}

	identities, err := h.adminStorage.GetUserIdentities(r.Context(), userUUID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	providers, err := h.idpService.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	component := admin.UserDetails(admin.UserDetailsProps{
		User:       *user,
		Identities: identities,
		Providers:  providers,
	})
	_ = component.Render(r.Context(), w)
}
