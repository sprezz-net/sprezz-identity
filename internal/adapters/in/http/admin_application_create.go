package http

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/views/admin"

	"github.com/google/uuid"
)

// clientIDPattern allows the RFC 3986 unreserved characters only.
var clientIDPattern = regexp.MustCompile(`^[a-zA-Z0-9\-_.~]+$`)

func (h *AdminApplicationHandler) newForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	groups, profiles, err := h.groupsAndProfiles(r, tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	props := admin.CreateFormProps{ActiveTenant: *tenant, Errors: map[string]string{}, Values: map[string]string{}}
	h.renderAdminPage(w, r, admin.NewApplicationContent(props, groups, profiles), admin.NewApplicationPage(props, groups, profiles))
}

func (h *AdminApplicationHandler) groupsAndProfiles(r *http.Request, tenantID uuid.UUID) ([]model.ApplicationGroup, []model.ApplicationProfile, error) {
	groups, err := h.adminApplicationUseCase.GetGroups(r.Context(), tenantID)
	if err != nil {
		return nil, nil, err
	}
	profiles, err := h.adminApplicationUseCase.GetProfiles(r.Context(), tenantID)
	if err != nil {
		return nil, nil, err
	}
	return groups, profiles, nil
}

// createInput is the validated content of the create form.
type createInput struct {
	clientID, name   string
	groupID, profile uuid.UUID
}

func parseCreateForm(r *http.Request) (createInput, map[string]string) {
	errs := map[string]string{}
	in := createInput{
		clientID: strings.TrimSpace(r.FormValue("client_id")),
		name:     strings.TrimSpace(r.FormValue("application_name")),
	}
	if in.name == "" {
		errs["application_name"] = "an application name is required"
	}
	if !clientIDPattern.MatchString(in.clientID) {
		errs["client_id"] = "use letters, digits and - _ . ~ only"
	}
	in.groupID = requiredUUID(r.FormValue("group_id"), "group_id", "choose a group", errs, uuid.Nil)
	in.profile = requiredUUID(r.FormValue("profile_id"), "profile_id", "choose a profile", errs, uuid.Nil)
	return in, errs
}

func (h *AdminApplicationHandler) renderCreateApplicationErrors(w http.ResponseWriter, r *http.Request, tenant *model.Tenant, in createInput, errs map[string]string) {
	groups, profiles, err := h.groupsAndProfiles(r, tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	values := map[string]string{"client_id": in.clientID, "application_name": in.name}
	if in.groupID != uuid.Nil {
		values["group_id"] = fmt.Sprint(in.groupID)
	}
	if in.profile != uuid.Nil {
		values["profile_id"] = fmt.Sprint(in.profile)
	}
	props := admin.CreateFormProps{ActiveTenant: *tenant, Errors: errs, Values: values}
	h.renderFragment(w, r, http.StatusUnprocessableEntity, admin.NewApplicationContent(props, groups, profiles))
}
