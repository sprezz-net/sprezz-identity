package http

import (
	"net/http"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// AdminGroupHandler serves the group pages under /admin/applications/groups.
type AdminGroupHandler struct {
	*HttpAdapter
}

func NewAdminGroupHandler(adapter *HttpAdapter) *AdminGroupHandler {
	return &AdminGroupHandler{HttpAdapter: adapter}
}

// Routes mounts the group routes. The static "new" route is registered before the {id} routes.
func (h *AdminGroupHandler) Routes(r chi.Router) {
	r.Route(port.RouteAdminApplicationsGroups, func(r chi.Router) {
		r.Get("/", h.list)
		r.Get("/new", h.newForm)
		r.Post("/", h.create)
		r.Get("/{id}", h.detail)
		r.Delete("/{id}", h.delete)
		r.Put("/{id}/{section}", h.saveSection)
	})
}

func (h *AdminGroupHandler) groupID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, port.ErrGroupNotFound.Error())
		return uuid.Nil, false
	}
	return id, true
}

func (h *AdminGroupHandler) list(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	groups, err := h.adminApplicationUseCase.GetGroups(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	counts, err := h.adminNavCounts(r, tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	props := admin.ListPageProps{ActiveTenant: *tenant, Counts: counts, Groups: groups, Msg: r.URL.Query().Get("msg")}
	h.renderAdminPage(w, r, admin.GroupsListContent(props), admin.GroupsListPage(props))
}

func (h *AdminGroupHandler) newForm(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	partitions, err := h.idpService.GetPartitionsWithProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	props := admin.CreateFormProps{ActiveTenant: *tenant, Errors: map[string]string{}, Values: map[string]string{}}
	h.renderAdminPage(w, r, admin.NewGroupContent(props, partitions), admin.NewGroupPage(props, partitions))
}

// create makes a group from a name and its sign-in methods, then continues on the new group's page.
func (h *AdminGroupHandler) create(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}

	errs := map[string]string{}
	name := strings.TrimSpace(r.FormValue("group_name"))
	if name == "" {
		errs["group_name"] = "a group name is required"
	}
	allowed := parseUUIDList(r.Form["allowed_idps"], "allowed_idps", errs)
	def := parseOptionalUUID(r.FormValue("default_idp_id"), "default_idp_id", errs)

	created, err := h.createGroupIfValid(r, tenant.ID, name, allowed, def, errs)
	if err != nil || len(errs) > 0 {
		h.renderCreateGroupErrors(w, r, tenant, name, errs, err)
		return
	}
	redirectTo(w, r, flashURL(groupURL(created.ID), "Group created. Add redirect URIs and scopes below."))
}

func groupURL(id uuid.UUID) string {
	return applicationsBase() + port.RouteAdminApplicationsGroups + "/" + id.String()
}

func applicationsBase() string {
	return port.RouteAdmin + port.RouteAdminApplications
}

func (h *AdminGroupHandler) createGroupIfValid(r *http.Request, tenantID uuid.UUID, name string, allowed []uuid.UUID, def *uuid.UUID, errs map[string]string) (*model.ApplicationGroup, error) {
	if len(errs) > 0 {
		return nil, nil
	}
	group, err := h.adminApplicationUseCase.CreateGroup(r.Context(), port.CreateGroupCommand{
		TenantID:      tenantID,
		GroupName:     name,
		AllowedIDPIDs: allowed,
		DefaultIDPID:  def,
		AllowedScopes: []string{"openid", "profile", "email"},
		DefaultScopes: []string{"openid"},
	})
	if err != nil {
		mergeFieldErrors(err, errs)
	}
	return group, err
}

func (h *AdminGroupHandler) renderCreateGroupErrors(w http.ResponseWriter, r *http.Request, tenant *model.Tenant, name string, errs map[string]string, err error) {
	if len(errs) == 0 && err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	partitions, perr := h.idpService.GetPartitionsWithProviders(r.Context(), tenant.ID)
	if perr != nil {
		h.renderDomainError(w, r, perr)
		return
	}
	props := admin.CreateFormProps{ActiveTenant: *tenant, Errors: errs, Values: map[string]string{"group_name": name}}
	h.renderFragment(w, r, http.StatusUnprocessableEntity, admin.NewGroupContent(props, partitions))
}
