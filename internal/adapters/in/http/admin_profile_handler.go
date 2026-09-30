package http

import (
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

// AdminProfileHandler serves the profile pages under /admin/applications/profiles.
type AdminProfileHandler struct {
	*HttpAdapter
}

func NewAdminProfileHandler(adapter *HttpAdapter) *AdminProfileHandler {
	return &AdminProfileHandler{HttpAdapter: adapter}
}

// Routes mounts the profile routes. The static "new" route is registered before the {id} routes.
func (h *AdminProfileHandler) Routes(r chi.Router) {
	r.Route(port.RouteAdminApplicationsProfiles, func(r chi.Router) {
		r.Get("/", h.list)
		r.Get("/new", h.newForm)
		r.Post("/", h.create)
		r.Get("/{id}", h.detail)
		r.Delete("/{id}", h.delete)
		r.Put("/{id}/{section}", h.saveSection)
	})
}

func profilesBase() string {
	return applicationsBase() + port.RouteAdminApplicationsProfiles
}

func profileURL(id uuid.UUID) string {
	return profilesBase() + "/" + id.String()
}

func (h *AdminProfileHandler) profileID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, port.ErrProfileNotFound.Error())
		return uuid.Nil, false
	}
	return id, true
}

func (h *AdminProfileHandler) list(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	profiles, err := h.adminApplicationUseCase.GetProfiles(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	counts, err := h.adminNavCounts(r, tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	props := admin.ListPageProps{ActiveTenant: *tenant, Counts: counts, Profiles: profiles, Msg: r.URL.Query().Get("msg")}
	h.renderAdminPage(w, r, admin.ProfilesListContent(props), admin.ProfilesListPage(props))
}

func (h *AdminProfileHandler) detail(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id, ok := h.profileID(w, r)
	if !ok {
		return
	}
	props, err := h.loadProfilePage(r, tenant, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	h.renderAdminPage(w, r, admin.ProfileContent(props), admin.ProfilePage(props))
}

func (h *AdminProfileHandler) loadProfilePage(r *http.Request, tenant *model.Tenant, id uuid.UUID) (admin.ProfilePageProps, error) {
	profile, err := h.adminApplicationUseCase.GetProfile(r.Context(), tenant.ID, id)
	if err != nil {
		return admin.ProfilePageProps{}, err
	}
	usedBy, err := h.adminApplicationUseCase.ListApplicationsByProfile(r.Context(), tenant.ID, id)
	if err != nil {
		return admin.ProfilePageProps{}, err
	}
	return admin.ProfilePageProps{
		ActiveTenant: *tenant,
		Profile:      profile,
		UsedBy:       usedBy,
		Msg:          r.URL.Query().Get("msg"),
		Sections:     map[string]admin.SectionResult{},
	}, nil
}

// parseLifetime reads a whole number of seconds; anything else is reported against the field.
func parseLifetime(raw, field string, errs map[string]string) time.Duration {
	seconds, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || seconds <= 0 {
		errs[field] = "enter a positive whole number"
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func parseGrantTypes(values []string) []model.GrantType {
	grants := []model.GrantType{}
	for _, v := range CleanBoundaryStringSlice(append([]string{}, values...)) {
		grants = append(grants, model.GrantType(v))
	}
	return grants
}
