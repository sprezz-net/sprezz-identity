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

// AdminTenantHandler serves the tenant pages under /admin/tenants. Which tenants a session may see or change is
// decided by AdminTenantService, not here, so the rule cannot be bypassed by a new route.
type AdminTenantHandler struct {
	*HttpAdapter
}

func NewAdminTenantHandler(adapter *HttpAdapter) *AdminTenantHandler {
	return &AdminTenantHandler{HttpAdapter: adapter}
}

// Routes mounts the tenant routes. The static "new" route is registered before the {id} routes.
func (h *AdminTenantHandler) Routes(r chi.Router) {
	r.Route(port.RouteAdminTenants, func(r chi.Router) {
		r.Get("/", h.list)
		r.Get("/new", h.newForm)
		r.Post("/", h.create)
		r.Get("/{id}", h.detail)
		r.Delete("/{id}", h.delete)
		r.Put("/{id}/{section}", h.saveSection)
	})
}

func (h *AdminTenantHandler) tenantID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, port.ErrTenantNotFound.Error())
		return uuid.Nil, false
	}
	return id, true
}

// list shows the tenants the signed-in tenant may see. A customer tenant therefore sees only itself.
func (h *AdminTenantHandler) list(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	rows, err := h.adminTenantUseCase.ListTenants(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	q := r.URL.Query()
	props := admin.TenantListProps{
		ActiveTenant: *tenant, Msg: q.Get("msg"), Query: strings.TrimSpace(q.Get("q")), CanManageAll: tenant.IsSystem,
	}
	props.Rows = filterTenantRows(rows, props.Query)
	h.renderAdminPage(w, r, admin.TenantsContent(props), admin.TenantsPage(props))
}

func filterTenantRows(rows []port.TenantDetail, query string) []port.TenantDetail {
	if query == "" {
		return rows
	}
	needle := strings.ToLower(query)
	out := make([]port.TenantDetail, 0, len(rows))
	for _, row := range rows {
		if strings.Contains(strings.ToLower(row.Tenant.Name), needle) || strings.Contains(strings.ToLower(row.Tenant.Domain), needle) {
			out = append(out, row)
		}
	}
	return out
}

// loadPage reads everything the detail page needs.
func (h *AdminTenantHandler) loadPage(r *http.Request, tenant *model.Tenant, id uuid.UUID) (admin.TenantPageProps, error) {
	detail, err := h.adminTenantUseCase.GetTenant(r.Context(), tenant.ID, id)
	if err != nil {
		return admin.TenantPageProps{}, err
	}
	return admin.TenantPageProps{
		ActiveTenant: *tenant, Detail: detail, CanManageAll: tenant.IsSystem,
		Msg: r.URL.Query().Get("msg"), Sections: map[string]admin.SectionResult{},
	}, nil
}

func (h *AdminTenantHandler) detail(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	props, err := h.loadPage(r, tenant, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	h.renderAdminPage(w, r, admin.TenantContent(props), admin.TenantPage(props))
}
