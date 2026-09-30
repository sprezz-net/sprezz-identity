package http

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// AdminIDPHandler serves the identity provider pages under /admin/idps.
type AdminIDPHandler struct {
	*HttpAdapter
}

func NewAdminIDPHandler(adapter *HttpAdapter) *AdminIDPHandler {
	return &AdminIDPHandler{HttpAdapter: adapter}
}

// Routes mounts the provider routes. The static "new" route is registered before the {id} routes.
func (h *AdminIDPHandler) Routes(r chi.Router) {
	r.Route(port.RouteAdminIdentityProviders, func(r chi.Router) {
		r.Get("/", h.list)
		r.Get("/new", h.newForm)
		r.Post("/", h.create)
		r.Get("/{id}", h.detail)
		r.Delete("/{id}", h.delete)
		r.Put("/{id}/{section}", h.saveSection)
	})
}

func (h *AdminIDPHandler) idpID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, port.ErrIdentityProviderNotFound.Error())
		return uuid.Nil, false
	}
	return id, true
}

// list shows the providers with their usage. Search and filters run on the server.
func (h *AdminIDPHandler) list(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	providers, err := h.idpService.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	usage, err := h.idpService.GetIdentityProviderUsage(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	partitions, err := h.storagePort.GetPartitions(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	q := r.URL.Query()
	props := admin.IDPListProps{
		ActiveTenant: *tenant, Partitions: partitions, Msg: q.Get("msg"),
		Query: strings.TrimSpace(q.Get("q")), Type: q.Get("type"), Status: q.Get("status"),
	}
	props.PartitionID, _ = strconv.ParseInt(q.Get("partition_id"), 10, 64)
	props.Rows = filterIDPRows(providers, usage, partitions, props)
	h.renderAdminPage(w, r, admin.IDPsContent(props), admin.IDPsPage(props))
}

func filterIDPRows(providers []model.IdentityProvider, usage map[uuid.UUID]model.IdentityProviderUsage, partitions []model.Partition, f admin.IDPListProps) []admin.IDPRow {
	names := map[int64]string{}
	for _, p := range partitions {
		names[p.ID] = partitionName(p)
	}
	rows := make([]admin.IDPRow, 0, len(providers))
	for _, p := range providers {
		if !matchesIDPFilter(p, f) {
			continue
		}
		rows = append(rows, admin.IDPRow{Provider: p, Usage: usage[p.ID], PartitionName: names[p.PartitionID]})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return strings.ToLower(rows[i].Provider.Name) < strings.ToLower(rows[j].Provider.Name)
	})
	return rows
}

func matchesIDPFilter(p model.IdentityProvider, f admin.IDPListProps) bool {
	if f.PartitionID > 0 && p.PartitionID != f.PartitionID {
		return false
	}
	if f.Type != "" && p.IDPType != f.Type {
		return false
	}
	if (f.Status == "active" && !p.Enabled) || (f.Status == "disabled" && p.Enabled) {
		return false
	}
	if f.Query != "" {
		needle := strings.ToLower(f.Query)
		return strings.Contains(strings.ToLower(p.Name), needle) || strings.Contains(strings.ToLower(p.Alias), needle)
	}
	return true
}

func partitionName(p model.Partition) string {
	if p.AliasName != "" {
		return p.AliasName
	}
	return p.Name
}

// loadPage reads everything the detail page needs.
func (h *AdminIDPHandler) loadPage(r *http.Request, tenant *model.Tenant, id uuid.UUID) (admin.IDPPageProps, error) {
	provider, err := h.idpService.GetIdentityProvider(r.Context(), tenant.ID, id)
	if err != nil {
		return admin.IDPPageProps{}, err
	}
	usage, err := h.idpService.GetIdentityProviderUsage(r.Context(), tenant.ID)
	if err != nil {
		return admin.IDPPageProps{}, err
	}
	partitions, err := h.storagePort.GetPartitions(r.Context(), tenant.ID)
	if err != nil {
		return admin.IDPPageProps{}, err
	}
	props := admin.IDPPageProps{
		ActiveTenant: *tenant, Provider: provider, Usage: usage[id],
		Msg: r.URL.Query().Get("msg"), Sections: map[string]admin.SectionResult{},
	}
	for _, p := range partitions {
		if p.ID == provider.PartitionID {
			props.PartitionName = partitionName(p)
		}
	}
	return props, nil
}

func (h *AdminIDPHandler) detail(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id, ok := h.idpID(w, r)
	if !ok {
		return
	}
	props, err := h.loadPage(r, tenant, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	h.renderAdminPage(w, r, admin.IDPContent(props), admin.IDPPage(props))
}
