package http

import (
	"net/http"
	"strconv"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// AdminUserHandler serves the user pages under /admin/users. A user is addressed by partition and ID, so a lookup
// is always scoped to the partition named in the path.
type AdminUserHandler struct {
	*HttpAdapter
}

func NewAdminUserHandler(adapter *HttpAdapter) *AdminUserHandler {
	return &AdminUserHandler{HttpAdapter: adapter}
}

// Routes mounts the user routes. The static "new" route is registered before the parameterized ones.
func (h *AdminUserHandler) Routes(r chi.Router) {
	r.Route(port.RouteAdminUsers, func(r chi.Router) {
		r.Get("/", h.list)
		r.Get("/new", h.newForm)
		r.Post("/", h.create)
		r.Get("/{partition}/{id}", h.detail)
		r.Delete("/{partition}/{id}", h.delete)
		r.Put("/{partition}/{id}/{section}", h.saveSection)
		r.Post("/{partition}/{id}/unlock", h.unlock)
		r.Delete("/{partition}/{id}"+port.RouteAdminUsersIdentities+"/{idp}", h.unlink)
	})
}

// target reads the partition and user from the path. A malformed value is reported as an unknown user.
func (h *AdminUserHandler) target(w http.ResponseWriter, r *http.Request) (int64, uuid.UUID, bool) {
	partition, perr := strconv.ParseInt(chi.URLParam(r, "partition"), 10, 64)
	id, uerr := uuid.Parse(chi.URLParam(r, "id"))
	if perr != nil || uerr != nil || partition <= 0 {
		h.renderError(w, r, http.StatusNotFound, port.ErrUserProfileNotFound.Error())
		return 0, uuid.Nil, false
	}
	return partition, id, true
}

// list shows the users. Search and filters run on the server.
func (h *AdminUserHandler) list(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	q := r.URL.Query()
	partitionID, _ := strconv.ParseInt(q.Get("partition_id"), 10, 64)

	partitions, err := h.storagePort.GetPartitions(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	users, err := h.adminUserUseCase.ListUsers(r.Context(), tenant.ID, partitionID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	props := admin.UserListProps{
		ActiveTenant: *tenant, Partitions: partitions, Msg: q.Get("msg"),
		Query: strings.TrimSpace(q.Get("q")), Status: q.Get("status"), PartitionID: partitionID,
	}
	props.Rows = filterUserRows(users, partitions, props)
	h.renderAdminPage(w, r, admin.UsersContent(props), admin.UsersPage(props))
}

func filterUserRows(users []model.UserProfile, partitions []model.Partition, f admin.UserListProps) []admin.UserRow {
	names := map[int64]string{}
	for _, p := range partitions {
		names[p.ID] = partitionName(p)
	}
	rows := make([]admin.UserRow, 0, len(users))
	for _, u := range users {
		if matchesUserFilter(u, f) {
			rows = append(rows, admin.UserRow{User: u, PartitionName: names[u.PartitionID]})
		}
	}
	return rows
}

func matchesUserFilter(u model.UserProfile, f admin.UserListProps) bool {
	if !matchesUserStatus(u, f.Status) {
		return false
	}
	if f.Query == "" {
		return true
	}
	needle := strings.ToLower(f.Query)
	for _, field := range []string{u.PreferredUsername, u.Name, u.Email} {
		if strings.Contains(strings.ToLower(field), needle) {
			return true
		}
	}
	return false
}

func matchesUserStatus(u model.UserProfile, status string) bool {
	switch status {
	case "active":
		return !u.Blocked && u.LifecycleState == model.LifecycleActivated
	case "pending":
		return u.LifecycleState == model.LifecycleRequested
	case "blocked":
		return u.Blocked
	case "inactive":
		return !u.Blocked && u.LifecycleState != model.LifecycleActivated && u.LifecycleState != model.LifecycleRequested
	default:
		return true
	}
}

// loadPage reads everything the detail page needs.
func (h *AdminUserHandler) loadPage(r *http.Request, tenant *model.Tenant, partitionID int64, id uuid.UUID) (admin.UserPageProps, error) {
	detail, err := h.adminUserUseCase.GetUser(r.Context(), tenant.ID, partitionID, id)
	if err != nil {
		return admin.UserPageProps{}, err
	}
	partitions, err := h.storagePort.GetPartitions(r.Context(), tenant.ID)
	if err != nil {
		return admin.UserPageProps{}, err
	}
	props := admin.UserPageProps{
		ActiveTenant: *tenant, Detail: detail, Msg: r.URL.Query().Get("msg"), Sections: map[string]admin.SectionResult{},
	}
	if session, ok := AdminSessionFromContext(r.Context()); ok {
		props.ActingUserID = session.UserID.String()
	}
	for _, p := range partitions {
		if p.ID == partitionID {
			props.PartitionName = partitionName(p)
		}
	}
	return props, nil
}

func (h *AdminUserHandler) detail(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	partition, id, ok := h.target(w, r)
	if !ok {
		return
	}
	props, err := h.loadPage(r, tenant, partition, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	h.renderAdminPage(w, r, admin.UserContent(props), admin.UserPage(props))
}
