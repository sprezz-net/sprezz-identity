package http

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// AdminApplicationHandler serves the application pages under /admin/applications.
type AdminApplicationHandler struct {
	*HttpAdapter
}

func NewAdminApplicationHandler(adapter *HttpAdapter) *AdminApplicationHandler {
	return &AdminApplicationHandler{HttpAdapter: adapter}
}

// Routes mounts the application routes together with the group and profile sub-sections. The static routes
// (generate-secret, new, groups, profiles) are registered before the {clientID} routes.
func (h *AdminApplicationHandler) Routes(r chi.Router) {
	r.Route(port.RouteAdminApplications, func(r chi.Router) {
		r.Get("/", h.list)
		r.Get("/new", h.newForm)
		r.Post("/", h.create)
		r.Get("/generate-secret", h.generateSecret)

		NewAdminGroupHandler(h.HttpAdapter).Routes(r)
		NewAdminProfileHandler(h.HttpAdapter).Routes(r)

		r.Get("/{clientID}", h.detail)
		r.Delete("/{clientID}", h.delete)
		r.Put("/{clientID}/{section}", h.saveSection)
		r.Post("/{clientID}/reset-secret", h.resetSecret)
	})
}

// adminNavCounts feeds the numbers in the Applications sub navigation.
func (h *HttpAdapter) adminNavCounts(r *http.Request, tenantID uuid.UUID) (admin.NavCounts, error) {
	summaries, profiles, groups, err := h.adminApplicationUseCase.GetApplicationDashboard(r.Context(), tenantID)
	if err != nil {
		return admin.NavCounts{}, err
	}
	return admin.NavCounts{Applications: len(summaries), Groups: len(groups), Profiles: len(profiles)}, nil
}

// filterApplications narrows the list by type and by a case-insensitive search of name and client ID.
func filterApplications(apps []model.ApplicationSummary, kind, query string) []model.ApplicationSummary {
	query = strings.ToLower(strings.TrimSpace(query))
	out := make([]model.ApplicationSummary, 0, len(apps))
	for _, app := range apps {
		if kind == "static" && app.IsDynamic || kind == "dynamic" && !app.IsDynamic {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(app.ApplicationName), query) && !strings.Contains(strings.ToLower(app.ClientID), query) {
			continue
		}
		out = append(out, app)
	}
	return out
}

func (h *AdminApplicationHandler) list(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	summaries, profiles, groups, err := h.adminApplicationUseCase.GetApplicationDashboard(r.Context(), tenant.ID)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	kind, query := r.URL.Query().Get("type"), r.URL.Query().Get("q")
	props := admin.ListPageProps{
		ActiveTenant: *tenant,
		Counts:       admin.NavCounts{Applications: len(summaries), Groups: len(groups), Profiles: len(profiles)},
		Applications: filterApplications(summaries, kind, query),
		Filter:       kind,
		Query:        query,
		Msg:          r.URL.Query().Get("msg"),
	}
	h.renderAdminPage(w, r, admin.ApplicationsListContent(props), admin.ApplicationsListPage(props))
}

func (h *AdminApplicationHandler) generateSecret(w http.ResponseWriter, r *http.Request) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "unable to generate a random value")
		return
	}
	w.Header().Set(model.HeaderContentType, model.ContentTypePlainText)
	_, _ = w.Write([]byte(base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(buf)))
}
