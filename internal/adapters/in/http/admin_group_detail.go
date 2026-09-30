package http

import (
	"net/http"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/views/admin"

	"github.com/google/uuid"
)

// loadGroupPage gathers everything the group page renders.
func (h *AdminGroupHandler) loadGroupPage(r *http.Request, tenant *model.Tenant, id uuid.UUID) (admin.GroupPageProps, error) {
	group, err := h.adminApplicationUseCase.GetGroup(r.Context(), tenant.ID, id)
	if err != nil {
		return admin.GroupPageProps{}, err
	}
	partitions, err := h.idpService.GetPartitionsWithProviders(r.Context(), tenant.ID)
	if err != nil {
		return admin.GroupPageProps{}, err
	}
	usedBy, err := h.adminApplicationUseCase.ListApplicationsByGroup(r.Context(), tenant.ID, id)
	if err != nil {
		return admin.GroupPageProps{}, err
	}
	return admin.GroupPageProps{
		ActiveTenant: *tenant,
		Group:        group,
		Partitions:   partitions,
		UsedBy:       usedBy,
		Msg:          r.URL.Query().Get("msg"),
		Sections:     map[string]admin.SectionResult{},
	}, nil
}

func (h *AdminGroupHandler) detail(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	id, ok := h.groupID(w, r)
	if !ok {
		return
	}
	props, err := h.loadGroupPage(r, tenant, id)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}
	h.renderAdminPage(w, r, admin.GroupContent(props), admin.GroupPage(props))
}
