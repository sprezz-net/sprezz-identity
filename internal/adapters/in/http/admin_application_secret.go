package http

import (
	"log/slog"
	"net/http"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"

	"github.com/go-chi/chi/v5"
)

// create registers an application. For a confidential client the plaintext secret is written to the response
// inside the database transaction, so a delivery failure rolls the registration back.
func (h *AdminApplicationHandler) create(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, ErrMalformedPayload)
		return
	}

	in, errs := parseCreateForm(r)
	if len(errs) > 0 {
		h.renderCreateApplicationErrors(w, r, tenant, in, errs)
		return
	}

	profile, err := h.adminApplicationUseCase.GetProfile(r.Context(), tenant.ID, in.profile)
	if err != nil {
		h.renderDomainError(w, r, err)
		return
	}

	delivered := false
	_, err = h.adminApplicationUseCase.CreateApplication(r.Context(), port.CreateApplicationCommand{
		TenantID:        tenant.ID,
		ClientID:        in.clientID,
		ApplicationName: in.name,
		ProfileID:       in.profile,
		GroupID:         in.groupID,
		OnDelivery:      h.deliverSecret(w, r, profile, in.clientID, &delivered),
	})
	if err != nil {
		h.finishFailedCreate(w, r, tenant, in, err, delivered)
		return
	}
	if profile.TokenEndpointAuthMethod == model.AuthMethodNone {
		redirectTo(w, r, flashURL(applicationURL(in.clientID), "Application created"))
	}
}

// deliverSecret streams the one-time secret panel for confidential clients. Public clients have no secret, so the
// browser is simply sent to the new page afterwards.
func (h *AdminApplicationHandler) deliverSecret(w http.ResponseWriter, r *http.Request, profile *model.ApplicationProfile, clientID string, delivered *bool) port.CommitCallback {
	return func(plaintextSecret string) error {
		if profile.TokenEndpointAuthMethod == model.AuthMethodNone {
			return nil
		}
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusOK)
		*delivered = true
		return admin.ApplicationSecretPanel(clientID, plaintextSecret, applicationURL(clientID)).Render(r.Context(), w)
	}
}

func (h *AdminApplicationHandler) finishFailedCreate(w http.ResponseWriter, r *http.Request, tenant *model.Tenant, in createInput, err error, delivered bool) {
	slog.Error("application creation failed", "client_id", in.clientID, "err", err)
	if delivered {
		// The response is already on the wire; the failed write rolled the transaction back.
		return
	}
	errs := map[string]string{}
	mergeFieldErrors(err, errs)
	if strings.Contains(err.Error(), "already exists") {
		errs["client_id"] = "this client ID is already taken"
	}
	if len(errs) == 0 {
		h.renderDomainError(w, r, err)
		return
	}
	h.renderCreateApplicationErrors(w, r, tenant, in, errs)
}

// resetSecret rotates the client secret and shows the new one once, inside the transaction.
func (h *AdminApplicationHandler) resetSecret(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	clientID := chi.URLParam(r, "clientID")

	err := h.adminApplicationUseCase.ResetApplicationSecret(r.Context(), port.ResetApplicationSecretCommand{
		TenantID: tenant.ID,
		ClientID: clientID,
		OnDelivery: func(plaintextSecret string) error {
			w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
			w.WriteHeader(http.StatusOK)
			return admin.ApplicationSecretPanel(clientID, plaintextSecret, "").Render(r.Context(), w)
		},
	})
	if err != nil {
		slog.Error("secret rotation failed", "client_id", clientID, "err", err)
		h.renderDomainError(w, r, err)
	}
}
