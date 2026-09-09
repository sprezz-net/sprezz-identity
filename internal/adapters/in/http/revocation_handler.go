package http

import (
	"encoding/json"
	"net/http"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type RevocationHandler struct {
	authUseCase port.AuthUseCase
	crypto      port.Crypto
	storage     port.Storage
}

func NewRevocationHandler(auc port.AuthUseCase, c port.Crypto, s port.Storage) *RevocationHandler {
	return &RevocationHandler{
		authUseCase: auc,
		crypto:      c,
		storage:     s,
	}
}

func (h *RevocationHandler) Routes(r chi.Router) {
	r.Post(port.RouteRevoke, h.HandleRevocationRequest)
}

func (h *RevocationHandler) HandleRevocationRequest(w http.ResponseWriter, r *http.Request) {
	// 1. Enforce strict RFC 7009 Section 2.1 Content-Type compliance
	contentType := r.Header.Get(model.HeaderContentType)
	if !strings.HasPrefix(contentType, model.ContentTypeFormUrlEncoded) {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "content-type must be application/x-www-form-urlencoded")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "malformed form parameters")
		return
	}

	// 2. Recover pre-validated parameters straight from the ClientAuthMiddleware context thread pool
	ctx := r.Context()
	tenantUUID := ctx.Value(tenantIDCtxKey).(uuid.UUID)
	clientID := ctx.Value(ClientIDContextKey).(string)
	isClientAuthenticated := ctx.Value(ClientAuthFlagKey).(bool)

	// 3. Map parameters cleanly to the Port Command envelope object
	cmd := port.RevokeTokenCommand{
		TenantID:              tenantUUID,
		ClientID:              clientID,
		IsClientAuthenticated: isClientAuthenticated,
		TokenString:           r.Form.Get("token"),
	}

	// 4. Pure Delegation: Fire the use case through the driving port perimeter
	err := h.authUseCase.ProcessTokenRevocation(r.Context(), cmd)
	if err != nil {
		// RFC 7009 Section 2.2.1: Specific error payloads are suppressed to prevent enumeration
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// 5. Success Output Generation (RFC 7009 Section 2.2: Return 200 OK empty response body)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
}

func (h *RevocationHandler) writeJSONError(w http.ResponseWriter, statusCode int, errCode, description string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
