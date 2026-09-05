package http

import (
	"context"
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
	r.Post("/oauth/revoke", h.HandleRevocationRequest)
}

func (h *RevocationHandler) HandleRevocationRequest(w http.ResponseWriter, r *http.Request) {
	// 1. Enforce strict application/x-www-form-urlencoded content-type parameters
	contentType := r.Header.Get(model.HeaderContentType)
	if !strings.HasPrefix(contentType, model.ContentTypeFormUrlEncoded) {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "content-type must be application/x-www-form-urlencoded")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "malformed form parameters")
		return
	}

	tenantUUID := h.mustResolveTenant(r.Context())

	// 2. Authenticate clients enforcing registered profile methods to prevent downgrades
	clientID, _, isClientAuthenticated, _, _, _, err := authenticateClientContext(r, tenantUUID, h.storage, h.crypto)
	if err != nil {
		h.writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	// 3. Map parameters cleanly to the Port Command envelope object
	cmd := port.RevokeTokenCommand{
		TenantID:              tenantUUID,
		ClientID:              clientID,
		IsClientAuthenticated: isClientAuthenticated,
		TokenString:           r.Form.Get("token"),
	}

	// 4. Pure Delegation: Fire the use case through the driving port perimeter
	err = h.authUseCase.ProcessTokenRevocation(r.Context(), cmd)
	if err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// 5. Success Output Generation (RFC 7009 Section 2.2: Return 200 OK empty response body)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
}

func (h *RevocationHandler) mustResolveTenant(ctx context.Context) uuid.UUID {
	if val := ctx.Value(tenantIDCtxKey); val != nil {
		if uid, ok := val.(uuid.UUID); ok {
			return uid
		}
	}
	return uuid.Nil
}

func (h *RevocationHandler) writeJSONError(w http.ResponseWriter, statusCode int, errCode, description string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
