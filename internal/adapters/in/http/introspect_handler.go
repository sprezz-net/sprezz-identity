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

type IntrospectionHandler struct {
	authUseCase port.AuthUseCase
	crypto      port.Crypto
	storage     port.Storage
}

func NewIntrospectionHandler(auc port.AuthUseCase, c port.Crypto, s port.Storage) *IntrospectionHandler {
	return &IntrospectionHandler{
		authUseCase: auc,
		crypto:      c,
		storage:     s,
	}
}

func (h *IntrospectionHandler) Routes(r chi.Router) {
	r.Post("/oauth/introspect", h.HandleIntrospectionRequest)
}

func (h *IntrospectionHandler) HandleIntrospectionRequest(w http.ResponseWriter, r *http.Request) {
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

	// 1. Authenticate client context on the transport perimeter using the shared helper function
	clientID, _, isClientAuthenticated, _, _, _, err := authenticateClientContext(r, tenantUUID, h.storage, h.crypto)
	if err != nil {
		h.writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	// 2. Map pure primitive fields directly into the Port Command envelope object
	cmd := port.IntrospectTokenCommand{
		TenantID:              tenantUUID,
		ClientID:              clientID,
		IsClientAuthenticated: isClientAuthenticated,
		TargetTokenString:     r.Form.Get("token"),
	}

	// 3. Pure Delegation: Fire use case execution across the driving perimeter
	response, err := h.authUseCase.ProcessTokenIntrospection(r.Context(), cmd)
	if err != nil {
		w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(model.IntrospectionResponse{Active: false})
		return
	}

	// 4. Success Output Generation
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func (h *IntrospectionHandler) mustResolveTenant(ctx context.Context) uuid.UUID {
	if val := ctx.Value(tenantIDCtxKey); val != nil {
		if uid, ok := val.(uuid.UUID); ok {
			return uid
		}
	}
	return uuid.Nil
}

func (h *IntrospectionHandler) writeJSONError(w http.ResponseWriter, statusCode int, errCode, description string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
