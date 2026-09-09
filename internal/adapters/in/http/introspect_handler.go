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

type IntrospectionHandler struct {
	authUseCase port.AuthUseCase
}

func NewIntrospectionHandler(auc port.AuthUseCase) *IntrospectionHandler {
	return &IntrospectionHandler{
		authUseCase: auc,
	}
}

func (h *IntrospectionHandler) Routes(r chi.Router) {
	r.Post(port.RouteIntrospect, h.HandleIntrospectionRequest)
}

func (h *IntrospectionHandler) HandleIntrospectionRequest(w http.ResponseWriter, r *http.Request) {
	// 1. Enforce strict Content-Type compliance per RFC 7662 Section 2.1
	contentType := r.Header.Get(model.HeaderContentType)
	if !strings.HasPrefix(contentType, model.ContentTypeFormUrlEncoded) {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "content-type must be application/x-www-form-urlencoded")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", "malformed form parameters")
		return
	}

	// 2. Recover pre-validated perimeter parameters from ClientAuthMiddleware context
	ctx := r.Context()
	tenantUUID := ctx.Value(TenantIDContextKey).(uuid.UUID)
	clientID := ctx.Value(ClientIDContextKey).(string)
	isClientAuthenticated := ctx.Value(ClientAuthFlagKey).(bool)

	// 3. Map pure primitive fields directly into the Port Command envelope object
	cmd := port.IntrospectTokenCommand{
		TenantID:              tenantUUID,
		ClientID:              clientID,
		IsClientAuthenticated: isClientAuthenticated,
		TargetTokenString:     r.Form.Get("token"),
	}

	// 4. Pure Delegation: Fire use case execution across the driving perimeter
	response, err := h.authUseCase.ProcessTokenIntrospection(r.Context(), cmd)
	if err != nil {
		// RFC 7662: If the token is invalid, expired, or revoked, return active: false with a 200 OK
		w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(model.IntrospectionResponse{Active: false})
		return
	}

	// 5. Success Output Generation
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func (h *IntrospectionHandler) writeJSONError(w http.ResponseWriter, statusCode int, errCode, description string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
