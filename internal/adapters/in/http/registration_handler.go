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

type RegistrationHandler struct {
	authUseCase port.AuthUseCase
}

func NewRegistrationHandler(auc port.AuthUseCase) *RegistrationHandler {
	return &RegistrationHandler{
		authUseCase: auc,
	}
}

func (h *RegistrationHandler) Routes(r chi.Router) {
	r.Post("/oauth/register", h.HandleRegistrationRequest)
}

func (h *RegistrationHandler) HandleRegistrationRequest(w http.ResponseWriter, r *http.Request) {
	// 1. Enforce strict RFC 7591 application/json content-type parameters
	contentType := r.Header.Get(model.HeaderContentType)
	if !strings.HasPrefix(contentType, model.ContentTypeJSON) {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_redirect_uri", "content-type must be application/json")
		return
	}

	var payload model.DynamicRegistrationPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_client_metadata", "malformed json payload layout")
		return
	}

	tenantUUID := h.mustResolveTenant(r.Context())

	// 2. Pure Delegation: Pass execution directly across the use-case boundary
	result, err := h.authUseCase.ProcessDynamicRegistration(r.Context(), tenantUUID, payload)
	if err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}

	// 3. Spec Compliance: Map out client metadata parameters cleanly (RFC 7591 Section 3.21)
	responseFields := map[string]any{
		"client_id":                  result.Application.ClientID,
		"client_name":                result.Application.ApplicationName,
		"client_id_issued_at":        result.Application.CreatedAt.Unix(),
		"token_endpoint_auth_method": string(payload.TokenEndpointAuthMethod),
	}

	// Confidential clients return their generated credentials; public clients hide them entirely
	if result.PlaintextSecret != "" {
		responseFields["client_secret"] = result.PlaintextSecret
		responseFields["client_secret_expires_at"] = 0 // Credentials do not expire arbitrarily
	}

	// 4. Success Output Generation
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(responseFields)
}

func (h *RegistrationHandler) mustResolveTenant(ctx context.Context) uuid.UUID {
	if val := ctx.Value(tenantIDCtxKey); val != nil {
		if uid, ok := val.(uuid.UUID); ok {
			return uid
		}
	}
	return uuid.Nil
}

func (h *RegistrationHandler) writeJSONError(w http.ResponseWriter, statusCode int, errCode, description string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
