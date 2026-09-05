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

type PARHandler struct {
	authUseCase port.AuthUseCase
	crypto      port.Crypto
	storage     port.Storage
}

func NewPARHandler(auc port.AuthUseCase, c port.Crypto, s port.Storage) *PARHandler {
	return &PARHandler{
		authUseCase: auc,
		crypto:      c,
		storage:     s,
	}
}

func (h *PARHandler) Routes(r chi.Router) {
	r.Post("/oauth/par", h.HandlePARRequest)
}

func (h *PARHandler) HandlePARRequest(w http.ResponseWriter, r *http.Request) {
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

	// Authenticate Client Credentials (Dual-Track: HTTP Basic vs Form POST)
	// Invokes the shared, spec-compliant extraction helper safely
	clientID, _, isClientAuthenticated, _, _, _, err := authenticateClientContext(r, tenantUUID, h.storage, h.crypto)
	if err != nil {
		h.writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	var requestedScopes []string
	if scopeParam := r.Form.Get("scope"); scopeParam != "" {
		requestedScopes = strings.Split(scopeParam, " ")
	}

	challengeMethod := r.Form.Get("code_challenge_method")
	if challengeMethod == "" && r.Form.Get("code_challenge") != "" {
		challengeMethod = "S256"
	}

	cmd := port.PushedAuthCommand{
		TenantID:              tenantUUID,
		ClientID:              clientID,
		IsClientAuthenticated: isClientAuthenticated,
		RedirectURI:           r.Form.Get("redirect_uri"),
		CodeChallenge:         r.Form.Get("code_challenge"),
		ChallengeMethod:       challengeMethod,
		Scopes:                requestedScopes,
		State:                 r.Form.Get("state"),
		Nonce:                 r.Form.Get("nonce"),
		IDPHint:               r.Form.Get("idp_hint"),
		ACRValues:             r.Form.Get("acr_values"),
	}

	response, err := h.authUseCase.ProcessPushedAuthorization(r.Context(), cmd)
	if err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

func (h *PARHandler) mustResolveTenant(ctx context.Context) uuid.UUID {
	if val := ctx.Value(tenantIDCtxKey); val != nil {
		if uid, ok := val.(uuid.UUID); ok {
			return uid
		}
	}
	return uuid.Nil
}

func (h *PARHandler) writeJSONError(w http.ResponseWriter, statusCode int, errCode, description string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
