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

type PARHandler struct {
	authUseCase port.AuthUseCase
}

func NewPARHandler(auc port.AuthUseCase) *PARHandler {
	return &PARHandler{
		authUseCase: auc,
	}
}

func (h *PARHandler) Routes(r chi.Router) {
	r.Post(port.RoutePAR, h.HandlePARRequest)
}

func (h *PARHandler) HandlePARRequest(w http.ResponseWriter, r *http.Request) {
	// 1. Enforce strict Content-Type compliance per RFC 9126 Section 2
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
	tenantUUID := ctx.Value(TenantIDContextKey).(uuid.UUID)
	clientID := ctx.Value(ClientIDContextKey).(string)
	isClientAuthenticated := ctx.Value(ClientAuthFlagKey).(bool)

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

func (h *PARHandler) writeJSONError(w http.ResponseWriter, statusCode int, errCode, description string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
