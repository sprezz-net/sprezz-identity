package http

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type TokenHandler struct {
	authUseCase port.AuthUseCase
	crypto      port.Crypto
	storage     port.Storage // Needed to fetch client secret hashes for inbound verification
}

func NewTokenHandler(auc port.AuthUseCase, c port.Crypto, s port.Storage) *TokenHandler {
	return &TokenHandler{
		authUseCase: auc,
		crypto:      c,
		storage:     s,
	}
}

// Routes hooks the handler up to the main chi router container.
func (h *TokenHandler) Routes(r chi.Router) {
	r.Post("/oauth/token", h.HandleTokenRequest)
}

func (h *TokenHandler) HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	// 1. Enforce strict Content-Type compliance per RFC 6749 Section 4.1.3
	contentType := r.Header.Get(model.HeaderContentType)
	if !strings.HasPrefix(contentType, model.ContentTypeFormUrlEncoded) {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "content-type must be application/x-www-form-urlencoded")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "malformed form parameters")
		return
	}

	// 2. Recover pre-validated parameters out of context with zero database query lookups
	ctx := r.Context()
	tenantUUID := ctx.Value(tenantIDCtxKey).(uuid.UUID)
	clientID := ctx.Value(ClientIDContextKey).(string)
	isClientAuthenticated := ctx.Value(ClientAuthFlagKey).(bool)

	app, _ := AppFromContext(ctx)
	profile, _ := ProfileFromContext(ctx)
	group, _ := GroupFromContext(ctx)

	grantType := model.GrantType(r.Form.Get("grant_type"))
	if grantType == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "missing mandatory grant_type parameter")
		return
	}

	var tokenResponse *model.TokenSetResponse
	var err error

	// 3. Branch Execution based on spec-compliant Grant Types
	switch grantType {
	case model.GrantTypeClientCredentials:
		// Machine-to-Machine Flow [RFC 6749 Section 4.4]
		if !isClientAuthenticated {
			h.writeError(w, http.StatusUnauthorized, "invalid_client", "client credentials grant mandates client authentication")
			return
		}

		tokenResponse, err = h.authUseCase.ExchangeClientCredentials(r.Context(), port.ExchangeClientCredentialsCommand{
			TenantID:           tenantUUID,
			ClientID:           clientID,
			Application:        app,
			ApplicationProfile: profile,
			ApplicationGroup:   group,
		})

	case model.GrantTypeAuthorizationCode:
		// Interactive User Authorization Flow with PKCE [RFC 7636]
		code := r.Form.Get("code")
		codeVerifier := r.Form.Get("code_verifier")
		if code == "" {
			h.writeError(w, http.StatusBadRequest, "invalid_request", "missing mandatory code parameter")
			return
		}

		tokenResponse, err = h.authUseCase.ExchangeCodeForTokens(r.Context(), port.ExchangeCodeForTokensCommand{
			TenantID:           tenantUUID,
			ClientID:           clientID,
			Code:               code,
			CodeVerifier:       codeVerifier,
			Application:        app,
			ApplicationProfile: profile,
			ApplicationGroup:   group,
		})

	case model.GrantTypeRefreshToken:
		// Sliding Session Renewal Flow [RFC 6749 Section 6]
		refreshToken := r.Form.Get("refresh_token")
		if refreshToken == "" {
			h.writeError(w, http.StatusBadRequest, "invalid_request", "missing mandatory refresh_token parameter")
			return
		}

		// Clean, decoupled delegation: Pass the raw token string directly to the business layer.
		// The service layer handles verification, token-family audits, and breach detection.
		tokenResponse, err = h.authUseCase.RotateRefreshToken(r.Context(), port.RotateRefreshTokenCommand{
			TenantID:           tenantUUID,
			ClientID:           clientID,
			RefreshToken:       refreshToken,
			Application:        app,
			ApplicationProfile: profile,
			ApplicationGroup:   group,
		})

	default:
		h.writeError(w, http.StatusBadRequest, "unsupported_grant_type", "the requested grant type profile is unsupported")
		return
	}

	// 4. Handle Use-Case Layer Errors mapping cleanly to OAuth2 semantics
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// 5. Success Output Generation
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(tokenResponse)
}

func (h *TokenHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, port.ErrInvalidGrant):
		h.writeError(w, http.StatusBadRequest, "invalid_grant", err.Error())
	case errors.Is(err, port.ErrInvalidClient):
		h.writeError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
	case errors.Is(err, port.ErrInvalidRequest):
		h.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		// Shield backend system faults gracefully from exposure logs
		slog.Error("Token handler execution failed with unexpected error", "error", err)
		h.writeError(w, http.StatusInternalServerError, "server_error", "an internal execution worker faulted")
	}
}

func (h *TokenHandler) writeError(w http.ResponseWriter, statusCode int, errCode string, description string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
