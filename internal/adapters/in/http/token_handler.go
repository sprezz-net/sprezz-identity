package http

import (
	"encoding/json"
	"errors"
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

	// 2. Resolve Multi-Tenant Context from Middleware thread injection
	tenantIDVal := r.Context().Value(tenantIDCtxKey)
	tenantUUID, ok := tenantIDVal.(uuid.UUID)
	if !ok || tenantUUID == uuid.Nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "missing or corrupt tenant execution boundary")
		return
	}

	// 3. Authenticate Client Credentials (Dual-Track: HTTP Basic vs Form POST)
	// Invokes the shared, spec-compliant extraction helper safely
	clientID, clientSecret, isClientAuthenticated, app, profile, group, err := authenticateClientContext(r, tenantUUID, h.storage, h.crypto)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	grantType := model.GrantType(r.Form.Get("grant_type"))
	if grantType == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "missing mandatory grant_type parameter")
		return
	}

	var tokenResponse *model.TokenSetResponse

	// 4. Branch Execution based on spec-compliant Grant Types
	switch grantType {
	case model.GrantTypeClientCredentials:
		// Machine-to-Machine Flow [RFC 6749 Section 4.4]
		if !isClientAuthenticated || clientSecret == "" {
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

		// Token verification infrastructure decrypts claims securely via the port boundary
		var rawClaims map[string]any
		rawClaims, err = h.crypto.VerifyToken(r.Header.Get("Authorization"))
		if err != nil {
			h.writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid or expired access token context loop")
			return
		}

		// Map dictionary structures safely into type-safe domain models
		currentClaims := h.mapMapClaimsToTokenClaims(tenantUUID, rawClaims)
		tokenResponse, err = h.authUseCase.RotateRefreshToken(r.Context(), port.RotateRefreshTokenCommand{
			TenantID:           tenantUUID,
			ClientID:           clientID,
			RefreshToken:       refreshToken,
			CurrentClaims:      currentClaims,
			Application:        app,
			ApplicationProfile: profile,
			ApplicationGroup:   group,
		})

	default:
		h.writeError(w, http.StatusBadRequest, "unsupported_grant_type", "the requested grant type profile is unsupported")
		return
	}

	// 5. Handle Use-Case Layer Errors mapping cleanly to OAuth2 semantics
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// 6. Success Output Generation
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(tokenResponse)
}

// Maps transient unverified string keys safely back into compiled structural Go primatives
func (h *TokenHandler) mapMapClaimsToTokenClaims(tenantID uuid.UUID, claims map[string]any) model.TokenClaims {
	sub, _ := claims["sub"].(string)
	sid, _ := claims["sid"].(string)
	pid, _ := claims["pid"].(string)
	azp, _ := claims["azp"].(string)
	acr, _ := claims["acr"].(string)

	var auds []string
	if rawAud, exists := claims["aud"]; exists {
		if single, ok := rawAud.(string); ok {
			auds = []string{single}
		} else if slice, ok := rawAud.([]any); ok {
			for _, a := range slice {
				if s, ok := a.(string); ok {
					auds = append(auds, s)
				}
			}
		}
	}

	return model.TokenClaims{
		BaseTokenClaims: model.BaseTokenClaims{
			Subject:   sub,
			SessionID: sid,
			TenantID:  tenantID,
			ClientID:  azp,
			ACR:       acr,
		},
		Audiences:      auds,
		PartitionAlias: pid,
	}
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
