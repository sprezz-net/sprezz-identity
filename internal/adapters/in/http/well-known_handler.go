package http

import (
	"context"
	"encoding/json"
	"net/http"

	"sprezz-identity/internal/domain/port"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type WellKnownHandler struct {
	authUseCase port.AuthUseCase
	appEnv      string
}

func NewWellKnownHandler(auc port.AuthUseCase, appEnv string) *WellKnownHandler {
	return &WellKnownHandler{
		authUseCase: auc,
		appEnv:      appEnv,
	}
}

func (h *WellKnownHandler) Routes(r chi.Router) {
	r.Get("/.well-known/openid-configuration", h.HandleOIDCDiscovery)
	r.Get("/.well-known/oauth-authorization-server", h.HandleOAuthMetadata)
	r.Get("/.well-known/jwks.json", h.HandleJWKS)
}

func (h *WellKnownHandler) HandleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	tenantUUID := h.mustResolveTenant(r.Context())

	metadata, err := h.authUseCase.ProcessDiscoveryMetadata(r.Context(), tenantUUID, true)
	if err != nil {
		h.writePlainError(w, http.StatusNotFound, err.Error())
		return
	}

	h.writeJSONResponse(w, http.StatusOK, "public, max-age=3600", metadata)
}

func (h *WellKnownHandler) HandleOAuthMetadata(w http.ResponseWriter, r *http.Request) {
	tenantUUID := h.mustResolveTenant(r.Context())

	metadata, err := h.authUseCase.ProcessDiscoveryMetadata(r.Context(), tenantUUID, false)
	if err != nil {
		h.writePlainError(w, http.StatusNotFound, err.Error())
		return
	}

	h.writeJSONResponse(w, http.StatusOK, "public, max-age=3600", metadata)
}

func (h *WellKnownHandler) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	tenantUUID := h.mustResolveTenant(r.Context())

	scheme := "https"
	if h.appEnv == "local" {
		scheme = "http"
	}

	jwks, err := h.authUseCase.ProcessJWKSetRetrieval(r.Context(), tenantUUID, r.Host, scheme)
	if err != nil {
		h.writePlainError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.writeJSONResponse(w, http.StatusOK, "public, max-age=600, stale-while-revalidate=86400", jwks)
}

func (h *WellKnownHandler) mustResolveTenant(ctx context.Context) uuid.UUID {
	if val := ctx.Value(tenantIDCtxKey); val != nil {
		if uid, ok := val.(uuid.UUID); ok {
			return uid
		}
	}
	return uuid.Nil
}

func (h *WellKnownHandler) writeJSONResponse(w http.ResponseWriter, status int, cacheControl string, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if cacheControl != "" {
		w.Header().Set("Cache-Control", cacheControl)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *WellKnownHandler) writePlainError(w http.ResponseWriter, status int, desc string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(desc))
}
