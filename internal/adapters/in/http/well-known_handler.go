package http

import (
	"encoding/json"
	"net/http"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/go-chi/chi/v5"
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
	r.Get(port.RouteWellKnownOpenIDConfig, h.HandleOIDCDiscovery)
	r.Get(port.RouteWellKnownOAuthServer, h.HandleOAuthMetadata)
	r.Get(port.RouteWellKnownKeys, h.HandleJWKS)
}

func (h *WellKnownHandler) HandleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	tenantUUID := TenantIDFromContext(r.Context())

	metadata, err := h.authUseCase.ProcessDiscoveryMetadata(r.Context(), tenantUUID, true)
	if err != nil {
		h.writePlainError(w, http.StatusNotFound, err.Error())
		return
	}

	h.writeJSONResponse(w, http.StatusOK, "public, max-age=3600", metadata)
}

func (h *WellKnownHandler) HandleOAuthMetadata(w http.ResponseWriter, r *http.Request) {
	tenantUUID := TenantIDFromContext(r.Context())

	metadata, err := h.authUseCase.ProcessDiscoveryMetadata(r.Context(), tenantUUID, false)
	if err != nil {
		h.writePlainError(w, http.StatusNotFound, err.Error())
		return
	}

	h.writeJSONResponse(w, http.StatusOK, "public, max-age=3600", metadata)
}

func (h *WellKnownHandler) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	tenantUUID := TenantIDFromContext(r.Context())

	scheme := model.SchemeHttps
	if h.appEnv == "local" {
		scheme = model.SchemeHttp
	}

	jwks, err := h.authUseCase.ProcessJWKSetRetrieval(r.Context(), tenantUUID, r.Host, scheme)
	if err != nil {
		h.writePlainError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.writeJSONResponse(w, http.StatusOK, "public, max-age=600, stale-while-revalidate=86400", jwks)
}

func (h *WellKnownHandler) writeJSONResponse(w http.ResponseWriter, status int, cacheControl string, data any) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	if cacheControl != "" {
		w.Header().Set("Cache-Control", cacheControl)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *WellKnownHandler) writePlainError(w http.ResponseWriter, status int, desc string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypePlainText)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(desc))
}
