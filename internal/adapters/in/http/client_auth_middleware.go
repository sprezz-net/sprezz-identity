package http

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

type MiddlewareProvider struct {
	storage port.Storage
	crypto  port.Crypto
}

func NewMiddlewareProvider(s port.Storage, c port.Crypto) *MiddlewareProvider {
	return &MiddlewareProvider{storage: s, crypto: c}
}

func (m *MiddlewareProvider) ClientAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Resolve Multi-Tenant Perimeter via pre-assigned context
		tenantIDVal := r.Context().Value(TenantIDContextKey) // Uses your existing tenant key anchor
		tenantUUID, ok := tenantIDVal.(uuid.UUID)
		if !ok || tenantUUID == uuid.Nil {
			w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"missing tenant execution boundary"}`))
			return
		}

		// Parse form parameters up front to safely support Form POST evaluation checks
		_ = r.ParseForm()

		var clientID, clientSecret string
		detectedMethod := model.AuthMethodNone

		// Track A: Evaluate standard HTTP Basic Authentication Headers
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Basic ") {
			payload, err := base64.StdEncoding.DecodeString(authHeader[6:])
			if err == nil {
				pair := strings.SplitN(string(payload), ":", 2)
				if len(pair) == 2 {
					clientID = pair[0]
					clientSecret = pair[1]
					detectedMethod = model.AuthMethodClientSecretBasic
				}
			}
		}

		// Track B: Fall back to checking inline Form POST parameters if basic auth header is absent
		if detectedMethod == model.AuthMethodNone {
			clientID = r.Form.Get("client_id")
			clientSecret = r.Form.Get("client_secret")
			if clientSecret != "" {
				detectedMethod = model.AuthMethodClientSecretPost
			}
		}

		if clientID == "" {
			clientID = r.Form.Get("client_id")
		}

		if clientID == "" {
			w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"missing client identifier"}`))
			return
		}

		// 2. Fetch target application metrics from relational storage CTE cache rows
		app, profile, group, err := m.storage.GetApplicationByClientID(r.Context(), tenantUUID, clientID)
		if err != nil {
			w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"client authentication failed"}`))
			return
		}

		// 3. Watertight Spec Enforcement: Reject protocol method downgrades instantly
		if profile.TokenEndpointAuthMethod != detectedMethod {
			w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"client authentication method mismatch"}`))
			return
		}

		var isClientAuthenticated bool

		if profile.TokenEndpointAuthMethod == model.AuthMethodNone {
			// Public client apps bypass credentials comparison tracks
			isClientAuthenticated = true
		} else {
			// Confidential clients require secure cryptographic verification
			if app.ClientSecretHash == nil || clientSecret == "" {
				w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"client credentials missing"}`))
				return
			}

			authenticated, err := m.crypto.CompareCredential(*app.ClientSecretHash, clientSecret)
			if err != nil || !authenticated {
				w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"client authentication failed"}`))
				return
			}
			isClientAuthenticated = true
		}

		// 4. Ingest compiled contexts into the active thread pool context
		ctx := r.Context()
		ctx = context.WithValue(ctx, AppContextKey, app)
		ctx = context.WithValue(ctx, ProfileContextKey, profile)
		ctx = context.WithValue(ctx, GroupContextKey, group)
		ctx = context.WithValue(ctx, ClientAuthFlagKey, isClientAuthenticated)
		ctx = context.WithValue(ctx, ClientIDContextKey, clientID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
