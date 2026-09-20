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

type ContextKey string

const (
	TenantContextKey   ContextKey = "spz_tenant_context"
	TenantIDContextKey ContextKey = "spz_tenant_id_context"
	AppContextKey      ContextKey = "spz_app_context"
	ProfileContextKey  ContextKey = "spz_profile_context"
	GroupContextKey    ContextKey = "spz_group_context"
	ClientAuthFlagKey  ContextKey = "spz_client_authenticated"
	ClientIDContextKey ContextKey = "spz_client_id"
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
			m.writeJSONError(w, http.StatusBadRequest, "invalid_request", port.ErrTenantNotFound.Error())
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
			m.writeJSONError(w, http.StatusBadRequest, "invalid_request", "missing client identifier")
			return
		}

		// 2. Fetch target application metrics from relational storage CTE cache rows
		app, profile, group, err := m.storage.GetApplicationByClientID(r.Context(), tenantUUID, clientID)
		if err != nil {
			m.writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}

		// 3. Watertight Spec Enforcement: Reject protocol method downgrades instantly
		if profile.TokenEndpointAuthMethod != detectedMethod {
			m.writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client authentication method mismatch")
			return
		}

		var isClientAuthenticated bool

		if profile.TokenEndpointAuthMethod == model.AuthMethodNone {
			// Public client apps bypass credentials comparison tracks
			isClientAuthenticated = true
		} else {
			// Confidential clients require secure cryptographic verification
			if app.ClientSecretHash == nil || clientSecret == "" {
				m.writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client credentials missing")
				return
			}

			authenticated, err := m.crypto.CompareCredential(*app.ClientSecretHash, clientSecret)
			if err != nil || !authenticated {
				m.writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
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

func (m *MiddlewareProvider) writeJSONError(w http.ResponseWriter, statusCode int, errCode, description string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(`{"error":"` + errCode + `","error_description":"` + description + `"}`))
}

// Helper functions to pull compiled layers out of the request context down-funnel
// TenantIDFromContext extracts the pre-validated Tenant UUID from the request context thread.
// It panics if the boundary is missing, as the perimeter middleware guarantees its presence.
func TenantIDFromContext(ctx context.Context) uuid.UUID {
	if val, ok := ctx.Value(TenantIDContextKey).(uuid.UUID); ok {
		return val
	}
	return uuid.Nil
}

func TenantFromContext(ctx context.Context) (*model.Tenant, bool) {
	tenant, ok := ctx.Value(TenantContextKey).(*model.Tenant)
	return tenant, ok
}

// ClientIDFromContext recovers the authenticated Client ID string from the request context.
func ClientIDFromContext(ctx context.Context) (string, bool) {
	val, ok := ctx.Value(ClientIDContextKey).(string)
	return val, ok
}

// IsClientAuthenticatedFromContext extracts the boolean credential verification status.
func IsClientAuthenticatedFromContext(ctx context.Context) bool {
	if val, ok := ctx.Value(ClientAuthFlagKey).(bool); ok {
		return val
	}
	return false
}

func AppFromContext(ctx context.Context) (*model.Application, bool) {
	val, ok := ctx.Value(AppContextKey).(*model.Application)
	return val, ok
}

func ProfileFromContext(ctx context.Context) (*model.ApplicationProfile, bool) {
	val, ok := ctx.Value(ProfileContextKey).(*model.ApplicationProfile)
	return val, ok
}

func GroupFromContext(ctx context.Context) (*model.ApplicationGroup, bool) {
	val, ok := ctx.Value(GroupContextKey).(*model.ApplicationGroup)
	return val, ok
}
