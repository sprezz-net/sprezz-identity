package http

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
)

const (
	errTenantNotResolved = "tenant not resolved"
)

type HttpAdapter struct {
	tenantUseCase           port.TenantUseCase
	tenantService           port.TenantUseCase
	authUseCase             port.AuthUseCase
	federatedUseCase        port.FederatedLoginUseCase
	adminLogonUseCase       port.AdminLogonUseCase
	ssoUseCase              port.SSOSessionUseCase
	userProfileUseCase      port.UserProfileUseCase
	userRegistrationUseCase port.UserRegistrationUseCase
	localAuthUseCase        port.LocalAuthUseCase
	adminApplicationUseCase port.AdminApplicationUseCase
	adminStorage            port.AdminStorage
	idpService              port.IdentityProviderUseCase
	storagePort             port.Storage
	cryptoPort              port.Crypto
	router                  chi.Router
	appEnv                  string
	adminDomain             string
}

type contextKey string

const (
	tenantCtxKey       contextKey = "tenant"
	tenantIDCtxKey     contextKey = "tenant_id"
	AppContextKey      contextKey = "spz_app_context"
	ProfileContextKey  contextKey = "spz_profile_context"
	GroupContextKey    contextKey = "spz_group_context"
	ClientAuthFlagKey  contextKey = "spz_client_authenticated"
	ClientIDContextKey contextKey = "spz_client_id"
)

// Helper functions to pull compiled layers out of the request context down-funnel
func TenantFromContext(ctx context.Context) (*model.Tenant, bool) {
	tenant, ok := ctx.Value(tenantCtxKey).(*model.Tenant)
	return tenant, ok
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

func NewHttpAdapter(
	tuc port.TenantUseCase,
	auc port.AuthUseCase,
	fuc port.FederatedLoginUseCase,
	aluc port.AdminLogonUseCase,
	suc port.SSOSessionUseCase,
	upuc port.UserProfileUseCase,
	uruc port.UserRegistrationUseCase,
	lauc port.LocalAuthUseCase,
	aauc port.AdminApplicationUseCase,
	as port.AdminStorage,
	idp port.IdentityProviderUseCase,
	s port.Storage,
	c port.Crypto,
	appEnv string,
	adminDomain string,
) *HttpAdapter {
	h := &HttpAdapter{
		tenantUseCase:           tuc,
		tenantService:           tuc,
		authUseCase:             auc,
		federatedUseCase:        fuc,
		adminLogonUseCase:       aluc,
		ssoUseCase:              suc,
		userProfileUseCase:      upuc,
		userRegistrationUseCase: uruc,
		localAuthUseCase:        lauc,
		adminApplicationUseCase: aauc,
		adminStorage:            as,
		idpService:              idp,
		storagePort:             s,
		cryptoPort:              c,
		router:                  chi.NewRouter(),
		appEnv:                  appEnv,
		adminDomain:             adminDomain,
	}

	h.router.Use(h.cspMiddleware)
	h.router.Use(h.tenantMiddleware)
	h.registerRoutes()
	return h
}

func (h *HttpAdapter) Router() http.Handler {
	return h.router
}

func (h *HttpAdapter) registerRoutes() {
	// 1. Instantiate the Centralized Middleware Provider
	mw := NewMiddlewareProvider(h.storagePort, h.cryptoPort)

	// 2. Instantiate the minimalist, zero-business-logic handlers
	wellKnownHandler := NewWellKnownHandler(h.authUseCase, h.appEnv)
	loginHandler := NewLoginHandler(h.authUseCase, h.federatedUseCase, h.ssoUseCase, h.localAuthUseCase)
	logoutHandler := NewLogoutHandler(h.authUseCase, h.ssoUseCase)
	signupHandler := NewSignupHandler(h.userRegistrationUseCase, h.ssoUseCase)
	profileHandler := NewProfileHandler(h.ssoUseCase, h.userProfileUseCase)
	authorizeHandler := NewAuthorizeHandler(h.authUseCase, h.ssoUseCase)
	callbackHandler := NewCallbackHandler(h.federatedUseCase, h.authUseCase, h.ssoUseCase)
	userInfoHandler := NewUserInfoHandler(h.authUseCase)
	registrationHandler := NewRegistrationHandler(h.authUseCase)
	adminHandler := NewAdminHandler(h)

	// Handlers that will be wired directly inside our protected client sub-router
	tokenHandler := NewTokenHandler(h.authUseCase, h.cryptoPort, h.storagePort)
	introspectionHandler := NewIntrospectionHandler(h.authUseCase, h.cryptoPort, h.storagePort)
	revocationHandler := NewRevocationHandler(h.authUseCase, h.cryptoPort, h.storagePort)
	parHandler := NewPARHandler(h.authUseCase, h.cryptoPort, h.storagePort)

	// 3. Mount standard public browser-facing routes and discovery endpoints
	wellKnownHandler.Routes(h.router)
	loginHandler.Routes(h.router)
	logoutHandler.Routes(h.router)
	signupHandler.Routes(h.router)
	profileHandler.Routes(h.router)
	authorizeHandler.Routes(h.router)
	callbackHandler.Routes(h.router)
	userInfoHandler.Routes(h.router)
	registrationHandler.Routes(h.router)
	adminHandler.Routes(h.router)

	// 4. Create an isolated sub-router scope for client-authenticated OAuth2 endpoints
	h.router.Group(func(r chi.Router) {
		// Enforce the strict client credentials middleware boundary across this entire group
		r.Use(mw.ClientAuthMiddleware)

		// Overwrite or directly append endpoints that require client context
		tokenHandler.Routes(r)         // Handles POST /oauth/token
		introspectionHandler.Routes(r) // Handles POST /oauth/introspect
		revocationHandler.Routes(r)    // Handles POST /oauth/revoke
		parHandler.Routes(r)           // Handles POST /oauth/par
	})
}

func (h *HttpAdapter) tenantMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// userinfo must bypass the tenant initialization gate if they resolve URLs dynamically
		if path == "/oauth/userinfo" {
			next.ServeHTTP(w, r)
			return
		}
		tenant, err := h.resolveTenant(r.Context(), r.Host)
		if err != nil {
			h.respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		ctx := context.WithValue(r.Context(), tenantCtxKey, tenant)
		ctx = context.WithValue(ctx, tenantIDCtxKey, tenant.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *HttpAdapter) resolveTenant(ctx context.Context, host string) (*model.Tenant, error) {
	return h.tenantUseCase.ResolveTenantContext(ctx, host)
}

func (h *HttpAdapter) cspMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		nonce := base64.StdEncoding.EncodeToString(nonceBytes)

		csp := fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s' https://unpkg.com; style-src 'self' 'unsafe-inline'; frame-src 'self' *", nonce)
		w.Header().Set("Content-Security-Policy", csp)

		ctx := templ.WithNonce(r.Context(), nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *HttpAdapter) respondJSON(w http.ResponseWriter, status int, payload any) {
	if status >= 400 {
		slog.Error("JSON API error response", "status", status, "payload", payload)
	}
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
