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
	tenantCtxKey   contextKey = "tenant"
	tenantIDCtxKey contextKey = "tenant_id"
)

func TenantFromContext(ctx context.Context) (*model.Tenant, bool) {
	tenant, ok := ctx.Value(tenantCtxKey).(*model.Tenant)
	return tenant, ok
}

func NewHttpAdapter(
	tuc port.TenantUseCase,
	auc port.AuthUseCase,
	fuc port.FederatedLoginUseCase,
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
	// Instantiate the minimalist, zero-business-logic handlers
	wellKnownHandler := NewWellKnownHandler(h.authUseCase, h.appEnv)
	loginHandler := NewLoginHandler(h.authUseCase, h.federatedUseCase, h.ssoUseCase, h.localAuthUseCase)
	logoutHandler := NewLogoutHandler(h.authUseCase, h.ssoUseCase)
	signupHandler := NewSignupHandler(h.userRegistrationUseCase, h.ssoUseCase)
	profileHandler := NewProfileHandler(h.ssoUseCase, h.userProfileUseCase)
	authorizeHandler := NewAuthorizeHandler(h.authUseCase, h.ssoUseCase)
	callbackHandler := NewCallbackHandler(h.federatedUseCase, h.authUseCase, h.ssoUseCase) // Handles both oauth and federation routes
	tokenHandler := NewTokenHandler(h.authUseCase, h.cryptoPort, h.storagePort)
	introspectionHandler := NewIntrospectionHandler(h.authUseCase, h.cryptoPort, h.storagePort)
	userInfoHandler := NewUserInfoHandler(h.authUseCase)
	registrationHandler := NewRegistrationHandler(h.authUseCase)
	revocationHandler := NewRevocationHandler(h.authUseCase, h.cryptoPort, h.storagePort)
	parHandler := NewPARHandler(h.authUseCase, h.cryptoPort, h.storagePort)
	adminHandler := NewAdminHandler(h)

	// Mount the standalone route engines
	wellKnownHandler.Routes(h.router)
	loginHandler.Routes(h.router)
	logoutHandler.Routes(h.router)
	signupHandler.Routes(h.router)
	profileHandler.Routes(h.router)
	authorizeHandler.Routes(h.router)
	callbackHandler.Routes(h.router)
	tokenHandler.Routes(h.router)
	introspectionHandler.Routes(h.router)
	userInfoHandler.Routes(h.router)
	registrationHandler.Routes(h.router)
	revocationHandler.Routes(h.router)
	parHandler.Routes(h.router)
	adminHandler.Routes(h.router)
}

func (h *HttpAdapter) tenantMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// /.well-known endpoints and userinfo must bypass the tenant initialization gate if they resolve URLs dynamically
		if path == "/.well-known/jwks.json" || path == "/oauth/userinfo" {
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
