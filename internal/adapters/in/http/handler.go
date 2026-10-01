package http

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/assets"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
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
	adminUserUseCase        port.AdminUserUseCase
	adminTenantUseCase      port.AdminTenantUseCase
	adminStorage            port.AdminStorage
	idpService              port.IdentityProviderUseCase
	storagePort             port.Storage
	cryptoPort              port.Crypto
	router                  chi.Router
	appEnv                  string
	adminDomain             string
}

// WithAdminUserUseCase wires the use case behind the admin Users pages. It is a separate call so the constructor
// signature, which every test and the composition root use, stays unchanged.
func (h *HttpAdapter) WithAdminUserUseCase(uc port.AdminUserUseCase) *HttpAdapter {
	h.adminUserUseCase = uc
	return h
}

// WithAdminTenantUseCase wires the use case behind the admin Tenants pages.
func (h *HttpAdapter) WithAdminTenantUseCase(uc port.AdminTenantUseCase) *HttpAdapter {
	h.adminTenantUseCase = uc
	return h
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
	h.router.Handle(assets.Prefix+"*", assets.Handler())
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
	introspectionHandler := NewIntrospectionHandler(h.authUseCase)
	revocationHandler := NewRevocationHandler(h.authUseCase)
	parHandler := NewPARHandler(h.authUseCase)

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
		// Static assets and userinfo must bypass the tenant initialization gate.
		if strings.HasPrefix(path, assets.Prefix) || path == "/oauth/userinfo" {
			next.ServeHTTP(w, r)
			return
		}
		tenant, err := h.resolveTenant(r.Context(), r.Host)
		if err != nil {
			h.respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		ctx := context.WithValue(r.Context(), TenantContextKey, tenant)
		ctx = context.WithValue(ctx, TenantIDContextKey, tenant.ID)
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

		csp := buildCSP(nonce, r.URL.Path)
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")

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

// buildCSP returns the Content-Security-Policy for a request path. Every script and stylesheet is served from this
// origin (see the assets package), so no third-party host is trusted. Scripts additionally need the per-request
// nonce, and neither eval nor inline styles are allowed.
func buildCSP(nonce, path string) string {
	directives := []string{
		"default-src 'self'",
		"script-src 'self' 'nonce-" + nonce + "'",
		"style-src 'self'",
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
	}

	switch path {
	case port.RouteLogout, port.RouteWebLogout:
		// Front-channel logout embeds the logout endpoints of every client application in hidden iframes.
		directives = append(directives, "frame-src https: http:", "frame-ancestors 'none'")
	case port.RouteAdmin + port.RouteAdminLogout:
		// The admin console's own front-channel logout endpoint is framed by the identity provider's logout page,
		// which may be served from another origin. It only clears a cookie, so framing it is harmless.
	default:
		directives = append(directives, "frame-ancestors 'none'")
	}

	return strings.Join(directives, "; ")
}
