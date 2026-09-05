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

/*
const (
	routeAuthorize          = "/oauth/authorize" // DONE
	routeToken              = "/oauth/token" // DONE
	routeUserInfo           = "/oauth/userinfo" // DONE
	routeRegister           = "/oauth/register" // DONE
	routeAuthServer         = "/.well-known/oauth-authorization-server" // DONE
	routeOpenIDConfig       = "/.well-known/openid-configuration" // DONE
	routeKeys               = "/.well-known/jwks.json" // DONE
	routeRevoke             = "/oauth/revoke" // DONE
	routeIntrospect         = "/oauth/introspect" // DONE
	routeLogout             = "/oauth/logout" // DONE
	routePAR                = "/oauth/par" // DONE
	routeCallback           = "/oauth/callback" // DONE
	routeAdmin              = port.RouteAdmin
	routeFederationCallback = port.RouteFederationCallback // DONE
	contentTypeHeader       = "Content-Type"
	contentTypeJSON         = "application/json"
	contentTypeHtml         = "text/html; charset=utf-8"
	errInvalidDPoP          = "invalid DPoP proof: "
	errClientAuthFailed     = "client authentication failed"
	xForwardedProto         = "X-Forwarded-Proto"

	routeRoot      = "/" // DONE
	routeWebLogin  = "/login" // DONE
	routeWebLogout = "/logout" // DONE
	routeWebSignUp = "/sign-up"

	errTenantNotResolved = "tenant not resolved"
)

func (h *HttpAdapter) registerRoutes() {
	h.router.Get(routeRoot, h.loginRoot)
	h.router.Get(routeCallback, h.oauthCallback)
	h.router.Get(routeFederationCallback, h.HandleOutboundCallback)
	h.router.Post(routeWebLogin, h.login)
	h.router.Get(routeWebSignUp, h.signUpForm)
	h.router.Post(routeWebSignUp, h.signUpSubmit)
	h.router.Get(routeOpenIDConfig, h.openIDConfiguration)
	h.router.Get(routeAuthServer, h.oauthAuthorizationServer)
	h.router.Get(routeKeys, h.jwks)
	h.router.Post(routeRegister, h.register)
	h.router.Get(routeAuthorize, h.authorize)
	h.router.Post(routeAuthorize, h.authorize)
	h.router.Post(routeToken, h.token)
	h.router.Get(routeUserInfo, h.userinfo)
	h.router.Post(routeUserInfo, h.userinfo)
	h.router.Get(routeLogout, h.logout)
	h.router.Get(routeWebLogout, h.webLogout)

	// Admin Routes
	h.router.Route("/admin", func(r chi.Router) {
		r.Get("/", h.adminDashboardView)
		r.Get("/dashboard", h.adminDashboardView)

		r.Get("/tenants", h.adminTenantsPage)
		r.Get("/tenants/new", h.adminNewTenantForm)
		r.Post("/tenants", h.adminCreateTenant)
		r.Post("/tenants/settings", h.adminSaveTenantSettings)
		r.Patch("/tenants/{id}/toggle-signup", h.adminToggleSignup)

		r.Get("/clients", h.adminClientsPage)
		r.Get("/clients/generate-secret", h.adminGenerateSecret)
		r.Get("/clients/new", h.adminNewClientForm)
		r.Get("/clients/edit", h.adminEditClientForm)
		r.Get("/clients/view", h.adminViewClient)
		r.Post("/clients", h.adminSaveClient)
		r.Post("/clients/{id}/reset-secret", h.adminResetClientSecret)
		r.Delete("/clients/{id}", h.adminDeleteClient)

		r.Get("/idps", h.adminIDPsPage)
		r.Get("/idps/discover", h.adminDiscoverIDP)
		r.Get("/idps/new", h.adminNewIDPForm)
		r.Get("/idps/edit", h.adminEditIDPForm)
		r.Post("/idps", h.adminSaveIDP)
		r.Delete("/idps/{id}", h.adminDeleteIDP)

		r.Get("/users", h.adminUsersPage)
		r.Get("/users/view", h.adminViewUser)
		r.Get("/users/edit", h.adminEditUserForm)
		r.Post("/users", h.adminSaveUser)
		r.Delete("/users/{id}", h.adminDeleteUser)
		r.Delete("/users/{id}/identities/{idp}", h.adminDecoupleIdentity)
	})

	// Profile Routes
	h.router.Route("/profile", func(r chi.Router) {
		r.Get("/", h.profileDashboard)
		r.Get("/password", h.changePasswordForm)
		r.Post("/password", h.changePasswordSubmit)
		r.Get("/email", h.changeEmailForm)
		r.Post("/email", h.changeEmailSubmit)
		r.Get("/name", h.changeNameForm)
		r.Post("/name", h.changeNameSubmit)
		r.Delete("/identities/{idp}", h.decoupleIdentitySubmit)
	})

	// Routes requiring mandatory client authentication
	h.router.Group(func(r chi.Router) {
		r.Use(h.clientAuthMiddleware)
		r.Post(routeRevoke, h.revoke)
		r.Post(routeIntrospect, h.introspect)
		r.Post(routePAR, h.par)
	})
}
*/

const (
	contentTypeHeader    = "Content-Type"
	contentTypeJSON      = "application/json"
	errTenantNotResolved = "tenant not resolved"
)

type HttpAdapter struct {
	tenantUseCase           port.TenantUseCase
	authUseCase             port.AuthUseCase
	federatedUseCase        port.FederatedLoginUseCase
	ssoUseCase              port.SSOSessionUseCase
	userProfileUseCase      port.UserProfileUseCase
	userRegistrationUseCase port.UserRegistrationUseCase
	localAuthUseCase        port.LocalAuthUseCase
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
	s port.Storage,
	c port.Crypto,
	appEnv string,
	adminDomain string,
) *HttpAdapter {
	h := &HttpAdapter{
		tenantUseCase:           tuc,
		authUseCase:             auc,
		federatedUseCase:        fuc,
		ssoUseCase:              suc,
		userProfileUseCase:      upuc,
		userRegistrationUseCase: uruc,
		localAuthUseCase:        lauc,
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
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
