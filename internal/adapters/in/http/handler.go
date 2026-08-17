package http

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/service"
	"sprezz-identity/internal/views/public"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	routeAuthorize      = "/oauth/authorize"
	routeToken          = "/oauth/token"
	routeUserInfo       = "/oauth/userinfo"
	routeRegister       = "/oauth/register"
	routeAuthServer     = "/.well-known/oauth-authorization-server"
	routeOpenIDConfig   = "/.well-known/openid-configuration"
	routeKeys           = "/.well-known/jwks.json"
	routeRevoke         = "/oauth/revoke"
	routeIntrospect     = "/oauth/introspect"
	routeLogout         = "/oauth/logout"
	routePAR            = "/oauth/par"
	routeCallback       = "/oauth/callback"
	routeAdmin          = "/admin"
	contentTypeHeader   = "Content-Type"
	contentTypeJSON     = "application/json"
	contentTypeHtml     = "text/html; charset=utf-8"
	errInvalidDPoP      = "invalid DPoP proof: "
	errClientAuthFailed = "client authentication failed"
	xForwardedProto     = "X-Forwarded-Proto"

	routeRoot      = "/"
	routeWebLogin  = "/login"
	routeWebLogout = "/logout"
	routeWebSignUp = "/sign-up"

	errTenantNotResolved = "tenant not resolved"
)

type HttpAdapter struct {
	authPort           port.Auth
	storagePort        port.Storage
	cryptoPort         port.Crypto
	clockPort          port.Clock
	idpService         *service.IdentityProviderService
	signupService      *service.UserRegistrationService
	oauthValidator     *service.OAuthValidatorService
	tenantService      *service.TenantService
	clientService      *service.ClientService
	userProfileService *service.UserProfileService
	router             chi.Router
	appEnv             string
	adminDomain        string
}

type registerRequest struct {
	ClientName             string   `json:"client_name"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	FrontChannelLogoutURI  string   `json:"frontchannel_logout_uri"`
	BackChannelLogoutURI   string   `json:"backchannel_logout_uri"`
	GrantTypes             []string `json:"grant_types"`
	ResponseTypes          []string `json:"response_types"`
	AllowedScopes          []string `json:"allowed_scopes"`
	DefaultScopes          []string `json:"default_scopes"`
	AllowedAudiences       []string `json:"allowed_audiences"`
	TokenEndpointMethod    string   `json:"token_endpoint_auth_method"`
}

type contextKey string

const (
	tenantCtxKey contextKey = "tenant"
	clientCtxKey contextKey = "client"
)

func TenantFromContext(ctx context.Context) (*model.Tenant, bool) {
	tenant, ok := ctx.Value(tenantCtxKey).(*model.Tenant)
	return tenant, ok
}

func ClientFromContext(ctx context.Context) (*model.ClientApplication, bool) {
	client, ok := ctx.Value(clientCtxKey).(*model.ClientApplication)
	return client, ok
}

func NewHttpAdapter(a port.Auth, s port.Storage, c port.Crypto, cl port.Clock, appEnv string, adminDomain string) *HttpAdapter {
	idpService := service.NewIdentityProviderService(s, cl)
	h := &HttpAdapter{
		authPort:           a,
		storagePort:        s,
		cryptoPort:         c,
		clockPort:          cl,
		idpService:         idpService,
		signupService:      service.NewUserRegistrationService(s),
		oauthValidator:     service.NewOAuthValidatorService(),
		tenantService:      service.NewTenantService(s, cl, idpService, appEnv, adminDomain),
		clientService:      service.NewClientService(s, c),
		userProfileService: service.NewUserProfileService(s),
		router:             chi.NewRouter(),
		appEnv:             appEnv,
		adminDomain:        adminDomain,
	}
	h.router.Use(h.cspMiddleware)
	h.router.Use(h.tenantMiddleware)
	h.registerRoutes()
	return h
}

func (h *HttpAdapter) renderError(w http.ResponseWriter, r *http.Request, status int, errorMessage string) {
	slog.Error("HTTP rendering error", "status", status, "path", r.URL.Path, "error", errorMessage)
	w.Header().Set(contentTypeHeader, "text/html; charset=utf-8")
	w.WriteHeader(status)
	component := public.Error(errorMessage)
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) tenantMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == routeRoot || path == routeKeys || path == routeUserInfo {
			next.ServeHTTP(w, r)
			return
		}
		tenant, err := h.resolveTenant(r.Context(), r.Host)
		if err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		ctx := context.WithValue(r.Context(), tenantCtxKey, tenant)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *HttpAdapter) clientAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := TenantFromContext(r.Context())
		if !ok {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": errTenantNotResolved})
			return
		}
		client, err := h.authenticateClient(w, r, tenant)
		if err != nil {
			return
		}
		ctx := context.WithValue(r.Context(), clientCtxKey, client)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *HttpAdapter) Router() http.Handler {
	return h.router
}

func (h *HttpAdapter) registerRoutes() {
	h.router.Get(routeRoot, h.loginRoot)
	h.router.Get(routeCallback, h.oauthCallback)
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

func (h *HttpAdapter) getDiscoveryMetadata(tenant *model.Tenant, isOIDC bool) map[string]any {
	scopesSupported := tenant.Config.PredefinedScopes
	if len(scopesSupported) == 0 {
		scopesSupported = []string{"openid", "profile", "email", "offline_access"}
	}

	acrValues := make([]string, 0, len(tenant.Config.ACRToLevels))
	for acr := range tenant.Config.ACRToLevels {
		acrValues = append(acrValues, acr)
	}
	sort.Strings(acrValues)

	issuer := tenant.GetBaseURI()
	meta := map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              issuer + routeKeys,
		"authorization_endpoint":                issuer + routeAuthorize,
		"token_endpoint":                        issuer + routeToken,
		"registration_endpoint":                 issuer + routeRegister,
		"introspection_endpoint":                issuer + routeIntrospect,
		"revocation_endpoint":                   issuer + routeRevoke,
		"pushed_authorization_request_endpoint": issuer + routePAR,
		"authorization_response_iss_parameter_supported": true,
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query", "form_post"},
		"grant_types_supported":                          []string{"authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"scopes_supported":                               scopesSupported,
		"acr_values_supported":                           acrValues,
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint_auth_methods_supported":     []string{"client_secret_basic", "client_secret_post", "none"},
		"introspection_endpoint_auth_methods_supported":  []string{"client_secret_basic", "client_secret_post"},
		"dpop_signing_alg_values_supported":              []string{string(model.AlgRS256), string(model.AlgES256), string(model.AlgEdDSA)},
		"code_challenge_methods_supported":               []string{"S256"},
		"request_uri_parameter_supported":                false,
		"require_pushed_authorization_requests":          false,
	}

	if isOIDC {
		meta["userinfo_endpoint"] = issuer + routeUserInfo
		meta["end_session_endpoint"] = issuer + routeLogout
		meta["frontchannel_logout_supported"] = true
		meta["frontchannel_logout_session_supported"] = true
		meta["claims_supported"] = []string{"sub", "name", "preferred_username", "email", "email_verified", "tid"}
		meta["id_token_signing_alg_values_supported"] = []string{string(model.AlgRS256), string(model.AlgES256)}
		meta["subject_types_supported"] = []string{"public"}
	}

	return meta
}

func (h *HttpAdapter) openIDConfiguration(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": errTenantNotResolved})
		return
	}

	metadata := h.getDiscoveryMetadata(tenant, true)
	respondJSON(w, http.StatusOK, metadata)
}

func (h *HttpAdapter) oauthAuthorizationServer(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": errTenantNotResolved})
		return
	}

	metadata := h.getDiscoveryMetadata(tenant, false)
	respondJSON(w, http.StatusOK, metadata)
}

func (h *HttpAdapter) jwks(w http.ResponseWriter, r *http.Request) {
	// 1. Resolve environment scheme dynamically based on your app configuration state
	scheme := "https"
	if h.appEnv == "local" {
		scheme = "http"
	}

	// 2. Call your abstract port interface directly (No downcasting, no implementation leaking!)
	body, err := h.cryptoPort.MarshalJWKSet(r.Context(), r.Host, scheme)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to serialize tenant keyset"})
		return
	}

	// 3. Render clean cache-controlled public headers
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	w.Header().Set("Cache-Control", "public, max-age=600, stale-while-revalidate=86400")
	_, _ = w.Write([]byte(body))
}

func (h *HttpAdapter) populateRegisterDefaults(payload *registerRequest) {
	if len(payload.RedirectURIs) == 0 {
		payload.RedirectURIs = []string{"https://example.com/callback"}
	}
	if len(payload.GrantTypes) == 0 {
		payload.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(payload.ResponseTypes) == 0 {
		payload.ResponseTypes = []string{"code"}
	}
	if len(payload.AllowedScopes) == 0 {
		payload.AllowedScopes = []string{"openid", "profile", "email"}
	}
	if len(payload.DefaultScopes) == 0 {
		payload.DefaultScopes = payload.AllowedScopes
	}
}

func (h *HttpAdapter) validateRegisterURLs(ctx context.Context, tenant *model.Tenant, payload *registerRequest) error {
	// Validate RedirectURIs
	for _, u := range payload.RedirectURIs {
		if err := h.oauthValidator.ValidateRedirect(ctx, tenant, nil, u); err != nil {
			return fmt.Errorf("redirect_uri not whitelisted: %w", err)
		}
	}

	// Validate PostLogoutRedirectURIs
	for _, u := range payload.PostLogoutRedirectURIs {
		if err := h.oauthValidator.ValidateRedirect(ctx, tenant, nil, u); err != nil {
			return fmt.Errorf("post_logout_redirect_uri not whitelisted: %w", err)
		}
	}

	// Validate FrontChannelLogoutURI
	if payload.FrontChannelLogoutURI != "" {
		if err := h.oauthValidator.ValidateRedirect(ctx, tenant, nil, payload.FrontChannelLogoutURI); err != nil {
			return fmt.Errorf("frontchannel_logout_uri not whitelisted: %w", err)
		}
	}

	// Validate BackChannelLogoutURI
	if payload.BackChannelLogoutURI != "" {
		if err := h.oauthValidator.ValidateRedirect(ctx, tenant, nil, payload.BackChannelLogoutURI); err != nil {
			return fmt.Errorf("backchannel_logout_uri not whitelisted: %w", err)
		}
	}
	return nil
}

func (h *HttpAdapter) validateRegisterScopesAndAudiences(ctx context.Context, tenant *model.Tenant, payload *registerRequest) error {
	if err := h.oauthValidator.ValidateScopes(ctx, tenant, nil, payload.AllowedScopes); err != nil {
		return errors.New("requested allowed_scopes are not predefined/allowed by the tenant")
	}
	if err := h.oauthValidator.ValidateScopes(ctx, tenant, nil, payload.DefaultScopes); err != nil {
		return errors.New("requested default_scopes are not predefined/allowed by the tenant")
	}

	if len(payload.AllowedAudiences) > 0 {
		if err := h.oauthValidator.ValidateAudiences(ctx, tenant, nil, payload.AllowedAudiences); err != nil {
			return err
		}
	}
	return nil
}

func (h *HttpAdapter) validateRegisterPayload(ctx context.Context, tenant *model.Tenant, payload *registerRequest) error {
	if err := h.validateRegisterURLs(ctx, tenant, payload); err != nil {
		return err
	}
	return h.validateRegisterScopesAndAudiences(ctx, tenant, payload)
}

func (h *HttpAdapter) register(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": errTenantNotResolved})
		return
	}

	var payload registerRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid registration payload"})
		return
	}
	if payload.ClientName == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "client_name is required"})
		return
	}
	h.populateRegisterDefaults(&payload)

	if err := h.validateRegisterPayload(r.Context(), tenant, &payload); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	clientID := uuid.NewString()
	clientSecret := uuid.NewString()
	client := model.ClientApplication{
		ID:                     uuid.NewString(),
		TenantID:               tenant.ID,
		ClientID:               clientID,
		ClientSecret:           &clientSecret,
		ClientName:             payload.ClientName,
		RedirectURIs:           payload.RedirectURIs,
		PostLogoutRedirectURIs: payload.PostLogoutRedirectURIs,
		FrontChannelLogoutURI:  payload.FrontChannelLogoutURI,
		BackChannelLogoutURI:   payload.BackChannelLogoutURI,
		GrantTypes:             payload.GrantTypes,
		ResponseTypes:          payload.ResponseTypes,
		Algorithm:              model.AlgRS256,
		AccessTokenLifetime:    900 * time.Second,
		IDTokenLifetime:        900 * time.Second,
		RefreshTokenLifetime:   1209600 * time.Second,
		AllowedScopes:          payload.AllowedScopes,
		DefaultScopes:          payload.DefaultScopes,
		AllowedAudiences:       payload.AllowedAudiences,
	}
	if err := h.storagePort.SaveClient(r.Context(), client); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	respondJSON(w, http.StatusCreated, map[string]any{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"client_name":   payload.ClientName,
		"redirect_uris": payload.RedirectURIs,
	})
}

func (h *HttpAdapter) resolveTenant(ctx context.Context, host string) (*model.Tenant, error) {
	tenant, err := h.storagePort.ResolveTenantByDomain(ctx, host)
	if err == nil {
		return tenant, nil
	}
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	tenant, err = h.storagePort.ResolveTenantByDomain(ctx, host)
	if err == nil {
		return tenant, nil
	}
	return nil, fmt.Errorf("tenant for host %s not bootstrapped", host)
}

func respondJSON(w http.ResponseWriter, status int, payload any) {
	if status >= 400 {
		slog.Error("JSON API error response", "status", status, "payload", payload)
	}
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (h *HttpAdapter) validateAuthorizeParams(ctx context.Context, client *model.ClientApplication, tenant *model.Tenant, redirectURI string, scopes []string) error {
	if err := h.oauthValidator.ValidateRedirect(ctx, tenant, client, redirectURI); err != nil {
		return err
	}
	return h.oauthValidator.ValidateScopes(ctx, tenant, client, scopes)
}

func (h *HttpAdapter) cspMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		nonce := base64.StdEncoding.EncodeToString(nonceBytes)

		// Set Content-Security-Policy header
		// Script sources permit 'self', the secure per-request nonce, and https://unpkg.com (for htmx)
		csp := fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s' https://unpkg.com; style-src 'self' 'unsafe-inline'; frame-src 'self' *", nonce)
		w.Header().Set("Content-Security-Policy", csp)

		// Pass the nonce down to our a-h/templ templates
		ctx := templ.WithNonce(r.Context(), nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
