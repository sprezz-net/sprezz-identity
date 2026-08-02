package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwtcrypto "sprezz-identity/internal/adapters/out/crypto"
	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/service"
	"sprezz-identity/internal/views"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	routeAuthorize    = "/oauth/authorize"
	routeToken        = "/oauth/token"
	routeUserInfo     = "/oauth/userinfo"
	routeRegister     = "/oauth/register"
	routeOpenIDConfig = "/.well-known/openid-configuration"
	routeKeys         = "/.well-known/jwks.json"
	routeRevoke       = "/oauth/revoke"
	routeIntrospect   = "/oauth/introspect"
	routeLogout       = "/oauth/logout"
	contentTypeHeader = "Content-Type"
	contentTypeJSON   = "application/json"
)

type HttpAdapter struct {
	authPort    port.Auth
	storagePort port.Storage
	cryptoPort  port.Crypto
	idpService  *service.IdentityProviderService
	router      chi.Router
}

type registerRequest struct {
	ClientName          string   `json:"client_name"`
	RedirectURIs        []string `json:"redirect_uris"`
	GrantTypes          []string `json:"grant_types"`
	ResponseTypes       []string `json:"response_types"`
	AllowedScopes       []string `json:"allowed_scopes"`
	DefaultScopes       []string `json:"default_scopes"`
	TokenEndpointMethod string   `json:"token_endpoint_auth_method"`
}

func NewHttpAdapter(a port.Auth, s port.Storage, c port.Crypto) *HttpAdapter {
	h := &HttpAdapter{
		authPort:    a,
		storagePort: s,
		cryptoPort:  c,
		idpService:  service.NewIdentityProviderService(s),
		router:      chi.NewRouter(),
	}
	h.registerRoutes()
	return h
}

func (h *HttpAdapter) Router() http.Handler {
	return h.router
}

func (h *HttpAdapter) registerRoutes() {
	h.router.Get("/", h.loginRoot)
	h.router.Post("/login", h.login)
	h.router.Get(routeOpenIDConfig, h.openIDConfiguration)
	h.router.Get(routeKeys, h.jwks)
	h.router.Post(routeRegister, h.register)
	h.router.Get(routeAuthorize, h.authorize)
	h.router.Post(routeAuthorize, h.authorize)
	h.router.Post(routeToken, h.token)
	h.router.Get(routeUserInfo, h.userinfo)
	h.router.Post(routeRevoke, h.revoke)
	h.router.Post(routeIntrospect, h.introspect)
	h.router.Get(routeLogout, h.logout)
}

func (h *HttpAdapter) loginRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentTypeHeader, "text/html; charset=utf-8")
	component := views.Login("")
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) processInteractionRedirect(w http.ResponseWriter, r *http.Request) bool {
	sessionCookie, err := r.Cookie("spz_auth_session_id")
	if err != nil || sessionCookie.Value == "" {
		return false
	}
	sessionUUID, parseErr := uuid.Parse(sessionCookie.Value)
	if parseErr != nil {
		return false
	}
	session, loadErr := h.storagePort.GetAndConsumeInteractionSession(r.Context(), sessionUUID)
	if loadErr != nil {
		return false
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "spz_auth_session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	redirectURL := routeAuthorize + "?client_id=" + url.QueryEscape(session.ClientID) + "&redirect_uri=" + url.QueryEscape(session.RedirectURI)
	if session.CodeChallenge != "" {
		redirectURL += "&code_challenge=" + url.QueryEscape(session.CodeChallenge)
	}
	if session.ChallengeMethod != "" {
		redirectURL += "&code_challenge_method=" + url.QueryEscape(session.ChallengeMethod)
	}
	if session.IDPHint != "" {
		redirectURL += "&idp_hint=" + url.QueryEscape(session.IDPHint)
	}
	w.Header().Set("HX-Redirect", redirectURL)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Authenticated"))
	return true
}

func (h *HttpAdapter) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("malformed login payload"))
		return
	}
	tenant, err := h.resolveTenant(r.Context(), r.Host)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := strings.TrimSpace(r.FormValue("password"))
	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("username and password are required"))
		return
	}

	result, err := h.idpService.AuthenticateUsernamePassword(r.Context(), tenant.ID, username, password)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `<div style="color:red;margin-bottom:1rem;">%s</div>`, err.Error())
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "spz_login_subject", Value: result.UserProfile.ID.String(), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "spz_login_provider", Value: result.Identity.IdentityProviderID.String(), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})

	if h.processInteractionRedirect(w, r) {
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Authenticated"))
}

func (h *HttpAdapter) openIDConfiguration(w http.ResponseWriter, r *http.Request) {
	tenant, err := h.resolveTenant(r.Context(), r.Host)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	scopesSupported := tenant.PredefinedScopes
	if len(scopesSupported) == 0 {
		scopesSupported = []string{"openid", "profile", "email", "offline_access"}
	}

	issuer := "https://" + r.Host
	respondJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              issuer + routeKeys,
		"authorization_endpoint":                issuer + routeAuthorize,
		"token_endpoint":                        issuer + routeToken,
		"userinfo_endpoint":                     issuer + routeUserInfo,
		"registration_endpoint":                 issuer + routeRegister,
		"introspection_endpoint":                issuer + routeIntrospect,
		"response_types_supported":              []string{"code", "token"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token"},
		"scopes_supported":                      scopesSupported,
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
	})
}

func (h *HttpAdapter) jwks(w http.ResponseWriter, r *http.Request) {
	signer, ok := h.cryptoPort.(*jwtcrypto.JWTSigner)
	if !ok {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "jwks signer unavailable"})
		return
	}
	body, err := signer.MarshalJWKSet(r.Host)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	_, _ = w.Write([]byte(body))
}

func (h *HttpAdapter) register(w http.ResponseWriter, r *http.Request) {
	tenant, err := h.resolveTenant(r.Context(), r.Host)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
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

	predefined := tenant.PredefinedScopes
	if len(predefined) == 0 {
		predefined = []string{"openid", "profile", "email", "offline_access"}
	}

	if !isSubset(payload.AllowedScopes, predefined) {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "requested allowed_scopes are not predefined/allowed by the tenant"})
		return
	}
	if !isSubset(payload.DefaultScopes, predefined) {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "requested default_scopes are not predefined/allowed by the tenant"})
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
		GrantTypes:             payload.GrantTypes,
		ResponseTypes:          payload.ResponseTypes,
		Algorithm:              model.AlgRS256,
		AccessTokenLifetime:    time.Hour,
		RefreshTokenLifetime:   30 * 24 * time.Hour,
		IDTokenLifetime:        10 * time.Minute,
		AllowedScopes:          payload.AllowedScopes,
		DefaultScopes:          payload.DefaultScopes,
		PostLogoutRedirectURIs: []string{},
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

func (h *HttpAdapter) handleUnauthenticatedAuthorize(w http.ResponseWriter, r *http.Request, session model.InteractionSession) {
	if err := h.storagePort.SaveInteractionSession(r.Context(), session); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "spz_auth_session_id", Value: session.ID.String(), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *HttpAdapter) handleAuthenticatedAuthorize(w http.ResponseWriter, r *http.Request, client *model.ClientApplication, subject string) {
	redirectURI := r.FormValue("redirect_uri")
	codeChallenge := r.FormValue("code_challenge")
	challengeMethod := r.FormValue("code_challenge_method")
	if challengeMethod == "" {
		challengeMethod = "S256"
	}
	idpHint := r.FormValue("idp_hint")

	if idpHint != "" {
		if len(client.AllowedIDPs) > 0 && !contains(client.AllowedIDPs, idpHint) {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "identity provider not allowed for client"})
			return
		}
	}

	code := uuid.NewString()
	authSession := model.AuthorizationCodeSession{
		Code:            code,
		TenantID:        client.TenantID.String(),
		ClientID:        client.ClientID,
		Subject:         subject,
		CodeChallenge:   codeChallenge,
		ChallengeMethod: challengeMethod,
		RedirectURI:     redirectURI,
		Scopes:          client.DefaultScopes,
		ExpiresAt:       time.Now().Add(10 * time.Minute),
	}
	if err := h.authPort.InitiateAuthorize(r.Context(), authSession); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	redirectURL := redirectURI
	if strings.Contains(redirectURL, "?") {
		redirectURL += "&code=" + code
	} else {
		redirectURL += "?code=" + code
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *HttpAdapter) authorize(w http.ResponseWriter, r *http.Request) {
	tenant, err := h.resolveTenant(r.Context(), r.Host)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := r.ParseForm(); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed authorize request"})
		return
	}

	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	codeChallenge := r.FormValue("code_challenge")
	challengeMethod := r.FormValue("code_challenge_method")
	if challengeMethod == "" {
		challengeMethod = "S256"
	}
	idpHint := r.FormValue("idp_hint")
	if clientID == "" || redirectURI == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "client_id and redirect_uri are required"})
		return
	}

	client, err := h.storagePort.GetClient(r.Context(), tenant.ID, clientID)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid client"})
		return
	}
	if !contains(client.RedirectURIs, redirectURI) {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "redirect_uri not allowed"})
		return
	}

	cookie, cookieErr := r.Cookie("spz_login_subject")
	if cookieErr != nil || cookie.Value == "" {
		session := model.InteractionSession{
			ID:              uuid.New(),
			TenantID:        tenant.ID,
			ClientID:        clientID,
			RedirectURI:     redirectURI,
			CodeChallenge:   codeChallenge,
			ChallengeMethod: challengeMethod,
			IDPHint:         idpHint,
			ExpiresAt:       time.Now().Add(10 * time.Minute),
		}
		h.handleUnauthenticatedAuthorize(w, r, session)
		return
	}

	h.handleAuthenticatedAuthorize(w, r, client, cookie.Value)
}

func (h *HttpAdapter) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, tenant *model.Tenant) {
	clientID := r.FormValue("client_id")
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")
	if clientID == "" || code == "" || codeVerifier == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "client_id, code and code_verifier are required"})
		return
	}
	tokens, err := h.authPort.ExchangeCodeForTokens(r.Context(), tenant.ID, clientID, code, codeVerifier)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	respondJSON(w, http.StatusOK, tokens)
}

func (h *HttpAdapter) authenticateClient(w http.ResponseWriter, r *http.Request, tenant *model.Tenant) (*model.ClientApplication, error) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if clientID == "" || clientSecret == "" {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "client_id and client_secret are required"})
		return nil, fmt.Errorf("client_id and client_secret are required")
	}

	client, err := h.storagePort.GetClient(r.Context(), tenant.ID, clientID)
	if err != nil || client.ClientSecret == nil || *client.ClientSecret != clientSecret {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "client authentication failed"})
		return nil, fmt.Errorf("client authentication failed")
	}

	return client, nil
}

func (h *HttpAdapter) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request, tenant *model.Tenant) {
	client, err := h.authenticateClient(w, r, tenant)
	if err != nil {
		return
	}
	issuedAt := time.Now().UTC()
	accessToken, err := h.cryptoPort.SignAccessToken(model.TokenClaims{
		TokenID:   uuid.NewString(),
		Issuer:    "https://" + tenant.Domain,
		TenantID:  tenant.ID.String(),
		Subject:   client.ClientID,
		ClientID:  client.ClientID,
		Scopes:    client.DefaultScopes,
		IssuedAt:  issuedAt,
		ExpiresAt: issuedAt.Add(client.AccessTokenLifetime),
	}, client.Algorithm)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	respondJSON(w, http.StatusOK, &model.TokenSetResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(client.AccessTokenLifetime / time.Second),
	})
}

func (h *HttpAdapter) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed token request"})
		return
	}
	grantType := r.FormValue("grant_type")
	tenant, err := h.resolveTenant(r.Context(), r.Host)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(w, r, tenant)
	case "client_credentials":
		h.handleClientCredentialsGrant(w, r, tenant)
	default:
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported grant_type"})
	}
}

func (h *HttpAdapter) revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed revocation request"})
		return
	}

	tenant, err := h.resolveTenant(r.Context(), r.Host)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	client, err := h.authenticateClient(w, r, tenant)
	if err != nil {
		return
	}

	token := r.FormValue("token")
	if token == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}

	if err := h.authPort.RevokeToken(r.Context(), tenant.ID, client.ClientID, token); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *HttpAdapter) introspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed introspection request"})
		return
	}

	tenant, err := h.resolveTenant(r.Context(), r.Host)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	client, err := h.authenticateClient(w, r, tenant)
	if err != nil {
		return
	}

	token := r.FormValue("token")
	if token == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}

	res, err := h.authPort.IntrospectToken(r.Context(), tenant.ID, client.ClientID, token)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	respondJSON(w, http.StatusOK, res)
}

func (h *HttpAdapter) parseIDTokenHint(idTokenHint string) (string, string) {
	if idTokenHint == "" {
		return "", ""
	}
	parser := new(jwt.Parser)
	parsedToken, _, err := parser.ParseUnverified(idTokenHint, jwt.MapClaims{})
	if err != nil {
		return "", ""
	}
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", ""
	}
	sub, _ := claims["sub"].(string)
	aud, _ := claims["aud"].(string)
	return sub, aud
}

func (h *HttpAdapter) determinePostLogoutRedirectURI(r *http.Request, tenant *model.Tenant, clientID, requestedURI string) string {
	if requestedURI != "" && clientID != "" {
		if client, err := h.storagePort.GetClient(r.Context(), tenant.ID, clientID); err == nil {
			if contains(client.PostLogoutRedirectURIs, requestedURI) {
				return requestedURI
			}
		}
	}
	return "/"
}

func (h *HttpAdapter) logout(w http.ResponseWriter, r *http.Request) {
	tenant, err := h.resolveTenant(r.Context(), r.Host)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	idTokenHint := r.URL.Query().Get("id_token_hint")
	postLogoutRedirectURI := r.URL.Query().Get("post_logout_redirect_uri")

	subject, clientID := h.parseIDTokenHint(idTokenHint)

	if subject == "" {
		if cookie, err := r.Cookie("spz_login_subject"); err == nil {
			subject = cookie.Value
		}
	}
	if clientID == "" {
		if cookie, err := r.Cookie("spz_login_provider"); err == nil {
			clientID = cookie.Value
		}
	}

	http.SetCookie(w, &http.Cookie{Name: "spz_login_subject", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "spz_login_provider", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})

	frontChannelURIs, _ := h.authPort.ProcessLogout(r.Context(), tenant.ID, subject, clientID)

	redirectURI := h.determinePostLogoutRedirectURI(r, tenant, clientID, postLogoutRedirectURI)

	if len(frontChannelURIs) > 0 {
		w.Header().Set(contentTypeHeader, "text/html; charset=utf-8")
		component := views.Logout(frontChannelURIs, redirectURI)
		_ = component.Render(r.Context(), w)
		return
	}

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func (h *HttpAdapter) userinfo(w http.ResponseWriter, r *http.Request) {
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "bearer token required"})
		return
	}

	tokenString := strings.TrimPrefix(authorization, "Bearer ")
	parser := new(jwt.Parser)
	parsedToken, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid bearer token"})
		return
	}
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid claims format"})
		return
	}

	subject, _ := claims["sub"].(string)
	response := map[string]any{"sub": subject}
	if scopeValue, ok := claims["scope"].(string); ok {
		response["scope"] = scopeValue
	}
	respondJSON(w, http.StatusOK, response)
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

func isSubset(subset, set []string) bool {
	setMap := make(map[string]struct{}, len(set))
	for _, item := range set {
		setMap[item] = struct{}{}
	}
	for _, item := range subset {
		if _, ok := setMap[item]; !ok {
			return false
		}
	}
	return true
}
