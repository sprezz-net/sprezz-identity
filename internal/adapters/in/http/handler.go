package http

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwtcrypto "sprezz-identity/internal/adapters/out/crypto"
	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/service"
	"sprezz-identity/internal/views"

	"github.com/a-h/templ"
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
	routePAR          = "/oauth/par"
	contentTypeHeader = "Content-Type"
	contentTypeJSON   = "application/json"
	schemeHttps       = "https://"
	errInvalidDPoP    = "invalid DPoP proof: "
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
	AllowedAudiences    []string `json:"allowed_audiences"`
	TokenEndpointMethod string   `json:"token_endpoint_auth_method"`
}

func NewHttpAdapter(a port.Auth, s port.Storage, c port.Crypto, cl port.Clock) *HttpAdapter {
	h := &HttpAdapter{
		authPort:    a,
		storagePort: s,
		cryptoPort:  c,
		idpService:  service.NewIdentityProviderService(s, cl),
		router:      chi.NewRouter(),
	}
	h.router.Use(h.cspMiddleware)
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
	h.router.Post(routePAR, h.par)
}

type ssoSession struct {
	SubjectID  string
	ProviderID string
	SessionID  string
}

func (h *HttpAdapter) setSSOSessionCookie(w http.ResponseWriter, session ssoSession) {
	val := fmt.Sprintf("%s:%s:%s", session.SubjectID, session.ProviderID, session.SessionID)
	http.SetCookie(w, &http.Cookie{
		Name:     "spz_session",
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *HttpAdapter) getSSOSessionCookie(r *http.Request) *ssoSession {
	cookie, err := r.Cookie("spz_session")
	if err != nil || cookie.Value == "" {
		return nil
	}
	parts := strings.Split(cookie.Value, ":")
	if len(parts) != 3 {
		return nil
	}
	return &ssoSession{
		SubjectID:  parts[0],
		ProviderID: parts[1],
		SessionID:  parts[2],
	}
}

func (h *HttpAdapter) clearSSOSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "spz_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
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
	tenant, err := h.resolveTenant(r.Context(), r.Host)
	if err != nil {
		return false
	}
	session, loadErr := h.storagePort.GetAndConsumeInteractionSession(r.Context(), tenant.ID, sessionUUID)
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

	h.setSSOSessionCookie(w, ssoSession{
		SubjectID:  result.UserProfile.ID.String(),
		ProviderID: result.Identity.IdentityProviderID.String(),
		SessionID:  uuid.NewString(),
	})

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

	issuer := schemeHttps + r.Host
	respondJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              issuer + routeKeys,
		"authorization_endpoint":                issuer + routeAuthorize,
		"token_endpoint":                        issuer + routeToken,
		"userinfo_endpoint":                     issuer + routeUserInfo,
		"registration_endpoint":                 issuer + routeRegister,
		"introspection_endpoint":                issuer + routeIntrospect,
		"end_session_endpoint":                  issuer + routeLogout,
		"pushed_authorization_request_endpoint": issuer + routePAR,
		"frontchannel_logout_supported":         true,
		"frontchannel_logout_session_supported": true,
		"response_types_supported":              []string{"code", "token"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token"},
		"scopes_supported":                      scopesSupported,
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"dpop_signing_alg_values_supported":    []string{"RS256"},
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

	if len(payload.AllowedAudiences) > 0 {
		if !isSubset(payload.AllowedAudiences, tenant.PredefinedAudiences) {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "requested allowed_audiences are not predefined/allowed by the tenant"})
			return
		}
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
		AllowedAudiences:       payload.AllowedAudiences,
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

func (h *HttpAdapter) handleAuthenticatedAuthorize(w http.ResponseWriter, r *http.Request, client *model.ClientApplication, sso *ssoSession) {
	redirectURI := r.FormValue("redirect_uri")
	codeChallenge := r.FormValue("code_challenge")
	challengeMethod := r.FormValue("code_challenge_method")
	if challengeMethod == "" {
		challengeMethod = "S256"
	}
	idpHint := r.FormValue("idp_hint")
	state := r.FormValue("state")
	nonce := r.FormValue("nonce")
	acrValues := r.FormValue("acr_values")

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
		Subject:         sso.SubjectID,
		CodeChallenge:   codeChallenge,
		ChallengeMethod: challengeMethod,
		RedirectURI:     redirectURI,
		Scopes:          client.DefaultScopes,
		ExpiresAt:       time.Now().Add(10 * time.Minute),
		SessionID:       sso.SessionID,
		State:           state,
		Nonce:           nonce,
		ACRValues:       acrValues,
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
	if state != "" {
		redirectURL += "&state=" + url.QueryEscape(state)
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

	requestURI := r.FormValue("request_uri")
	var clientID, redirectURI, codeChallenge, challengeMethod, idpHint, state, nonce, acrValues string
	var scopes []string

	if requestURI != "" {
		parReq, err := h.authPort.GetAndConsumePAR(r.Context(), tenant.ID, requestURI)
		if err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired request_uri"})
			return
		}
		clientID = parReq.ClientID
		redirectURI = parReq.RedirectURI
		codeChallenge = parReq.CodeChallenge
		challengeMethod = parReq.ChallengeMethod
		idpHint = parReq.IDPHint
		state = parReq.State
		nonce = parReq.Nonce
		scopes = parReq.Scopes
		acrValues = parReq.ACRValues
	} else {
		clientID = r.FormValue("client_id")
		redirectURI = r.FormValue("redirect_uri")
		codeChallenge = r.FormValue("code_challenge")
		challengeMethod = r.FormValue("code_challenge_method")
		idpHint = r.FormValue("idp_hint")
		state = r.FormValue("state")
		nonce = r.FormValue("nonce")
		acrValues = r.FormValue("acr_values")
	}

	if challengeMethod == "" {
		challengeMethod = "S256"
	}
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

	r.Form.Set("client_id", clientID)
	r.Form.Set("redirect_uri", redirectURI)
	r.Form.Set("code_challenge", codeChallenge)
	r.Form.Set("code_challenge_method", challengeMethod)
	r.Form.Set("idp_hint", idpHint)
	r.Form.Set("state", state)
	r.Form.Set("nonce", nonce)
	r.Form.Set("acr_values", acrValues)

	_ = scopes

	sso := h.getSSOSessionCookie(r)
	if sso == nil {
		session := model.InteractionSession{
			ID:              uuid.New(),
			TenantID:        tenant.ID,
			ClientID:        clientID,
			RedirectURI:     redirectURI,
			CodeChallenge:   codeChallenge,
			ChallengeMethod: challengeMethod,
			IDPHint:         idpHint,
			ExpiresAt:       time.Now().Add(10 * time.Minute),
			State:           state,
			Nonce:           nonce,
			ACRValues:       acrValues,
		}
		h.handleUnauthenticatedAuthorize(w, r, session)
		return
	}

	h.handleAuthenticatedAuthorize(w, r, client, sso)
}

func (h *HttpAdapter) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, tenant *model.Tenant) {
	clientID := r.FormValue("client_id")
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")
	if clientID == "" || code == "" || codeVerifier == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "client_id, code and code_verifier are required"})
		return
	}
	dpopJKT, err := h.validateDPoPProof(r)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": errInvalidDPoP + err.Error()})
		return
	}
	tokens, err := h.authPort.ExchangeCodeForTokens(r.Context(), tenant.ID, clientID, code, codeVerifier, dpopJKT)
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
	dpopJKT, err := h.validateDPoPProof(r)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": errInvalidDPoP + err.Error()})
		return
	}
	issuedAt := time.Now().UTC()
	accessToken, err := h.cryptoPort.SignAccessToken(model.TokenClaims{
		TokenID:   uuid.NewString(),
		Issuer:    schemeHttps + tenant.Domain,
		TenantID:  tenant.ID.String(),
		Subject:   client.ClientID,
		ClientID:  client.ClientID,
		Scopes:    client.DefaultScopes,
		IssuedAt:  issuedAt,
		ExpiresAt: issuedAt.Add(client.AccessTokenLifetime),
		Audiences: client.AllowedAudiences,
		DPoPHash:  dpopJKT,
	}, client.Algorithm)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	tokenType := "Bearer"
	if dpopJKT != "" {
		tokenType = "DPoP"
	}
	respondJSON(w, http.StatusOK, &model.TokenSetResponse{
		AccessToken: accessToken,
		TokenType:   tokenType,
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

	sso := h.getSSOSessionCookie(r)
	if subject == "" && sso != nil {
		subject = sso.SubjectID
	}
	if clientID == "" && sso != nil {
		clientID = sso.ProviderID
	}

	h.clearSSOSessionCookie(w)

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

func (h *HttpAdapter) validateUserInfoDPoP(r *http.Request, claims jwt.MapClaims, isDPoP bool) error {
	cnfVal, ok := claims["cnf"].(map[string]any)
	if !ok {
		return nil
	}
	jktVal, _ := cnfVal["jkt"].(string)
	if jktVal == "" {
		return nil
	}
	if !isDPoP {
		return errors.New("token is DPoP-bound, but Bearer scheme was used")
	}
	dpopJKT, err := h.validateDPoPProof(r)
	if err != nil {
		return fmt.Errorf("%s%w", errInvalidDPoP, err)
	}
	if dpopJKT != jktVal {
		return errors.New("DPoP proof key mismatch")
	}
	return nil
}

func (h *HttpAdapter) userinfo(w http.ResponseWriter, r *http.Request) {
	authorization := r.Header.Get("Authorization")
	tokenString := ""
	isDPoP := false
	if strings.HasPrefix(authorization, "Bearer ") {
		tokenString = strings.TrimPrefix(authorization, "Bearer ")
	} else if strings.HasPrefix(authorization, "DPoP ") {
		tokenString = strings.TrimPrefix(authorization, "DPoP ")
		isDPoP = true
	} else {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "bearer or dpop token required"})
		return
	}

	claims, err := h.cryptoPort.VerifyToken(tokenString)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}

	if err := h.validateUserInfoDPoP(r, claims, isDPoP); err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
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

func (h *HttpAdapter) validateAuthorizeParams(client *model.ClientApplication, tenant *model.Tenant, redirectURI string, scopes []string) error {
	if !contains(client.RedirectURIs, redirectURI) {
		return errors.New("redirect_uri not allowed")
	}

	predefined := tenant.PredefinedScopes
	if len(predefined) == 0 {
		predefined = []string{"openid", "profile", "email", "offline_access"}
	}
	if !isSubset(scopes, predefined) {
		return errors.New("requested scopes are not predefined/allowed by the tenant")
	}
	return nil
}

func (h *HttpAdapter) parseDPoPPubKey(dpopHeader string) (*rsa.PublicKey, string, error) {
	parser := new(jwt.Parser)
	token, _, err := parser.ParseUnverified(dpopHeader, jwt.MapClaims{})
	if err != nil {
		return nil, "", fmt.Errorf("invalid DPoP header format: %w", err)
	}

	jwkHeader, ok := token.Header["jwk"].(map[string]any)
	if !ok || jwkHeader == nil {
		return nil, "", errors.New("missing jwk in DPoP header")
	}

	typHeader, _ := token.Header["typ"].(string)
	if typHeader != "dpop+jwt" {
		return nil, "", errors.New("invalid DPoP header typ, must be dpop+jwt")
	}

	jwkJSON, err := json.Marshal(jwkHeader)
	if err != nil {
		return nil, "", fmt.Errorf("marshal jwk: %w", err)
	}

	var rsaPub struct {
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	if err := json.Unmarshal(jwkJSON, &rsaPub); err != nil {
		return nil, "", fmt.Errorf("unmarshal rsa jwk: %w", err)
	}
	if rsaPub.Kty != "RSA" {
		return nil, "", fmt.Errorf("unsupported JWK kty: %s", rsaPub.Kty)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(rsaPub.N)
	if err != nil {
		return nil, "", fmt.Errorf("decode jwk n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(rsaPub.E)
	if err != nil {
		return nil, "", fmt.Errorf("decode jwk e: %w", err)
	}
	if len(eBytes) < 1 {
		return nil, "", errors.New("invalid jwk e")
	}
	var eVal int
	for _, b := range eBytes {
		eVal = (eVal << 8) | int(b)
	}

	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eVal,
	}

	sortedJWKJSON := fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, rsaPub.E, rsaPub.N)
	hsh := sha256.Sum256([]byte(sortedJWKJSON))
	jkt := base64.RawURLEncoding.EncodeToString(hsh[:])

	return pubKey, jkt, nil
}

func (h *HttpAdapter) validateDPoPClaims(r *http.Request, claims jwt.MapClaims) (time.Time, error) {
	htm, _ := claims["htm"].(string)
	htu, _ := claims["htu"].(string)
	jti, _ := claims["jti"].(string)
	iatVal, _ := claims["iat"].(float64)

	if htm == "" || htu == "" || jti == "" || iatVal == 0 {
		return time.Time{}, errors.New("missing mandatory DPoP claims (htm, htu, jti, iat)")
	}

	if !strings.EqualFold(htm, r.Method) {
		return time.Time{}, fmt.Errorf("DPoP htm mismatch: expected %s, got %s", r.Method, htm)
	}

	reqURL := schemeHttps + r.Host + r.URL.Path
	if !strings.HasPrefix(htu, "http://") && !strings.HasPrefix(htu, "https://") {
		reqURL = r.URL.Path
	}
	normHTU := strings.Split(htu, "?")[0]
	normReq := strings.Split(reqURL, "?")[0]
	if !strings.HasSuffix(normReq, normHTU) && !strings.HasSuffix(normHTU, normReq) {
		return time.Time{}, fmt.Errorf("DPoP htu mismatch: expected %s, got %s", normReq, normHTU)
	}

	iat := time.Unix(int64(iatVal), 0)
	now := time.Now()
	if iat.Before(now.Add(-2 * time.Minute)) || iat.After(now.Add(2 * time.Minute)) {
		return time.Time{}, errors.New("DPoP proof has expired or is in the future")
	}

	return iat, nil
}

func (h *HttpAdapter) validateDPoPProof(r *http.Request) (string, error) {
	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		return "", nil
	}

	pubKey, jkt, err := h.parseDPoPPubKey(dpopHeader)
	if err != nil {
		return "", err
	}

	parsedToken, err := jwt.Parse(dpopHeader, func(t *jwt.Token) (any, error) {
		return pubKey, nil
	})
	if err != nil || !parsedToken.Valid {
		return "", fmt.Errorf("invalid DPoP proof signature: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid DPoP claims")
	}

	iat, err := h.validateDPoPClaims(r, claims)
	if err != nil {
		return "", err
	}

	jti, _ := claims["jti"].(string)
	used, err := h.storagePort.IsDPoPProofUsed(r.Context(), jti)
	if err != nil || used {
		return "", errors.New("DPoP proof jti has already been used")
	}

	if err := h.storagePort.SaveDPoPProof(r.Context(), jti, iat.Add(5 * time.Minute)); err != nil {
		return "", fmt.Errorf("save DPoP proof: %w", err)
	}

	return jkt, nil
}

func (h *HttpAdapter) par(w http.ResponseWriter, r *http.Request) {
	tenant, err := h.resolveTenant(r.Context(), r.Host)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := r.ParseForm(); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed PAR request"})
		return
	}

	client, err := h.authenticateClient(w, r, tenant)
	if err != nil {
		return
	}

	redirectURI := r.FormValue("redirect_uri")
	if redirectURI == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "redirect_uri is required"})
		return
	}

	scopesStr := r.FormValue("scope")
	var scopes []string
	if scopesStr != "" {
		scopes = strings.Split(scopesStr, " ")
	} else {
		scopes = client.DefaultScopes
	}

	if err := h.validateAuthorizeParams(client, tenant, redirectURI, scopes); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	codeChallenge := r.FormValue("code_challenge")
	challengeMethod := r.FormValue("code_challenge_method")
	if challengeMethod == "" {
		challengeMethod = "S256"
	}

	requestURI := "urn:ietf:params:oauth:request_uri:" + uuid.NewString()
	expiresIn := 600

	parReq := model.PushedAuthorizationRequest{
		RequestURI:      requestURI,
		TenantID:        tenant.ID,
		ClientID:        client.ClientID,
		RedirectURI:     redirectURI,
		CodeChallenge:   codeChallenge,
		ChallengeMethod: challengeMethod,
		Scopes:          scopes,
		State:           r.FormValue("state"),
		Nonce:           r.FormValue("nonce"),
		IDPHint:         r.FormValue("idp_hint"),
		ACRValues:       r.FormValue("acr_values"),
		ExpiresAt:       time.Now().Add(10 * time.Minute),
	}

	if err := h.authPort.SavePAR(r.Context(), parReq); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	respondJSON(w, http.StatusCreated, map[string]any{
		"request_uri": requestURI,
		"expires_in":  expiresIn,
	})
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
