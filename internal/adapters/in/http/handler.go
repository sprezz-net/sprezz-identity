package http

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwtcrypto "sprezz-identity/internal/adapters/out/crypto"
	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type HttpAdapter struct {
	authPort    port.Auth
	storagePort port.Storage
	cryptoPort  port.Crypto
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
		router:      chi.NewRouter(),
	}
	h.registerRoutes()
	return h
}

func (h *HttpAdapter) Router() http.Handler {
	return h.router
}

func (h *HttpAdapter) registerRoutes() {
	h.router.Get("/.well-known/openid-configuration", h.openIDConfiguration)
	h.router.Get("/.well-known/jwks.json", h.jwks)
	h.router.Post("/oauth/register", h.register)
	h.router.Get("/oauth/authorize", h.authorize)
	h.router.Post("/oauth/authorize", h.authorize)
	h.router.Post("/oauth/token", h.token)
	h.router.Get("/oauth/userinfo", h.userinfo)
}

func (h *HttpAdapter) openIDConfiguration(w http.ResponseWriter, r *http.Request) {
	issuer := "https://" + r.Host
	respondJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"userinfo_endpoint":                     issuer + "/oauth/userinfo",
		"registration_endpoint":                 issuer + "/oauth/register",
		"response_types_supported":              []string{"code", "token"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
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
	w.Header().Set("Content-Type", "application/json")
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

	code := uuid.NewString()
	session := model.AuthorizationCodeSession{
		Code:            code,
		TenantID:        tenant.ID.String(),
		ClientID:        clientID,
		Subject:         "anon-subject",
		CodeChallenge:   codeChallenge,
		ChallengeMethod: challengeMethod,
		RedirectURI:     redirectURI,
		Scopes:          client.DefaultScopes,
		ExpiresAt:       time.Now().Add(10 * time.Minute),
	}
	if err := h.authPort.InitiateAuthorize(r.Context(), session); err != nil {
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
	case "client_credentials":
		clientID := r.FormValue("client_id")
		clientSecret := r.FormValue("client_secret")
		if clientID == "" || clientSecret == "" {
			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "client_id and client_secret are required"})
			return
		}
		client, err := h.storagePort.GetClient(r.Context(), tenant.ID, clientID)
		if err != nil || client.ClientSecret == nil || *client.ClientSecret != clientSecret {
			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "client authentication failed"})
			return
		}
		issuedAt := time.Now().UTC()
		accessToken, err := h.cryptoPort.SignAccessToken(model.TokenClaims{
			TokenID:   uuid.NewString(),
			Issuer:    "https://" + tenant.Domain,
			TenantID:  tenant.ID.String(),
			Subject:   clientID,
			ClientID:  clientID,
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
	default:
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported grant_type"})
	}
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
	w.Header().Set("Content-Type", "application/json")
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

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
