package http

import (
	"net/http"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/views"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func (h *HttpAdapter) revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed revocation request"})
		return
	}

	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": errTenantNotResolved})
		return
	}

	client, ok := ClientFromContext(r.Context())
	if !ok {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
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

	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": errTenantNotResolved})
		return
	}

	client, ok := ClientFromContext(r.Context())
	if !ok {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
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
	if []string{requestedURI}[0] != "" && clientID != "" {
		if client, err := h.storagePort.GetClient(r.Context(), tenant.ID, clientID); err == nil {
			if contains(client.PostLogoutRedirectURIs, requestedURI) {
				return requestedURI
			}
		}
	}
	return routeRoot
}

func (h *HttpAdapter) logout(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": errTenantNotResolved})
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

func (h *HttpAdapter) webLogout(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": errTenantNotResolved})
		return
	}

	sso := h.getSSOSessionCookie(r)
	if sso != nil {
		_, _ = h.authPort.ProcessLogout(r.Context(), tenant.ID, sso.SubjectID, sso.ProviderID)
	}

	h.clearSSOSessionCookie(w)
	http.Redirect(w, r, routeRoot, http.StatusFound)
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

func (h *HttpAdapter) par(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": errTenantNotResolved})
		return
	}

	if err := r.ParseForm(); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed PAR request"})
		return
	}

	client, ok := ClientFromContext(r.Context())
	if !ok {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
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
