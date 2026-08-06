package http

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/service"
	"sprezz-identity/internal/views/public"

	"github.com/google/uuid"
)

type ssoSession struct {
	SubjectID  string
	ProviderID string
	SessionID  string
}

func (h *HttpAdapter) resolveSessionCookieConfig(r *http.Request) (string, bool) {
	name := model.CookieSessionNameProd
	secure := true

	appEnv := os.Getenv("APP_ENV")
	if appEnv == "" {
		appEnv = "local"
	}

	host := r.Host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	isLocalHost := host == "localhost" || host == "127.0.0.1"

	if appEnv == "local" && isLocalHost {
		name = model.CookieSessionNameDev
		secure = false
	}

	return name, secure
}

func (h *HttpAdapter) setSSOSessionCookie(w http.ResponseWriter, r *http.Request, session ssoSession) {
	val := fmt.Sprintf("%s:%s:%s", session.SubjectID, session.ProviderID, session.SessionID)
	name, secure := h.resolveSessionCookieConfig(r)
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *HttpAdapter) getSSOSessionCookie(r *http.Request) *ssoSession {
	name, _ := h.resolveSessionCookieConfig(r)
	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		altName := model.CookieSessionNameDev
		if name == model.CookieSessionNameDev {
			altName = model.CookieSessionNameProd
		}
		cookie, err = r.Cookie(altName)
		if err != nil || cookie.Value == "" {
			return nil
		}
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

func (h *HttpAdapter) clearSSOSessionCookie(w http.ResponseWriter, r *http.Request) {
	name, secure := h.resolveSessionCookieConfig(r)
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	altName := model.CookieSessionNameDev
	if name == model.CookieSessionNameDev {
		altName = model.CookieSessionNameProd
	}
	http.SetCookie(w, &http.Cookie{
		Name:     altName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *HttpAdapter) loginRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentTypeHeader, contentTypeHtml)

	allowSignup := false
	if tenant, err := h.resolveTenant(r.Context(), r.Host); err == nil {
		allowSignup = tenant.Config.AllowSignup
	}

	component := public.Login("", allowSignup)
	_ = component.Render(r.Context(), w)
}

func (h *HttpAdapter) processInteractionRedirect(w http.ResponseWriter, r *http.Request, provider *model.IdentityProvider) bool {
	sessionCookie, err := r.Cookie("spz_auth_session_id")
	if err != nil || sessionCookie.Value == "" {
		return false
	}
	sessionUUID, parseErr := uuid.Parse(sessionCookie.Value)
	if parseErr != nil {
		return false
	}
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
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

	var acrValues, claimsJSON string
	if strings.HasPrefix(session.ACRValues, "{") {
		claimsJSON = session.ACRValues
	} else {
		acrValues = session.ACRValues
	}

	if _, err := h.oauthValidator.ValidateACR(r.Context(), tenant, provider, acrValues, claimsJSON); err != nil {
		h.clearSSOSessionCookie(w, r)
		h.renderError(w, r, http.StatusForbidden, err.Error())
		return true
	}

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
	if session.State != "" {
		redirectURL += "&state=" + url.QueryEscape(session.State)
	}
	if session.Nonce != "" {
		redirectURL += "&nonce=" + url.QueryEscape(session.Nonce)
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
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(errTenantNotResolved))
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
		errMsg := err.Error()
		if errMsg == "invalid username or password" {
			errMsg = "Invalid username or password"
		}
		_, _ = fmt.Fprintf(w, `<div style="color:red;margin-bottom:1rem;">%s</div>`, html.EscapeString(errMsg))
		return
	}

	provider, err := h.storagePort.GetIdentityProviderByType(r.Context(), tenant.ID, model.UsernamePasswordIDPType)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Self-service login is not configured/enabled for this tenant"))
		return
	}

	h.setSSOSessionCookie(w, r, ssoSession{
		SubjectID:  result.UserProfile.ID.String(),
		ProviderID: provider.ID.String(),
		SessionID:  uuid.NewString(),
	})

	if h.processInteractionRedirect(w, r, provider) {
		return
	}

	defaultRedirect := tenant.Config.DefaultRedirectURI
	if defaultRedirect == "" {
		defaultRedirect = "/"
	}

	if err := h.oauthValidator.ValidateRedirect(r.Context(), tenant, nil, defaultRedirect); err != nil {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(err.Error()))
		return
	}

	w.Header().Set("HX-Redirect", defaultRedirect)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Authenticated"))
}

func (h *HttpAdapter) handleUnauthenticatedAuthorize(w http.ResponseWriter, r *http.Request, session model.InteractionSession) {
	if err := h.storagePort.SaveInteractionSession(r.Context(), session); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "spz_auth_session_id", Value: session.ID.String(), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, routeRoot, http.StatusFound)
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

	if idpHint != "" {
		if len(client.AllowedIDPs) > 0 && !contains(client.AllowedIDPs, idpHint) {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "identity provider not allowed for client"})
			return
		}
	}

	tenant, _ := TenantFromContext(r.Context())
	providers, _ := h.storagePort.GetEnabledIdentityProviders(r.Context(), tenant.ID)
	var provider *model.IdentityProvider
	for _, p := range providers {
		if p.ID.String() == sso.ProviderID {
			provider = &p
			break
		}
	}

	reachedACR := ""
	if provider != nil {
		reachedACR = h.oauthValidator.EvaluateReachedACR(tenant, provider)
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
		ACRValues:       reachedACR,
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
	issuer := schemeHttps + r.Host
	redirectURL += "&iss=" + url.QueryEscape(issuer)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *HttpAdapter) extractAuthorizeParams(r *http.Request, tenant *model.Tenant) (clientID, redirectURI, codeChallenge, challengeMethod, idpHint, state, nonce, acrValues string, scopes []string, err error) {
	requestURI := r.FormValue("request_uri")
	if requestURI != "" {
		const prefix = "urn:ietf:params:oauth:request_uri:"
		if !strings.HasPrefix(requestURI, prefix) {
			return "", "", "", "", "", "", "", "", nil, errors.New("invalid or expired request_uri")
		}
		uuidPart := strings.TrimPrefix(requestURI, prefix)
		if _, parseErr := uuid.Parse(uuidPart); parseErr != nil {
			return "", "", "", "", "", "", "", "", nil, errors.New("invalid or expired request_uri")
		}

		parReq, loadErr := h.authPort.GetAndConsumePAR(r.Context(), tenant.ID, requestURI)
		if loadErr != nil {
			return "", "", "", "", "", "", "", "", nil, errors.New("invalid or expired request_uri")
		}
		queryClientID := r.FormValue("client_id")
		if queryClientID != "" && queryClientID != parReq.ClientID {
			return "", "", "", "", "", "", "", "", nil, errors.New("client_id mismatch with request_uri")
		}
		return parReq.ClientID, parReq.RedirectURI, parReq.CodeChallenge, parReq.ChallengeMethod, parReq.IDPHint, parReq.State, parReq.Nonce, parReq.ACRValues, parReq.Scopes, nil
	}

	return r.FormValue("client_id"), r.FormValue("redirect_uri"), r.FormValue("code_challenge"), r.FormValue("code_challenge_method"), r.FormValue("idp_hint"), r.FormValue("state"), r.FormValue("nonce"), r.FormValue("acr_values"), nil, nil
}

func (h *HttpAdapter) authorize(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": errTenantNotResolved})
		return
	}

	if err := r.ParseForm(); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed authorize request"})
		return
	}

	clientID, redirectURI, codeChallenge, challengeMethod, idpHint, state, nonce, acrValues, scopes, err := h.extractAuthorizeParams(r, tenant)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := h.oauthValidator.ValidateState(r.Context(), state); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
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
	if err := h.oauthValidator.ValidateRedirect(r.Context(), tenant, client, redirectURI); err != nil {
		if errors.Is(err, service.ErrClientRedirectNotAllowed) {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		h.renderError(w, r, http.StatusForbidden, err.Error())
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
		claimsJSON := r.FormValue("claims")
		sessionACR := acrValues
		if claimsJSON != "" {
			sessionACR = claimsJSON
		}
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
			ACRValues:       sessionACR,
		}
		h.handleUnauthenticatedAuthorize(w, r, session)
		return
	}

	h.handleAuthenticatedAuthorize(w, r, client, sso)
}
