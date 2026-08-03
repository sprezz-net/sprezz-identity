package http

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/views"

	"github.com/google/uuid"
)

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
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": errTenantNotResolved})
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
