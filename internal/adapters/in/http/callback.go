package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

// HandleOutboundCallback handles incoming OIDC redirection responses from upstream IDPs (GET /oauth/callback)
func (h *HttpAdapter) HandleOutboundCallback(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, errTenantNotResolved)
		return
	}

	incomingState := r.URL.Query().Get("state")
	incomingCode := r.URL.Query().Get("code")
	if incomingState == "" || incomingCode == "" {
		h.renderError(w, r, http.StatusBadRequest, "missing mandatory verification parameters from identity provider")
		return
	}

	// 1. Validate state token context and consume the record atomically via the domain service
	handshake, err := h.authPort.ValidateOutboundCallback(r.Context(), tenant.ID, incomingState)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	// 2. Resolve full Identity Provider metadata configuration to find the upstream Token Endpoint
	providers, err := h.storagePort.GetIdentityProviders(r.Context(), tenant.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "failed to load provider cluster maps")
		return
	}

	var matchedProvider *model.IdentityProvider
	for _, p := range providers {
		if p.ID == handshake.IdentityProviderID {
			matchedProvider = &p
			break
		}
	}

	if matchedProvider == nil || matchedProvider.Config.TokenEndpoint == "" {
		h.renderError(w, r, http.StatusBadRequest, "associated upstream identity configuration is missing or inactive")
		return
	}

	// 3. Trade the authorization code for tokens at the upstream IDP token endpoint
	upstreamTokens, err := h.exchangeUpstreamCode(r.Context(), matchedProvider, handshake, incomingCode)
	if err != nil {
		h.renderError(w, r, http.StatusBadGateway, "upstream token exchange rejected: "+err.Error())
		return
	}

	// 4. Exchange the external token inside our domain core to locate or auto-link the local User Profile
	localTokens, err := h.authPort.ExchangeExternalToken(
		r.Context(),
		tenant.ID,
		handshake.ClientID,
		upstreamTokens.IDToken,
		"urn:ietf:params:oauth:token-type:id_token",
		"",
	)
	if err != nil {
		h.renderError(w, r, http.StatusUnauthorized, "profile mapping and federation link denied: "+err.Error())
		return
	}

	// 5. Unified Format: Payload structured as "SubjectID:ProviderID:SessionID" to match weblogin layout
	sessionUUID := uuid.NewString()
	cookieVal := fmt.Sprintf("%s:%s:%s", localTokens.AccessToken, matchedProvider.ID.String(), sessionUUID)

	// 6. Leverage configuration calculators to resolve names and flags safely
	name, isSecureCookie := h.resolveSessionCookieConfig(r)

	cookie := &http.Cookie{
		Name:     name,
		Value:    cookieVal,
		Path:     "/", // Enforced path structure required by __Host- prefixes
		HttpOnly: true,
		Secure:   isSecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	}

	// Leave the 'Domain' property blank to preserve strict __Host- cookie validity limits
	http.SetCookie(w, cookie)

	// 7. Compute destination routes dynamically without falling back to hardcoded strings
	redirectDestination := handshake.TargetURI
	if redirectDestination == "" {
		redirectDestination = tenant.Config.DefaultRedirectURI
	}
	if redirectDestination == "" {
		redirectDestination = "/"
	}

	http.Redirect(w, r, redirectDestination, http.StatusFound)
}

// exchangeUpstreamCode runs an authenticated back-channel token swap execution loop
func (h *HttpAdapter) exchangeUpstreamCode(ctx context.Context, idp *model.IdentityProvider, handshake *model.OutboundHandshakeSession, code string) (*model.TokenSetResponse, error) {
	tenant, _ := TenantFromContext(ctx)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", idp.Config.ClientID)
	form.Set("redirect_uri", tenant.GetBaseURI()+routeCallback)

	if handshake.CodeVerifier != "" {
		form.Set("code_verifier", handshake.CodeVerifier)
	}
	if idp.Config.ClientSecret != "" {
		form.Set("client_secret", idp.Config.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, idp.Config.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set(model.HeaderContentType, model.ContentTypeFormUrlEncoded)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http error code: %d returned from provider", resp.StatusCode)
	}

	var tokenSet model.TokenSetResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenSet); err != nil {
		return nil, err
	}

	if tokenSet.IDToken == "" {
		return nil, errors.New("identity provider failed to return an id_token payload asset")
	}

	return &tokenSet, nil
}
