package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

type FederationHTTPAdapter struct {
	secureClient *http.Client // Injected secure, SSRF-guarded HTTP client pool
	appEnv       string       // Environment identifier track ("local", "production", etc.)
}

// NewFederationHTTPAdapter instantiates the client, injecting structural configuration fields.
func NewFederationHTTPAdapter(client *http.Client, appEnv string) *FederationHTTPAdapter {
	return &FederationHTTPAdapter{
		secureClient: client,
		appEnv:       appEnv,
	}
}

// Guarantee compile-time compliance with our clean hexagonal port boundary
var _ port.FederationClient = (*FederationHTTPAdapter)(nil)

// FetchOIDCDiscoveryMetadata executes back-channel metadata pulls against trusted providers,
// dynamically allowing both http and https schemes strictly inside local development setups.
func (a *FederationHTTPAdapter) FetchOIDCDiscoveryMetadata(ctx context.Context, discoveryURL string) (*model.OIDCDiscoveryMetadata, error) {
	hasHTTPS := strings.HasPrefix(discoveryURL, model.SchemeHttps+"://")
	hasHTTP := strings.HasPrefix(discoveryURL, model.SchemeHttp+"://")

	// 1. Structural Guard: Ensure the incoming URL string at least contains a readable HTTP schema prefix
	if !hasHTTPS && !hasHTTP {
		return nil, errors.New("federation_client: discovery target configuration is missing a valid scheme descriptor prefix")
	}

	// 2. Strict Production Guard: If the runtime environment is NOT local, reject plain-text unencrypted http lines instantly
	if a.appEnv != "local" && !hasHTTPS {
		return nil, errors.New("federation_client: secure boundary restriction rejected target scheme; non-local environments must utilize https://")
	}

	// 3. Dispatch the request through your secure SSRF-guarded network loop
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.secureClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("federation_client: secure oidc discovery handshake failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("federation_client: discovery endpoint returned non-200 status code: %d", resp.StatusCode)
	}

	// Section 5.3 Compliance: Limit stream reader to exactly 1 Megabyte to protect memory allocations
	safeLimitReader := io.LimitReader(resp.Body, 1024*1024)

	var metadata model.OIDCDiscoveryMetadata
	if err := json.NewDecoder(safeLimitReader).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("federation_client: failed to parse metadata JSON payload: %w", err)
	}

	return &metadata, nil
}

func (a *FederationHTTPAdapter) ExecutePushedAuthorization(ctx context.Context, endpointURL string, req port.OutboundOIDCParams, state, challenge, scopes string) (string, error) {
	form := url.Values{}
	form.Set("response_type", "code")
	form.Set("client_id", req.ClientID)
	form.Set("redirect_uri", req.RedirectURI)
	form.Set("scope", scopes)
	form.Set("state", state)

	if challenge != "" {
		form.Set("code_challenge", challenge)
		form.Set("code_challenge_method", "S256")
	}

	if req.IdentityProvider.Config.ClientSecret != "" {
		form.Set("client_secret", req.IdentityProvider.Config.ClientSecret)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set(model.HeaderContentType, model.ContentTypeFormUrlEncoded)

	resp, err := a.secureClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("federation_client: secure outbound par connection failure: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("federation_client: upstream par rejected execution with status code: %d", resp.StatusCode)
	}

	safeLimitReader := io.LimitReader(resp.Body, 1024*1024)

	var parResponse struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.NewDecoder(safeLimitReader).Decode(&parResponse); err != nil {
		return "", fmt.Errorf("federation_client: corrupt payload structure json: %w", err)
	}

	return parResponse.RequestURI, nil
}

// ExchangeAuthorizationCode trades an authorization code for raw token dictionaries.
func (a *FederationHTTPAdapter) ExchangeAuthorizationCode(
	ctx context.Context,
	tokenEndpoint string,
	req port.OutboundOIDCParams,
	incomingCode,
	codeVerifier string,
) (*port.UpstreamTokenSet, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", incomingCode)
	form.Set("client_id", req.ClientID)
	form.Set("redirect_uri", req.RedirectURI)

	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}
	if req.IdentityProvider.Config.ClientSecret != "" {
		form.Set("client_secret", req.IdentityProvider.Config.ClientSecret)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set(model.HeaderContentType, model.ContentTypeFormUrlEncoded)

	resp, err := a.secureClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("federation_client: secure back-channel token trade failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("federation_client: token endpoint rejected exchange with status code: %d", resp.StatusCode)
	}

	// Limit reader to 1MB to safely prevent memory exhaustion profiles
	safeLimitReader := io.LimitReader(resp.Body, 1024*1024)

	// Unmarshal directly into your clear ports-defined structural entity
	var tokenSet port.UpstreamTokenSet
	if err := json.NewDecoder(safeLimitReader).Decode(&tokenSet); err != nil {
		return nil, fmt.Errorf("federation_client: corrupt token response json structure: %w", err)
	}

	return &tokenSet, nil
}
