package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

// BuildOutboundOidcIntent coordinates dynamic state allocations, computes optional PKCE pairs,
// triggers upstream PAR endpoints if mandated, and registers transient handshake states.
func (s *OAuthService) BuildOutboundOidcIntent(ctx context.Context, req model.OutboundOidcRequest) (model.OidcLoginIntent, model.OutboundHandshakeSession, error) {
	if req.IdentityProvider == nil {
		return model.OidcLoginIntent{}, model.OutboundHandshakeSession{}, errors.New("identity provider context is mandatory for outbound requests")
	}

	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return model.OidcLoginIntent{}, model.OutboundHandshakeSession{}, fmt.Errorf("generate outbound state token bytes: %w", err)
	}
	stateToken := base64.RawURLEncoding.EncodeToString(stateBytes)

	cfg := req.IdentityProvider.Config

	var scopesStr string
	if len(cfg.Scopes) > 0 {
		scopesStr = strings.Join(cfg.Scopes, "+")
	} else if len(req.Scopes) > 0 {
		scopesStr = strings.Join(req.Scopes, "+")
	}

	authEndpoint := "/oauth/authorize"
	if cfg.AuthorizationEndpoint != "" {
		authEndpoint = cfg.AuthorizationEndpoint
	}

	var codeVerifier, codeChallenge string
	if cfg.PkceEnabled {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			return model.OidcLoginIntent{}, model.OutboundHandshakeSession{}, fmt.Errorf("read secure pkce bytes: %w", err)
		}
		codeVerifier = base64.RawURLEncoding.EncodeToString(bytes)
		hsh := sha256.Sum256([]byte(codeVerifier))
		codeChallenge = base64.RawURLEncoding.EncodeToString(hsh[:])
	}

	handshakeSession := model.OutboundHandshakeSession{
		ID:                 stateToken,
		TenantID:           req.IdentityProvider.TenantID,
		IdentityProviderID: req.IdentityProvider.ID,
		ClientID:           req.ClientID,
		CodeVerifier:       codeVerifier,
		ExpiresAt:          s.clock.Now().Add(5 * time.Minute),
		TargetURI:          req.TargetURI,
	}

	if cfg.ParEnabled && cfg.PushedAuthorizationEndpoint != "" {
		intent, err := s.executeOutboundPAR(ctx, cfg.PushedAuthorizationEndpoint, authEndpoint, req, stateToken, codeChallenge, scopesStr)
		if err != nil {
			return model.OidcLoginIntent{}, model.OutboundHandshakeSession{}, err
		}

		if err := s.storage.SaveOutboundHandshake(ctx, handshakeSession); err != nil {
			return model.OidcLoginIntent{}, model.OutboundHandshakeSession{}, fmt.Errorf("persist par handshake state: %w", err)
		}

		return intent, handshakeSession, nil
	}

	authURL := fmt.Sprintf(
		"%s?response_type=code&client_id=%s&redirect_uri=%s&state=%s",
		authEndpoint,
		url.QueryEscape(req.ClientID),
		url.QueryEscape(req.RedirectURI),
		stateToken,
	)

	if scopesStr != "" {
		authURL = fmt.Sprintf("%s&scope=%s", authURL, scopesStr)
	}

	if cfg.PkceEnabled {
		authURL = fmt.Sprintf("%s&code_challenge=%s&code_challenge_method=S256", authURL, codeChallenge)
	}

	if err := s.storage.SaveOutboundHandshake(ctx, handshakeSession); err != nil {
		return model.OidcLoginIntent{}, model.OutboundHandshakeSession{}, fmt.Errorf("persist handshake state: %w", err)
	}

	return model.OidcLoginIntent{
		AuthURL: authURL,
		State:   stateToken,
	}, handshakeSession, nil
}

// executeOutboundPAR handles back-channel pushed authorization workflows (RFC 9126) for secure dynamic upstream links.
func (s *OAuthService) executeOutboundPAR(ctx context.Context, parURL, authURL string, req model.OutboundOidcRequest, state, challenge, scopes string) (model.OidcLoginIntent, error) {
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

	client := &http.Client{Timeout: 5 * time.Second}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, parURL, strings.NewReader(form.Encode()))
	if err != nil {
		return model.OidcLoginIntent{}, err
	}
	httpReq.Header.Set("Content-Type", model.ContentTypeFormUrlEncoded)

	resp, err := client.Do(httpReq)
	if err != nil {
		return model.OidcLoginIntent{}, fmt.Errorf("outbound par network failure: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return model.OidcLoginIntent{}, fmt.Errorf("upstream par rejected with status code: %d", resp.StatusCode)
	}

	var parResponse struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parResponse); err != nil {
		return model.OidcLoginIntent{}, fmt.Errorf("decode par payload json: %w", err)
	}

	finalURL := fmt.Sprintf("%s?client_id=%s&request_uri=%s",
		authURL,
		url.QueryEscape(req.ClientID),
		url.QueryEscape(parResponse.RequestURI),
	)

	return model.OidcLoginIntent{
		AuthURL: finalURL,
		State:   state,
	}, nil
}

// ValidateOutboundCallback cleans up and validates an incoming federation code return tracking vector.
func (s *OAuthService) ValidateOutboundCallback(ctx context.Context, tenantID uuid.UUID, incomingState string) (*model.OutboundHandshakeSession, error) {
	if incomingState == "" {
		return nil, errors.New("mandatory federation callback tracking state parameter is missing")
	}

	// 1. Consume the row from database storage immediately to prevent replay vectors
	// (Invokes your outbound port.Storage interface)
	handshake, err := s.storage.GetAndConsumeOutboundHandshake(ctx, tenantID, incomingState)
	if err != nil || handshake == nil {
		return nil, errors.New("outbound federation context is invalid, unknown, or expired")
	}

	// 2. Validate expiration constraints in the domain core
	if s.clock.Now().After(handshake.ExpiresAt) {
		return nil, errors.New("outbound verification window has closed")
	}

	return handshake, nil
}
