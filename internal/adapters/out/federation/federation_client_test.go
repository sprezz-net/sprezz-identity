package federation

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

type mockRoundTripper func(req *http.Request) (*http.Response, error)

func (m mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m(req)
}

func TestFetchOIDCDiscoveryMetadata(t *testing.T) {
	tests := []struct {
		name         string
		appEnv       string
		discoveryURL string
		mockResp     *http.Response
		mockErr      error
		expectErrSub string
		expectMeta   bool
	}{
		{
			name:         "missing scheme descriptor prefix",
			appEnv:       "local",
			discoveryURL: "example.com/.well-known/openid-configuration",
			expectErrSub: "federation_client: discovery target configuration is missing a valid scheme descriptor prefix",
		},
		{
			name:         "production non-local secure boundary restriction rejects http",
			appEnv:       "production",
			discoveryURL: "http://example.com/.well-known/openid-configuration",
			expectErrSub: "federation_client: secure boundary restriction rejected target scheme; non-local environments must utilize https://",
		},
		{
			name:         "http client connection failure",
			appEnv:       "local",
			discoveryURL: "http://example.com/.well-known/openid-configuration",
			mockErr:      errors.New("network error"),
			expectErrSub: "network error",
		},
		{
			name:         "non-200 status code returned",
			appEnv:       "local",
			discoveryURL: "http://example.com/.well-known/openid-configuration",
			mockResp: &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(bytes.NewReader([]byte(""))),
			},
			expectErrSub: "federation_client: discovery endpoint returned non-200 status code: 500",
		},
		{
			name:         "failed to parse metadata JSON payload",
			appEnv:       "local",
			discoveryURL: "http://example.com/.well-known/openid-configuration",
			mockResp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte("{invalid-json"))),
			},
			expectErrSub: "federation_client: failed to parse metadata JSON payload",
		},
		{
			name:         "success on local environment using http",
			appEnv:       "local",
			discoveryURL: "http://example.com/.well-known/openid-configuration",
			mockResp: &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(bytes.NewReader([]byte(`{
					"authorization_endpoint": "http://example.com/auth",
					"token_endpoint": "http://example.com/token",
					"jwks_uri": "http://example.com/jwks"
				}`))),
			},
			expectMeta: true,
		},
		{
			name:         "success on production environment using https",
			appEnv:       "production",
			discoveryURL: "https://example.com/.well-known/openid-configuration",
			mockResp: &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(bytes.NewReader([]byte(`{
					"authorization_endpoint": "https://example.com/auth",
					"token_endpoint": "https://example.com/token",
					"jwks_uri": "https://example.com/jwks",
					"pushed_authorization_request_endpoint": "https://example.com/par",
					"code_challenge_methods_supported": ["S256"]
				}`))),
			},
			expectMeta: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := &http.Client{
				Transport: mockRoundTripper(func(req *http.Request) (*http.Response, error) {
					if tt.mockErr != nil {
						return nil, tt.mockErr
					}
					return tt.mockResp, nil
				}),
			}

			adapter := NewFederationHTTPAdapter(httpClient, tt.appEnv)
			meta, err := adapter.FetchOIDCDiscoveryMetadata(context.Background(), tt.discoveryURL)

			if tt.expectErrSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.expectErrSub)
				}
				if !strings.Contains(err.Error(), tt.expectErrSub) {
					t.Errorf("expected error %q to contain %q", err.Error(), tt.expectErrSub)
				}
				if meta != nil {
					t.Errorf("expected nil metadata on error, got: %+v", meta)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !tt.expectMeta || meta == nil {
					t.Fatalf("expected valid metadata, got nil")
				}
				if meta.AuthorizationEndpoint == "" {
					t.Errorf("expected authorization_endpoint to be populated")
				}
			}
		})
	}
}


func TestExecutePushedAuthorization(t *testing.T) {
	tests := []struct {
		name         string
		challenge    string
		clientSecret string
		mockResp     *http.Response
		mockErr      error
		expectErrSub string
		expectURI    string
	}{
		{
			name:      "success with challenge and secret",
			challenge: "test-challenge",
			mockResp: &http.Response{
				StatusCode: http.StatusCreated,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"request_uri": "urn:ietf:params:oauth:request_uri:123"}`))),
			},
			expectURI: "urn:ietf:params:oauth:request_uri:123",
		},
		{
			name: "success with status OK 200",
			mockResp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"request_uri": "urn:ietf:params:oauth:request_uri:456"}`))),
			},
			expectURI: "urn:ietf:params:oauth:request_uri:456",
		},
		{
			name:    "http client request failure",
			mockErr: errors.New("connection failed"),
			mockResp: &http.Response{
				StatusCode: http.StatusCreated,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"request_uri": "urn:123"}`))),
			},
			expectErrSub: "connection failed",
		},
		{
			name: "upstream rejected execution non-201/200",
			mockResp: &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"error": "invalid_request"}`))),
			},
			expectErrSub: "federation_client: upstream par rejected execution with status code: 400",
		},
		{
			name: "corrupt payload json structure",
			mockResp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{corrupt-json`))),
			},
			expectErrSub: "federation_client: corrupt payload structure json: invalid character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqPayload := port.OutboundOIDCParams{
				ClientID:    "test-client-id",
				RedirectURI: "http://local/callback",
				IdentityProvider: &model.IdentityProvider{
					Config: model.IdentityProviderConfig{
						ClientSecret: tt.clientSecret,
					},
				},
			}

			httpClient := &http.Client{
				Transport: mockRoundTripper(func(req *http.Request) (*http.Response, error) {
					if tt.mockErr != nil {
						return nil, tt.mockErr
					}

					// Verify request headers and fields
					if req.Method != http.MethodPost {
						t.Errorf("expected POST request, got %s", req.Method)
					}
					if req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
						t.Errorf("expected form urlencoded header, got %s", req.Header.Get("Content-Type"))
					}

					bodyBytes, _ := io.ReadAll(req.Body)
					values, err := url.ParseQuery(string(bodyBytes))
					if err != nil {
						t.Fatalf("failed to parse request form body: %v", err)
					}

					if values.Get("client_id") != "test-client-id" {
						t.Errorf("unexpected client_id: %s", values.Get("client_id"))
					}
					if values.Get("redirect_uri") != "http://local/callback" {
						t.Errorf("unexpected redirect_uri: %s", values.Get("redirect_uri"))
					}
					if values.Get("scope") != "openid profile" {
						t.Errorf("unexpected scopes: %s", values.Get("scope"))
					}
					if values.Get("state") != "state-token" {
						t.Errorf("unexpected state: %s", values.Get("state"))
					}

					if tt.challenge != "" {
						if values.Get("code_challenge") != tt.challenge {
							t.Errorf("expected code_challenge %s, got %s", tt.challenge, values.Get("code_challenge"))
						}
						if values.Get("code_challenge_method") != "S256" {
							t.Errorf("expected S256 challenge method, got %s", values.Get("code_challenge_method"))
						}
					} else {
						if values.Get("code_challenge") != "" {
							t.Errorf("unexpected code_challenge present: %s", values.Get("code_challenge"))
						}
					}

					if tt.clientSecret != "" {
						if values.Get("client_secret") != tt.clientSecret {
							t.Errorf("expected client_secret %s, got %s", tt.clientSecret, values.Get("client_secret"))
						}
					}

					return tt.mockResp, nil
				}),
			}

			adapter := NewFederationHTTPAdapter(httpClient, "local")
			uri, err := adapter.ExecutePushedAuthorization(
				context.Background(),
				"https://example.com/par",
				reqPayload,
				"state-token",
				tt.challenge,
				"openid profile",
			)

			if tt.expectErrSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.expectErrSub)
				}
				if !strings.Contains(err.Error(), tt.expectErrSub) {
					t.Errorf("expected error %q to contain %q", err.Error(), tt.expectErrSub)
				}
				if uri != "" {
					t.Errorf("expected empty request_uri on error, got: %s", uri)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if uri != tt.expectURI {
					t.Errorf("expected request_uri %s, got %s", tt.expectURI, uri)
				}
			}
		})
	}
}


func TestExchangeAuthorizationCode(t *testing.T) {
	tests := []struct {
		name         string
		codeVerifier string
		clientSecret string
		mockResp     *http.Response
		mockErr      error
		expectErrSub string
		expectTokens bool
	}{
		{
			name:         "success full options",
			codeVerifier: "ver-123",
			clientSecret: "sec-456",
			mockResp: &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(bytes.NewReader([]byte(`{
					"access_token": "acc-token-abc",
					"id_token": "id-token-xyz",
					"refresh_token": "ref-token-789",
					"token_type": "Bearer",
					"expires_in": 3600
				}`))),
			},
			expectTokens: true,
		},
		{
			name: "http client connection error",
			mockErr: errors.New("network failure"),
			mockResp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
			},
			expectErrSub: "network failure",
		},
		{
			name: "upstream rejected code exchange non-200",
			mockResp: &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"error": "invalid_grant"}`))),
			},
			expectErrSub: "federation_client: token endpoint rejected exchange with status code: 400",
		},
		{
			name: "corrupt json response format",
			mockResp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{bad-json`))),
			},
			expectErrSub: "federation_client: corrupt token response json structure: invalid character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqPayload := port.OutboundOIDCParams{
				ClientID:    "client-x",
				RedirectURI: "https://local/callback",
				IdentityProvider: &model.IdentityProvider{
					Config: model.IdentityProviderConfig{
						ClientSecret: tt.clientSecret,
					},
				},
			}

			httpClient := &http.Client{
				Transport: mockRoundTripper(func(req *http.Request) (*http.Response, error) {
					if tt.mockErr != nil {
						return nil, tt.mockErr
					}

					if req.Method != http.MethodPost {
						t.Errorf("expected POST request, got %s", req.Method)
					}
					if req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
						t.Errorf("expected form urlencoded header, got %s", req.Header.Get("Content-Type"))
					}

					bodyBytes, _ := io.ReadAll(req.Body)
					values, err := url.ParseQuery(string(bodyBytes))
					if err != nil {
						t.Fatalf("failed to parse request form body: %v", err)
					}

					if values.Get("grant_type") != "authorization_code" {
						t.Errorf("expected grant_type authorization_code, got %s", values.Get("grant_type"))
					}
					if values.Get("code") != "auth-code-000" {
						t.Errorf("expected code auth-code-000, got %s", values.Get("code"))
					}
					if values.Get("client_id") != "client-x" {
						t.Errorf("expected client_id client-x, got %s", values.Get("client_id"))
					}
					if values.Get("redirect_uri") != "https://local/callback" {
						t.Errorf("expected redirect_uri, got %s", values.Get("redirect_uri"))
					}

					if tt.codeVerifier != "" {
						if values.Get("code_verifier") != tt.codeVerifier {
							t.Errorf("expected code_verifier %s, got %s", tt.codeVerifier, values.Get("code_verifier"))
						}
					} else {
						if values.Get("code_verifier") != "" {
							t.Errorf("unexpected code_verifier present: %s", values.Get("code_verifier"))
						}
					}

					if tt.clientSecret != "" {
						if values.Get("client_secret") != tt.clientSecret {
							t.Errorf("expected client_secret %s, got %s", tt.clientSecret, values.Get("client_secret"))
						}
					}

					return tt.mockResp, nil
				}),
			}

			adapter := NewFederationHTTPAdapter(httpClient, "production")
			tokens, err := adapter.ExchangeAuthorizationCode(
				context.Background(),
				"https://example.com/token",
				reqPayload,
				"auth-code-000",
				tt.codeVerifier,
			)

			if tt.expectErrSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.expectErrSub)
				}
				if !strings.Contains(err.Error(), tt.expectErrSub) {
					t.Errorf("expected error %q to contain %q", err.Error(), tt.expectErrSub)
				}
				if tokens != nil {
					t.Errorf("expected nil tokens on error, got %+v", tokens)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !tt.expectTokens || tokens == nil {
					t.Fatalf("expected non-nil token set, got nil")
				}
				if tokens.AccessToken != "acc-token-abc" {
					t.Errorf("expected AccessToken 'acc-token-abc', got %q", tokens.AccessToken)
				}
				if tokens.IDToken != "id-token-xyz" {
					t.Errorf("expected IDToken 'id-token-xyz', got %q", tokens.IDToken)
				}
				if tokens.RefreshToken != "ref-token-789" {
					t.Errorf("expected RefreshToken 'ref-token-789', got %q", tokens.RefreshToken)
				}
				if tokens.TokenType != "Bearer" {
					t.Errorf("expected TokenType 'Bearer', got %q", tokens.TokenType)
				}
				if tokens.ExpiresIn != 3600 {
					t.Errorf("expected ExpiresIn 3600, got %d", tokens.ExpiresIn)
				}
			}
		})
	}
}
