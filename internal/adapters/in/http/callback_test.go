package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/google/uuid"
)

func TestHttpAdapter_HandleOutboundCallback(t *testing.T) {
	tenantID := uuid.New()
	providerID := uuid.New()

	// 1. Establish common mock return data payloads
	mockTenant := &model.Tenant{
		ID:     tenantID,
		Domain: "auth.sprezz.local",
		Scheme: "https",
	}

	mockHandshake := &model.OutboundHandshakeSession{
		ID:                 "mock-state-token",
		TenantID:           tenantID,
		IdentityProviderID: providerID,
		ClientID:           "admin_ui",
		CodeVerifier:       "mock-code-verifier",
		TargetURI:          "https://sprezz.local",
	}

	mockLocalTokens := &model.TokenSetResponse{
		AccessToken: "mock-local-access-token",
		IDToken:     "mock-local-id-token",
	}

	tests := []struct {
		name           string
		appEnv         string
		queryParams    string
		withTenantCtx  bool
		setupMocks     func(a *portmock.AuthMock, s *portmock.StorageMock, server *httptest.Server)
		expectedStatus int
		expectedCookie string
		expectedLoc    string
	}{
		{
			name:           "Successful Callback Processing and Secure Cookie Distribution in Production",
			appEnv:         "production",
			queryParams:    "?state=mock-state-token&code=mock-auth-code",
			withTenantCtx:  true,
			expectedStatus: http.StatusFound,
			expectedCookie: model.CookieSessionNameProd,
			expectedLoc:    "https://sprezz.local",
			setupMocks: func(a *portmock.AuthMock, s *portmock.StorageMock, upstreamIDP *httptest.Server) {
				localProviders := []model.IdentityProvider{
					{
						ID:       providerID,
						TenantID: tenantID,
						Config: model.IdentityProviderConfig{
							ClientID:      "upstream-client-id",
							TokenEndpoint: upstreamIDP.URL + "/oauth/token",
						},
					},
				}

				// FIX: Use .Set closures to validate functional inputs, bypassing strict context type matching
				a.ValidateOutboundCallbackMock.Set(func(ctx context.Context, tID uuid.UUID, state string) (*model.OutboundHandshakeSession, error) {
					if tID != tenantID || state != "mock-state-token" {
						return nil, fmt.Errorf("mock: unexpected parameters to ValidateOutboundCallback")
					}
					return mockHandshake, nil
				})

				s.GetIdentityProvidersMock.Set(func(ctx context.Context, tID uuid.UUID) ([]model.IdentityProvider, error) {
					if tID != tenantID {
						return nil, fmt.Errorf("mock: unexpected tenant ID to GetIdentityProviders")
					}
					return localProviders, nil
				})

				a.ExchangeExternalTokenMock.Set(func(ctx context.Context, tID uuid.UUID, clientID string, sToken string, sTokenType string, dpop string) (*model.TokenSetResponse, error) {
					if tID != tenantID || clientID != "admin_ui" || sToken != "mock-upstream-id-token" {
						return nil, fmt.Errorf("mock: unexpected parameters to ExchangeExternalToken")
					}
					return mockLocalTokens, nil
				})
			},
		},
		{
			name:           "Successful Callback Clears Down to Standard Dev Cookie When Running Local",
			appEnv:         "local",
			queryParams:    "?state=mock-state-token&code=mock-auth-code",
			withTenantCtx:  true,
			expectedStatus: http.StatusFound,
			expectedCookie: model.CookieSessionNameDev,
			expectedLoc:    "https://sprezz.local",
			setupMocks: func(a *portmock.AuthMock, s *portmock.StorageMock, upstreamIDP *httptest.Server) {
				localProviders := []model.IdentityProvider{
					{
						ID:       providerID,
						TenantID: tenantID,
						Config: model.IdentityProviderConfig{
							ClientID:      "upstream-client-id",
							TokenEndpoint: upstreamIDP.URL + "/oauth/token",
						},
					},
				}

				a.ValidateOutboundCallbackMock.Set(func(ctx context.Context, tID uuid.UUID, state string) (*model.OutboundHandshakeSession, error) {
					if tID != tenantID || state != "mock-state-token" {
						return nil, fmt.Errorf("mock: unexpected parameters")
					}
					return mockHandshake, nil
				})

				s.GetIdentityProvidersMock.Set(func(ctx context.Context, tID uuid.UUID) ([]model.IdentityProvider, error) {
					if tID != tenantID {
						return nil, fmt.Errorf("mock: unexpected parameters")
					}
					return localProviders, nil
				})

				a.ExchangeExternalTokenMock.Set(func(ctx context.Context, tID uuid.UUID, clientID string, sToken string, sTokenType string, dpop string) (*model.TokenSetResponse, error) {
					if tID != tenantID || clientID != "admin_ui" || sToken != "mock-upstream-id-token" {
						return nil, fmt.Errorf("mock: unexpected parameters")
					}
					return mockLocalTokens, nil
				})
			},
		},
		{
			name:           "Fails Immediately If Cross-Site Tracing State Is Invalid or Missing",
			appEnv:         "production",
			queryParams:    "?state=bad-state&code=mock-auth-code",
			withTenantCtx:  true,
			expectedStatus: http.StatusBadRequest,
			setupMocks: func(a *portmock.AuthMock, s *portmock.StorageMock, upstreamIDP *httptest.Server) {
				a.ValidateOutboundCallbackMock.Set(func(ctx context.Context, tID uuid.UUID, state string) (*model.OutboundHandshakeSession, error) {
					if state == "bad-state" {
						return nil, errors.New("state invalid")
					}
					return nil, errors.New("mock: unhandled query state path")
				})
			},
		},
		{
			name:           "Fails Swiftly If Multi-Tenant Context Cannot Be Resolved From Route Middlewares",
			appEnv:         "production",
			queryParams:    "?state=mock-state-token&code=mock-auth-code",
			withTenantCtx:  false,
			expectedStatus: http.StatusBadRequest,
			setupMocks:     func(a *portmock.AuthMock, s *portmock.StorageMock, upstreamIDP *httptest.Server) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock upstream authorization server response stream loop
			upstreamIDP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth/token" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"access_token":"mock-upstream-access-token","id_token":"mock-upstream-id-token","token_type":"Bearer"}`))
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer upstreamIDP.Close()

			authMock := portmock.NewAuthMock(t)
			storageMock := portmock.NewStorageMock(t)
			tt.setupMocks(authMock, storageMock, upstreamIDP)

			adapter := &HttpAdapter{
				authPort:    authMock,
				storagePort: storageMock,
				appEnv:      tt.appEnv,
				adminDomain: "sprezz.local",
			}

			req := httptest.NewRequest(http.MethodGet, "/oauth/callback"+tt.queryParams, nil)
			if tt.appEnv == "local" {
				req.Host = "localhost"
			} else {
				req.Host = "auth.sprezz.local"
			}

			if tt.withTenantCtx {
				ctx := context.WithValue(req.Context(), tenantCtxKey, mockTenant)
				req = req.WithContext(ctx)
			}

			w := httptest.NewRecorder()
			adapter.HandleOutboundCallback(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusFound {
				loc := w.Header().Get("Location")
				if loc != tt.expectedLoc {
					t.Errorf("expected destination redirect location %s, got %s", tt.expectedLoc, loc)
				}

				cookies := w.Result().Cookies()
				var targetCookie *http.Cookie
				for _, c := range cookies {
					if c.Name == tt.expectedCookie {
						targetCookie = c
						break
					}
				}

				if targetCookie == nil {
					t.Fatalf("expected session verification cookie %q was missing from headers payload", tt.expectedCookie)
				}

				// Check that cookie values strictly map to your multi-colon layout configuration template
				expectedCookieValue := fmt.Sprintf("mock-local-access-token:%s:", providerID.String())
				if !strings.HasPrefix(targetCookie.Value, expectedCookieValue) {
					t.Errorf("cookie payload failed to pack into our unified alignment matrix structure: got %s, wanted prefix %s", targetCookie.Value, expectedCookieValue)
				}

				if tt.appEnv == "production" && !targetCookie.Secure {
					t.Error("production session cookies must strictly mandate the Secure property flag configuration")
				}
				if tt.appEnv == "local" && targetCookie.Secure {
					t.Error("local development environments running on localhost should relax Secure cookie flags")
				}
			}

			authMock.MinimockFinish()
			storageMock.MinimockFinish()
		})
	}
}
