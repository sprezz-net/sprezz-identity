package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

// Helper function to build a pre-authenticated client request context matching ClientAuthMiddleware outputs
func buildMockAuthenticatedContext(tenantID uuid.UUID, clientID string, isAuthenticated bool) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, TenantIDContextKey, tenantID)
	ctx = context.WithValue(ctx, ClientIDContextKey, clientID)
	ctx = context.WithValue(ctx, ClientAuthFlagKey, isAuthenticated)
	ctx = context.WithValue(ctx, AppContextKey, &model.Application{ClientID: clientID, IsEnabled: true})
	ctx = context.WithValue(ctx, ProfileContextKey, &model.ApplicationProfile{IsEnabled: true})
	ctx = context.WithValue(ctx, GroupContextKey, &model.ApplicationGroup{IsEnabled: true})
	return ctx
}

func TestTokenHandler_HandleTokenRequest_ClientCredentials_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthUseCaseMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", Scheme: "https"}
	secret := "supersecret"
	fakeHash := "$argon2id$v=19$m=65536,t=3,p=4$storedsecurecredentialhash"

	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	storage.GetApplicationByClientIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, clientID string) (*model.Application, *model.ApplicationProfile, *model.ApplicationGroup, error) {
		return &model.Application{
				ClientID:         "cc-client",
				ClientSecretHash: &fakeHash,
			},
			&model.ApplicationProfile{
				TokenEndpointAuthMethod: model.AuthMethodClientSecretPost,
			},
			&model.ApplicationGroup{},
			nil
	})

	crypto.CompareCredentialMock.Expect(fakeHash, secret).Return(true, nil)

	auth.ExchangeClientCredentialsMock.Set(func(ctx context.Context, cmd port.ExchangeClientCredentialsCommand) (*model.TokenSetResponse, error) {
		return &model.TokenSetResponse{
			AccessToken: "mock-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}, nil
	})

	adapter := NewHttpAdapter(tuc, auth, fuc, nil, suc, upuc, uruc, portmock.NewLocalAuthUseCaseMock(ctrl), nil, nil, nil, storage, crypto, "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewBufferString("grant_type=client_credentials&client_id=cc-client&client_secret=supersecret"))
	req.Header.Set(model.HeaderContentType, model.ContentTypeFormUrlEncoded)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "mock-access-token") {
		t.Fatalf("expected response to contain access token")
	}
}

func TestTokenHandler_HandleTokenRequest_AuthCodeExchange_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthUseCaseMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", Scheme: "https"}

	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	storage.GetApplicationByClientIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, clientID string) (*model.Application, *model.ApplicationProfile, *model.ApplicationGroup, error) {
		return &model.Application{ClientID: "ac-client"},
			&model.ApplicationProfile{TokenEndpointAuthMethod: model.AuthMethodNone},
			&model.ApplicationGroup{},
			nil
	})

	auth.ExchangeCodeForTokensMock.Set(func(ctx context.Context, cmd port.ExchangeCodeForTokensCommand) (*model.TokenSetResponse, error) {
		return &model.TokenSetResponse{
			AccessToken:  "at-123",
			IDToken:      "id-123",
			RefreshToken: "rt-123",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}, nil
	})

	adapter := NewHttpAdapter(tuc, auth, fuc, nil, suc, upuc, uruc, portmock.NewLocalAuthUseCaseMock(ctrl), nil, nil, nil, storage, crypto, "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewBufferString("grant_type=authorization_code&client_id=ac-client&code=code123&code_verifier=verifier123"))
	req.Header.Set(model.HeaderContentType, model.ContentTypeFormUrlEncoded)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "at-123") || !strings.Contains(rec.Body.String(), "id-123") {
		t.Fatalf("response missing expected tokens: %s", rec.Body.String())
	}
}

func TestTokenHandler_HandleTokenRequest_InvalidGrantType(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthUseCaseMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", Scheme: "https"}

	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	storage.GetApplicationByClientIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, clientID string) (*model.Application, *model.ApplicationProfile, *model.ApplicationGroup, error) {
		return &model.Application{ClientID: "cc-client"},
			&model.ApplicationProfile{TokenEndpointAuthMethod: model.AuthMethodNone},
			&model.ApplicationGroup{},
			nil
	})

	adapter := NewHttpAdapter(tuc, auth, fuc, nil, suc, upuc, uruc, portmock.NewLocalAuthUseCaseMock(ctrl), nil, nil, nil, storage, crypto, "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewBufferString("grant_type=invalid_grant&client_id=cc-client"))
	req.Header.Set(model.HeaderContentType, model.ContentTypeFormUrlEncoded)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestTokenHandler_HandleTokenRequest_AuthorizationCode_Success(t *testing.T) {
	ctrl := minimock.NewController(t)

	authMock := portmock.NewAuthUseCaseMock(ctrl)
	handler := NewTokenHandler(authMock, nil, nil)

	tenantID := uuid.New()
	clientID := "test-client-app"
	ctx := buildMockAuthenticatedContext(tenantID, clientID, true)

	authMock.ExchangeCodeForTokensMock.Set(func(ctx context.Context, cmd port.ExchangeCodeForTokensCommand) (*model.TokenSetResponse, error) {
		if cmd.Code != "valid-auth-code" || cmd.CodeVerifier != "valid-verifier" {
			t.Errorf("unexpected parameters passed to authorization code use-case")
		}
		return &model.TokenSetResponse{
			AccessToken:  "mock-access-token",
			IDToken:      "mock-id-token",
			RefreshToken: "mock-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}, nil
	})

	form := url.Values{}
	form.Set("grant_type", string(model.GrantTypeAuthorizationCode))
	form.Set("code", "valid-auth-code")
	form.Set("code_verifier", "valid-verifier")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.HandleTokenRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp model.TokenSetResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.AccessToken != "mock-access-token" {
		t.Errorf("expected access token match, got: %s", resp.AccessToken)
	}
}

func TestTokenHandler_HandleTokenRequest_RefreshToken_Success(t *testing.T) {
	ctrl := minimock.NewController(t)

	authMock := portmock.NewAuthUseCaseMock(ctrl)
	handler := NewTokenHandler(authMock, nil, nil)

	tenantID := uuid.New()
	clientID := "test-client-app"
	ctx := buildMockAuthenticatedContext(tenantID, clientID, true)

	authMock.RotateRefreshTokenMock.Set(func(ctx context.Context, cmd port.RotateRefreshTokenCommand) (*model.TokenSetResponse, error) {
		if cmd.RefreshToken != "active-refresh-token" {
			t.Errorf("unexpected refresh token parameter passed downstream")
		}
		return &model.TokenSetResponse{
			AccessToken:  "rotated-access-token",
			RefreshToken: "new-refresh-token-child",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}, nil
	})

	form := url.Values{}
	form.Set("grant_type", string(model.GrantTypeRefreshToken))
	form.Set("refresh_token", "active-refresh-token")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.HandleTokenRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp model.TokenSetResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.AccessToken != "rotated-access-token" {
		t.Errorf("expected token rotation pass, got: %s", resp.AccessToken)
	}
}

func TestTokenHandler_HandleTokenRequest_TokenExchange_Success(t *testing.T) {
	ctrl := minimock.NewController(t)

	authMock := portmock.NewAuthUseCaseMock(ctrl)
	handler := NewTokenHandler(authMock, nil, nil)

	tenantID := uuid.New()
	clientID := "test-client-app"
	ctx := buildMockAuthenticatedContext(tenantID, clientID, true)

	authMock.ExchangeExternalTokenMock.Set(func(ctx context.Context, tenantIDParam uuid.UUID, clID string, subToken string, subTokenType model.TokenType) (*model.TokenSetResponse, error) {
		if tenantIDParam != tenantID || clID != clientID || subToken != "external-jwt-assertion" || subTokenType != model.TokenTypeIDToken {
			t.Errorf("mismatched RFC 8693 dynamic exchange parameters passed to service loop")
		}
		return &model.TokenSetResponse{
			AccessToken: "native-federated-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   1800,
		}, nil
	})

	form := url.Values{}
	form.Set("grant_type", string(model.GrantTypeTokenExchange))
	form.Set("subject_token", "external-jwt-assertion")
	form.Set("subject_token_type", string(model.TokenTypeIDToken))

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.HandleTokenRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp model.TokenSetResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.AccessToken != "native-federated-access-token" {
		t.Errorf("expected successful external identity translation mapping, got: %s", resp.AccessToken)
	}
}

func TestTokenHandler_HandleTokenRequest_InvalidContentType(t *testing.T) {
	handler := NewTokenHandler(nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(`{"grant_type":"client_credentials"}`))
	req.Header.Set("Content-Type", "application/json") // VIOLATION: Mandatory urlencoded header missing
	rec := httptest.NewRecorder()

	handler.HandleTokenRequest(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected HTTP 400 Bad Request, got %d", rec.Code)
	}
}

func TestTokenHandler_HandleTokenRequest_ClientCredentials_Unauthenticated(t *testing.T) {
	handler := NewTokenHandler(nil, nil, nil)

	tenantID := uuid.New()
	clientID := "secure-confidential-app"
	ctx := buildMockAuthenticatedContext(tenantID, clientID, false) // VIOLATION: Client flag unauthenticated

	form := url.Values{}
	form.Set("grant_type", string(model.GrantTypeClientCredentials))

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.HandleTokenRequest(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected HTTP 401 Unauthorized for client credentials breach, got %d", rec.Code)
	}
}
