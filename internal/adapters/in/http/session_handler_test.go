package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sprezz-identity/internal/adapters/out/clock"
	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestHttpAdapter_UserInfo_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	crypto.VerifyTokenMock.Set(func(token string) (map[string]any, error) {
		if token != "token123" {
			t.Errorf("expected token 'token123', got %s", token)
		}
		return map[string]any{
			"sub":   "user-1",
			"scope": "openid email",
		}, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer token123")
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["sub"] != "user-1" || resp["scope"] != "openid email" {
		t.Fatalf("unexpected userinfo response: %v", resp)
	}
}

func TestHttpAdapter_UserInfo_Unauthorized(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	crypto.VerifyTokenMock.Set(func(token string) (map[string]any, error) {
		return nil, jwt.ErrSignatureInvalid
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer badtoken")
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestHttpAdapter_Revoke_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{
		ID:     tenantID,
		Domain: "test.com",
		Config: model.TenantConfig{
			RedirectWhitelist: []string{"https://test.com/callback"},
		},
	}
	secret := "clientsecret"
	client := &model.ClientApplication{
		ID:           uuid.NewString(),
		TenantID:     tenantID,
		ClientID:     "test-client",
		ClientSecret: &secret,
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})
	auth.RevokeTokenMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string, token string) error {
		if token != "token-to-revoke" {
			t.Errorf("expected token-to-revoke, got %s", token)
		}
		return nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", bytes.NewBufferString("client_id=test-client&client_secret=clientsecret&token=token-to-revoke"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}

func TestHttpAdapter_Introspect_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}
	secret := "clientsecret"
	client := &model.ClientApplication{
		ID:           uuid.NewString(),
		TenantID:     tenantID,
		ClientID:     "test-client",
		ClientSecret: &secret,
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})
	auth.IntrospectTokenMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string, token string) (*model.IntrospectionResponse, error) {
		return &model.IntrospectionResponse{
			Active:    true,
			ClientID:  clientID,
			Subject:   "user-1",
			Scope:     "openid",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		}, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", bytes.NewBufferString("client_id=test-client&client_secret=clientsecret&token=token-to-introspect"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["active"] != true || resp["sub"] != "user-1" {
		t.Fatalf("unexpected introspection response: %v", resp)
	}
}

func TestHttpAdapter_PAR_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{
		ID:     tenantID,
		Domain: "test.com",
		Config: model.TenantConfig{
			RedirectWhitelist: []string{"https://test.com/callback"},
		},
	}
	secret := "clientsecret"
	client := &model.ClientApplication{
		ID:            uuid.NewString(),
		TenantID:      tenantID,
		ClientID:      "test-client",
		ClientSecret:  &secret,
		AllowedScopes: []string{"openid"},
		DefaultScopes: []string{"openid"},
		RedirectURIs:  []string{"https://test.com/callback"},
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})
	auth.SavePARMock.Set(func(ctx context.Context, req model.PushedAuthorizationRequest) error {
		if req.ClientID != "test-client" || req.RedirectURI != "https://test.com/callback" {
			t.Errorf("unexpected PAR request saved: %v", req)
		}
		return nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodPost, "/oauth/par", bytes.NewBufferString("client_id=test-client&client_secret=clientsecret&redirect_uri=https://test.com/callback&scope=openid"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201 Created, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !strings.HasPrefix(resp["request_uri"].(string), "urn:ietf:params:oauth:request_uri:") {
		t.Fatalf("unexpected request_uri returned: %v", resp)
	}
}

func TestHttpAdapter_Logout_Redirect(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	auth.ProcessLogoutMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, subject string, clientID string) ([]string, error) {
		return nil, nil // no frontchannel URLs
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodGet, "/oauth/logout?post_logout_redirect_uri=https://test.com/logged-out", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 redirect, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/" { // redirect to "/" because client is not authenticated to verify post_logout_redirect_uri
		t.Fatalf("expected location '/', got %s", loc)
	}
}

func TestHttpAdapter_Logout_ValidPostLogoutRedirectURI(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{
		ID:     tenantID,
		Domain: "test.com",
		Config: model.TenantConfig{
			RedirectWhitelist: []string{"https://test.com/logged-out"},
		},
	}
	client := &model.ClientApplication{
		ID:                     uuid.NewString(),
		TenantID:               tenantID,
		ClientID:               "test-client",
		PostLogoutRedirectURIs: []string{"https://test.com/logged-out"},
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})
	auth.ProcessLogoutMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, subject string, clientID string) ([]string, error) {
		return nil, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	// Use valid SSO cookie that identifies test-client as sso.ProviderID
	req := httptest.NewRequest(http.MethodGet, "/oauth/logout?post_logout_redirect_uri=https://test.com/logged-out", nil)
	req.Host = "test.com"
	req.AddCookie(&http.Cookie{
		Name:  "spz_session",
		Value: "sub-123:test-client:session-id",
	})
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "https://test.com/logged-out" {
		t.Fatalf("expected location 'https://test.com/logged-out', got %s", loc)
	}
}

func TestHttpAdapter_Revoke_MissingToken(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}
	secret := "clientsecret"
	client := &model.ClientApplication{
		ID:           uuid.NewString(),
		TenantID:     tenantID,
		ClientID:     "test-client",
		ClientSecret: &secret,
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", bytes.NewBufferString("client_id=test-client&client_secret=clientsecret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestHttpAdapter_Introspect_MissingToken(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}
	secret := "clientsecret"
	client := &model.ClientApplication{
		ID:           uuid.NewString(),
		TenantID:     tenantID,
		ClientID:     "test-client",
		ClientSecret: &secret,
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", bytes.NewBufferString("client_id=test-client&client_secret=clientsecret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestHttpAdapter_PAR_MissingRedirectURI(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}
	secret := "clientsecret"
	client := &model.ClientApplication{
		ID:           uuid.NewString(),
		TenantID:     tenantID,
		ClientID:     "test-client",
		ClientSecret: &secret,
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodPost, "/oauth/par", bytes.NewBufferString("client_id=test-client&client_secret=clientsecret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}

func TestHttpAdapter_ClientAuthMiddleware_Failure_InvalidSecret(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}
	secret := "clientsecret"
	client := &model.ClientApplication{
		ID:           uuid.NewString(),
		TenantID:     tenantID,
		ClientID:     "test-client",
		ClientSecret: &secret,
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	// Call introspect with wrong secret
	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", bytes.NewBufferString("client_id=test-client&client_secret=wrongsecret&token=dummy"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 Unauthorized, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}

func TestHttpAdapter_ClientAuthMiddleware_Failure_MissingCredentials(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	// Call revoke with no client_id / secret
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", bytes.NewBufferString("token=dummy"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 Unauthorized, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}

func TestHttpAdapter_WebLogout_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	auth.ProcessLogoutMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, subject string, clientID string) ([]string, error) {
		if subject != "sub1" || clientID != "prov1" {
			t.Errorf("unexpected subject/clientID passed to ProcessLogout: %s/%s", subject, clientID)
		}
		return nil, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodGet, routeWebLogout, nil)
	req.Host = "test.com"
	req.AddCookie(&http.Cookie{
		Name:  "spz_session",
		Value: "sub1:prov1:session1",
	})
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if loc != "/" {
		t.Fatalf("expected redirect to '/', got %s", loc)
	}

	// Verify cookie has been cleared
	cookies := rec.Result().Cookies()
	cleared := false
	for _, cookie := range cookies {
		if cookie.Name == "spz_session" && cookie.MaxAge < 0 {
			cleared = true
			break
		}
	}
	if !cleared {
		t.Fatal("expected spz_session cookie to be cleared")
	}
}
