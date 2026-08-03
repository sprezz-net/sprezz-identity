package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sprezz-identity/internal/adapters/out/clock"
	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestHttpAdapter_Authorize_PreservesParams(t *testing.T) {
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
	client := &model.ClientApplication{
		ID:           uuid.NewString(),
		TenantID:     tenantID,
		ClientID:     "test-client",
		RedirectURIs: []string{"https://test.com/callback"},
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})

	storage.SaveInteractionSessionMock.Set(func(ctx context.Context, session model.InteractionSession) error {
		if session.State != "state-123" {
			t.Errorf("expected State 'state-123', got %s", session.State)
		}
		if session.Nonce != "nonce-456" {
			t.Errorf("expected Nonce 'nonce-456', got %s", session.Nonce)
		}
		if session.ACRValues != "acr-silver" {
			t.Errorf("expected ACRValues 'acr-silver', got %s", session.ACRValues)
		}
		return nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=test-client&redirect_uri=https://test.com/callback&state=state-123&nonce=nonce-456&acr_values=acr-silver", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", rec.Code)
	}
}

func TestHttpAdapter_Authorize_InvalidClient(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return nil, http.ErrNoCookie // simulate client not found
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=unknown-client&redirect_uri=https://test.com/callback", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestHttpAdapter_Authorize_DisallowedRedirectURI(t *testing.T) {
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
	client := &model.ClientApplication{
		ID:           uuid.NewString(),
		TenantID:     tenantID,
		ClientID:     "test-client",
		RedirectURIs: []string{"https://test.com/callback"},
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=test-client&redirect_uri=https://malicious.com/callback", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestHttpAdapter_Authorize_AuthenticatedSSO(t *testing.T) {
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
	client := &model.ClientApplication{
		ID:            uuid.NewString(),
		TenantID:      tenantID,
		ClientID:      "test-client",
		RedirectURIs:  []string{"https://test.com/callback"},
		DefaultScopes: []string{"openid"},
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
		return client, nil
	})
	auth.InitiateAuthorizeMock.Set(func(ctx context.Context, session model.AuthorizationCodeSession) error {
		if session.ClientID != "test-client" {
			t.Errorf("expected client_id 'test-client', got %s", session.ClientID)
		}
		return nil
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=test-client&redirect_uri=https://test.com/callback&state=state123", nil)
	req.Host = "test.com"
	// Set valid SSO cookie
	req.AddCookie(&http.Cookie{
		Name:  "spz_session",
		Value: "sub-123:provider-id:session-id",
	})
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "code=") || !strings.Contains(loc, "state=state123") {
		t.Fatalf("unexpected redirect URI: %s", loc)
	}
}

func TestHttpAdapter_Login_Failure(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetEnabledIdentityProvidersMock.Set(func(ctx context.Context, gotTenantID uuid.UUID) ([]model.IdentityProvider, error) {
		return nil, context.DeadlineExceeded
	})

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock())

	req := httptest.NewRequest(http.MethodPost, routeWebLogin, strings.NewReader("username=admin&password=wrongpassword"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}

func TestHttpAdapter_Login_Malformed(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodPost, routeWebLogin, nil) // no payload, but post
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}
