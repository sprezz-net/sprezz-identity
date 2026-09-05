package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func buildTestAdapter(ctrl *minimock.Controller) (*HttpAdapter, *model.Tenant) {
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{
		ID:       tenantID,
		Name:     "test-tenant",
		Domain:   "test.com",
		Scheme:   "https",
		IsActive: true,
		Config: model.TenantConfig{
			PredefinedScopes: []string{"openid", "custom-scope"},
			ACRToLevels: map[string]model.Levels{
				"acr:b": {},
				"acr:a": {},
			},
		},
	}

	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)
	lauc := portmock.NewLocalAuthUseCaseMock(ctrl)

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	auth.ProcessDiscoveryMetadataMock.Set(func(ctx context.Context, tenantID uuid.UUID, isOIDC bool) (*port.DiscoveryResponse, error) {
		resp := &port.DiscoveryResponse{
			Issuer:                "https://test.com",
			ScopesSupported:       []string{"openid", "custom-scope"},
			ACRValuesSupported:    []string{"acr:a", "acr:b"},
			AuthorizationEndpoint: "https://test.com/oauth/authorize",
			TokenEndpoint:         "https://test.com/oauth/token",
			JWKSURI:               "https://test.com/.well-known/jwks.json",
		}
		if isOIDC {
			resp.EndSessionEndpoint = "https://test.com/oauth/logout"
			resp.FrontChannelLogoutSupported = true
			resp.FrontChannelLogoutSessionSupported = true
		}
		return resp, nil
	})

	return NewHttpAdapter(tuc, auth, fuc, suc, upuc, uruc, lauc, storage, crypto, "unittest", "admin-domain.com"), tenant
}

func TestHttpAdapter_CSPNonce(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)

	tenant := &model.Tenant{
		ID:     uuid.New(),
		Domain: "example.com",
		Config: model.TenantConfig{
			AllowSignup: false,
		},
	}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	suc.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: "spz_session"}, nil
	})

	lauc := portmock.NewLocalAuthUseCaseMock(ctrl)
	lauc.GetLoginContextMock.Set(func(ctx context.Context, cmd port.GetLoginContextCommand) (*port.LoginContextResponse, error) {
		return &port.LoginContextResponse{
			AllowSignup:              false,
			Providers:                []model.IdentityProvider{},
			ShowUsernamePasswordForm: false,
			PartitionID:              0,
		}, nil
	})

	adapter := NewHttpAdapter(tuc, auth, fuc, suc, upuc, uruc, lauc, storage, crypto, "unittest", "admin-domain.com")

	// Request 1
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	rec1 := httptest.NewRecorder()
	adapter.Router().ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec1.Code)
	}

	csp1 := rec1.Header().Get("Content-Security-Policy")
	if csp1 == "" {
		t.Fatal("expected Content-Security-Policy header, got empty")
	}

	re := regexp.MustCompile(`'nonce-([^']+)'`)
	match1 := re.FindStringSubmatch(csp1)
	if len(match1) < 2 {
		t.Fatalf("could not find nonce in CSP header: %s", csp1)
	}
	nonce1 := match1[1]

	body1 := rec1.Body.String()
	expectedScriptTag1 := `nonce="` + nonce1 + `"`
	if !strings.Contains(body1, expectedScriptTag1) {
		t.Fatalf("expected body to contain %q, but got:\n%s", expectedScriptTag1, body1)
	}
}

func TestHttpAdapter_Tenant_Middleware_Failure(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return nil, errors.New("unbootstrapped tenant")
	})

	adapter := NewHttpAdapter(tuc, auth, fuc, suc, upuc, uruc, portmock.NewLocalAuthUseCaseMock(ctrl), storage, crypto, "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = "unknown.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}

type registerRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	FrontChannelLogoutURI   string   `json:"frontchannel_logout_uri"`
	BackChannelLogoutURI    string   `json:"backchannel_logout_uri"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	AllowedScopes           []string `json:"allowed_scopes"`
	DefaultScopes           []string `json:"default_scopes"`
	AllowedAudiences        []string `json:"allowed_audiences"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	SoftwareStatement       string   `json:"software_statement,omitempty"`
}

type handlerMockStorage struct {
	*portmock.StorageMock
	deks   map[uuid.UUID][]byte
	nonces map[uuid.UUID][]byte
	keys   map[uuid.UUID][]model.SigningKey
}

func (m *handlerMockStorage) GetTenantDEK(ctx context.Context, tenantUUID uuid.UUID) ([]byte, []byte, error) {
	return m.deks[tenantUUID], m.nonces[tenantUUID], nil
}

func (m *handlerMockStorage) InsertTenantDEK(ctx context.Context, tenantUUID uuid.UUID, key, nonce []byte) error {
	m.deks[tenantUUID] = key
	m.nonces[tenantUUID] = nonce
	return nil
}

func (m *handlerMockStorage) GetActiveSigningKeys(ctx context.Context, tenantUUID uuid.UUID) ([]model.SigningKey, error) {
	return m.keys[tenantUUID], nil
}

func (m *handlerMockStorage) GetActiveVerificationKeys(ctx context.Context, tenantUUID uuid.UUID) ([]model.SigningKey, error) {
	return m.keys[tenantUUID], nil
}

func (m *handlerMockStorage) InsertSigningKey(ctx context.Context, tenantUUID uuid.UUID, key model.SigningKey, encryptedPrivateKey, nonce []byte) (string, error) {
	if key.Kid == "" {
		key.Kid = uuid.New().String()
	}
	key.RawEncryptedPrivateKey = encryptedPrivateKey
	key.CryptoNonce = nonce
	m.keys[tenantUUID] = append(m.keys[tenantUUID], key)
	return key.Kid, nil
}

func (m *handlerMockStorage) RotateSigningKeys(ctx context.Context, tenantUUID uuid.UUID) error {
	m.keys[tenantUUID] = nil
	return nil
}
