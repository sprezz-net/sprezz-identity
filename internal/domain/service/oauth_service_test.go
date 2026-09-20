package service

import (
	"context"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestOAuthService_ProcessDiscoveryMetadata_Success(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewOAuthService(storage, nil, nil, nil, clock, nil, nil)

	tenantUUID := uuid.New()
	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(&model.Tenant{
		ID:     tenantUUID,
		Name:   "My OAuth Tenant",
		Domain: "identity.my-tenant.com",
		Scheme: "https",
		Config: model.TenantConfig{
			PredefinedScopes: []string{"openid", "profile", "custom-scope"},
			ACRToLevels: map[string]model.Levels{
				"aal2": {AAL: 2},
				"aal1": {AAL: 1},
			},
		},
	}, nil)

	resp, err := svc.ProcessDiscoveryMetadata(context.Background(), tenantUUID, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Issuer != "https://identity.my-tenant.com" {
		t.Errorf("expected issuer 'https://identity.my-tenant.com', got '%s'", resp.Issuer)
	}

	if len(resp.ScopesSupported) != 3 || resp.ScopesSupported[2] != "custom-scope" {
		t.Errorf("unexpected scopes supported: %v", resp.ScopesSupported)
	}

	if len(resp.ACRValuesSupported) != 2 || resp.ACRValuesSupported[0] != "aal1" || resp.ACRValuesSupported[1] != "aal2" {
		t.Errorf("unexpected sorted ACR values: %v", resp.ACRValuesSupported)
	}
}

func TestOAuthService_ProcessDiscoveryMetadata_TenantNotFound(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewOAuthService(storage, nil, nil, nil, clock, nil, nil)

	tenantUUID := uuid.New()
	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(nil, port.ErrTenantNotFound)

	_, err := svc.ProcessDiscoveryMetadata(context.Background(), tenantUUID, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestOAuthService_ProcessAuthorizeRequest_StrictPartitionIsolation(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	ssoUseCase := portmock.NewSSOSessionUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)
	idpService := NewIdentityProviderService(storage, nil, clock)
	validator := NewOAuthValidatorService(idpService)

	svc := NewOAuthService(storage, nil, nil, nil, clock, ssoUseCase, validator)

	tenantUUID := uuid.New()
	clientID := "test-client"
	redirectURI := "https://myapp.com/callback"

	tenant := &model.Tenant{
		ID:     tenantUUID,
		Domain: "myapp.com",
		Scheme: "https",
		Config: model.TenantConfig{
			RedirectWhitelist: []string{"https://myapp.com/callback"},
		},
	}

	app := &model.Application{ID: uuid.New(), IsEnabled: true}
	profile := &model.ApplicationProfile{ID: uuid.New(), IsEnabled: true}
	group := &model.ApplicationGroup{
		ID:            uuid.New(),
		IsEnabled:     true,
		RedirectURIs:  []string{redirectURI},
		AllowedIDPIDs: []uuid.UUID{uuid.New()},
	}

	idps := []model.IdentityProvider{
		{
			ID:          group.AllowedIDPIDs[0],
			Enabled:     true,
			PartitionID: 14, // Target partition is 14
			Alias:       "google",
		},
	}

	// 1. Storage setup
	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(tenant, nil)
	storage.GetApplicationByClientIDMock.Expect(minimock.AnyContext, tenantUUID, clientID).Return(app, profile, group, nil)
	storage.GetIdentityProvidersByUUIDsMock.Expect(minimock.AnyContext, tenantUUID, group.AllowedIDPIDs).Return(idps, nil)

	// Since we pass ActiveSessionID = "user-uuid:13" (partition 13, mismatching 14),
	// the engine should invalidate it and proceed to Branch A (SaveInteractionSession and BuildSessionCookie).
	storage.SaveInteractionSessionMock.Set(func(ctx context.Context, session model.InteractionSession) error {
		if session.PartitionID != 14 {
			t.Errorf("expected interaction session to be bound to partition 14, got %d", session.PartitionID)
		}
		return nil
	})

	ssoUseCase.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		if cmd.PartitionID != 14 {
			t.Errorf("expected cookie intent to be bound to partition 14, got %d", cmd.PartitionID)
		}
		return &port.CookieIntentResponse{
			CookieName:  "spz_session_admin",
			CookieValue: "temp-value",
			MaxAge:      600,
			Secure:      true,
		}, nil
	})

	cmd := port.AuthorizeRequestCommand{
		TenantID:        tenantUUID,
		ClientID:        clientID,
		RedirectURI:     redirectURI,
		ActiveSessionID: "user-uuid:13", // Mismatching partition (13 vs 14)
	}

	res, err := svc.ProcessAuthorizeRequest(context.Background(), cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Action != port.ActionRedirectToLoginUI {
		t.Errorf("expected ActionRedirectToLoginUI, got %v", res.Action)
	}
}

func TestOAuthService_ProcessAuthorizeRequest_MatchingPartitionAllowed(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	ssoUseCase := portmock.NewSSOSessionUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)
	idpService := NewIdentityProviderService(storage, nil, clock)
	validator := NewOAuthValidatorService(idpService)

	svc := NewOAuthService(storage, nil, nil, nil, clock, ssoUseCase, validator)

	tenantUUID := uuid.New()
	clientID := "test-client"
	redirectURI := "https://myapp.com/callback"

	tenant := &model.Tenant{
		ID:     tenantUUID,
		Domain: "myapp.com",
		Scheme: "https",
		Config: model.TenantConfig{
			RedirectWhitelist: []string{"https://myapp.com/callback"},
		},
	}

	app := &model.Application{ID: uuid.New(), IsEnabled: true}
	profile := &model.ApplicationProfile{ID: uuid.New(), IsEnabled: true}
	group := &model.ApplicationGroup{
		ID:            uuid.New(),
		IsEnabled:     true,
		RedirectURIs:  []string{redirectURI},
		AllowedIDPIDs: []uuid.UUID{uuid.New()},
	}

	idps := []model.IdentityProvider{
		{
			ID:          group.AllowedIDPIDs[0],
			Enabled:     true,
			PartitionID: 14, // Target partition is 14
			Alias:       "google",
		},
	}

	// 1. Storage setup
	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(tenant, nil)
	storage.GetApplicationByClientIDMock.Expect(minimock.AnyContext, tenantUUID, clientID).Return(app, profile, group, nil)
	storage.GetIdentityProvidersByUUIDsMock.Expect(minimock.AnyContext, tenantUUID, group.AllowedIDPIDs).Return(idps, nil)

	// Since we pass ActiveSessionID = "user-uuid:14" (matching partition 14),
	// the engine should accept it and proceed to Branch B (SaveAuthSession and return authorization code).
	storage.SaveAuthSessionMock.Set(func(ctx context.Context, session model.AuthorizationCodeSession) error {
		if session.PartitionID != 14 {
			t.Errorf("expected authorization code session to be bound to partition 14, got %d", session.PartitionID)
		}
		if session.Subject != "user-uuid" {
			t.Errorf("expected subject to be user-uuid, got %s", session.Subject)
		}
		return nil
	})

	cmd := port.AuthorizeRequestCommand{
		TenantID:        tenantUUID,
		ClientID:        clientID,
		RedirectURI:     redirectURI,
		ActiveSessionID: "user-uuid:14", // Matching partition!
	}

	res, err := svc.ProcessAuthorizeRequest(context.Background(), cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Action != port.ActionEmitAuthorizationCode {
		t.Errorf("expected ActionEmitAuthorizationCode, got %v", res.Action)
	}
}

func TestOAuthService_ProcessAuthorizeRequest_PersistsRequestedScopes(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	ssoUseCase := portmock.NewSSOSessionUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)
	idpService := NewIdentityProviderService(storage, nil, clock)
	validator := NewOAuthValidatorService(idpService)

	svc := NewOAuthService(storage, nil, nil, nil, clock, ssoUseCase, validator)

	tenantUUID := uuid.New()
	clientID := "test-client"
	redirectURI := "https://myapp.com/callback"

	tenant := &model.Tenant{
		ID:     tenantUUID,
		Domain: "myapp.com",
		Scheme: "https",
		Config: model.TenantConfig{
			RedirectWhitelist: []string{"https://myapp.com/callback"},
			PredefinedScopes:  []string{"openid", "profile", "email"},
		},
	}

	app := &model.Application{ID: uuid.New(), IsEnabled: true}
	profile := &model.ApplicationProfile{ID: uuid.New(), IsEnabled: true}
	group := &model.ApplicationGroup{
		ID:            uuid.New(),
		IsEnabled:     true,
		RedirectURIs:  []string{redirectURI},
		AllowedScopes: []string{"openid", "profile", "email"},
		DefaultScopes: []string{"openid"},
		AllowedIDPIDs: []uuid.UUID{uuid.New()},
	}

	idps := []model.IdentityProvider{
		{
			ID:          group.AllowedIDPIDs[0],
			Enabled:     true,
			PartitionID: 14,
			Alias:       "google",
		},
	}

	// Storage mocks
	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(tenant, nil)
	storage.GetApplicationByClientIDMock.Expect(minimock.AnyContext, tenantUUID, clientID).Return(app, profile, group, nil)
	storage.GetIdentityProvidersByUUIDsMock.Expect(minimock.AnyContext, tenantUUID, group.AllowedIDPIDs).Return(idps, nil)

	// Assert that we correctly pass and save the custom requested scopes ["openid", "profile", "email"]
	storage.SaveAuthSessionMock.Set(func(ctx context.Context, session model.AuthorizationCodeSession) error {
		if len(session.Scopes) != 3 || session.Scopes[0] != "openid" || session.Scopes[1] != "profile" || session.Scopes[2] != "email" {
			t.Errorf("expected session to preserve requested scopes [openid profile email], got %v", session.Scopes)
		}
		return nil
	})

	cmd := port.AuthorizeRequestCommand{
		TenantID:        tenantUUID,
		ClientID:        clientID,
		RedirectURI:     redirectURI,
		ActiveSessionID: "user-uuid:14",
		Scopes:          []string{"openid", "profile", "email"}, // Requested custom scopes!
	}

	_, err := svc.ProcessAuthorizeRequest(context.Background(), cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOAuthService_ProcessLogoutRequest_UnwhitelistedRedirectFallback(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	ssoUseCase := portmock.NewSSOSessionUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	// Initialize standard internal dependency validation layer
	idpService := NewIdentityProviderService(storage, nil, clock)
	validator := NewOAuthValidatorService(idpService)

	svc := NewOAuthService(storage, nil, nil, nil, clock, ssoUseCase, validator)

	tenantUUID := uuid.New()
	tenant := &model.Tenant{
		ID:     tenantUUID,
		Domain: "my-tenant.com",
		Scheme: "https",
		Config: model.TenantConfig{
			RedirectWhitelist:  []string{"https://my-tenant.com/admin"},
			DefaultRedirectURI: "https://my-tenant.com/admin",
		},
	}

	// 1. SETUP EXPLICIT MOCK EXPECTATIONS
	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(tenant, nil)

	// Mock the destructive database session revocation step cleanly
	storage.RevokeSessionMock.Expect(minimock.AnyContext, tenantUUID, "user-uuid", "user-uuid:33").Return(nil)

	// Mock the front-channel application lookup loop to return zero bound clients
	storage.GetApplicationsLogoutContextBySessionMock.Expect(minimock.AnyContext, tenantUUID, "user-uuid:33").Return([]model.Application{}, nil)

	// Mock dynamic single sign-out cookie clearance parameters
	ssoUseCase.BuildSessionCookieMock.Expect(minimock.AnyContext, port.CookieIntentCommand{
		TenantID:       tenantUUID,
		PartitionID:    33,
		LifecycleStage: "clear",
		RequestHost:    "my-tenant.com",
	}).Return(&port.CookieIntentResponse{
		CookieName:  "spz_session_default",
		CookieValue: "",
		MaxAge:      -1,
	}, nil)

	// 2. Build malicious payload parameters context
	cmd := port.LogoutRequestCommand{
		TenantID:              tenantUUID,
		ActiveSessionID:       "user-uuid:33",
		PostLogoutRedirectURI: "https://malicious-attacker-site.com", // Dangerous unwhitelisted destination!
		RequestHost:           "my-tenant.com",
	}

	// 3. Execute execution across the driving service core
	res, err := svc.ProcessLogoutRequest(context.Background(), cmd)
	if err != nil {
		t.Fatalf("unexpected error during logout processing: %v", err)
	}

	// 4. VERIFY SECURITY BOUNDARIES:
	// The service must catch the unwhitelisted destination and fallback cleanly to the login wall path.
	expectedFallback := tenant.Config.DefaultRedirectURI
	if res.PostLogoutRedirectURI != expectedFallback {
		t.Errorf("SECURITY FAULT: expected fallback redirect destination path '%s', but system leaked to: '%s'", expectedFallback, res.PostLogoutRedirectURI)
	}
}

func TestOAuthService_ProcessLogoutRequest_JITFrontChannelValidation_DropsMaliciousURI(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	ssoUseCase := portmock.NewSSOSessionUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	idpService := NewIdentityProviderService(storage, nil, clock)
	validator := NewOAuthValidatorService(idpService)

	svc := NewOAuthService(storage, nil, nil, nil, clock, ssoUseCase, validator)

	tenantUUID := uuid.New()
	tenant := &model.Tenant{
		ID:     tenantUUID,
		Domain: "my-tenant.com",
		Scheme: "https",
		Config: model.TenantConfig{
			// The tenant whitelist ONLY permits internal domain callbacks
			RedirectWhitelist:  []string{"https://my-tenant.com"},
			DefaultRedirectURI: "https://my-tenant.com",
		},
	}

	// Mock an application session link where an attacker has injected a malicious iframe hook
	activeApps := []model.Application{
		{
			ID:                    uuid.New(),
			ClientID:              "compromised-client",
			IsEnabled:             true,
			FrontChannelLogoutURI: "https://malicious-attacker-site.com", // Dangerous unwhitelisted destination!
		},
	}

	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(tenant, nil)
	storage.RevokeSessionMock.Expect(minimock.AnyContext, tenantUUID, "user-uuid", "user-uuid:33").Return(nil)
	storage.GetApplicationsLogoutContextBySessionMock.Expect(minimock.AnyContext, tenantUUID, "user-uuid:33").Return(activeApps, nil)

	ssoUseCase.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: "spz_session_default", MaxAge: -1}, nil
	})

	cmd := port.LogoutRequestCommand{
		TenantID:              tenantUUID,
		ActiveSessionID:       "user-uuid:33",
		PostLogoutRedirectURI: "https://my-tenant.com",
		RequestHost:           "my-tenant.com",
	}

	res, err := svc.ProcessLogoutRequest(context.Background(), cmd)
	if err != nil {
		t.Fatalf("unexpected logout processing failure: %v", err)
	}

	// VERIFY FRONT-CHANNEL SECURITY BOUNDARY:
	// The malicious unwhitelisted URI must be caught and completely stripped from the front-channel output slice.
	if len(res.FrontChannelLogoutURIs) != 0 {
		t.Errorf("SECURITY FAULT: Expected 0 front-channel iframe URIs due to JIT whitelist validation failure, but system leaked: %v", res.FrontChannelLogoutURIs)
	}
}

func TestOAuthService_ProcessLogoutRequest_JITBackChannelValidation_DropsMaliciousURI(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl) // Track cryptographic signing assertions
	ssoUseCase := portmock.NewSSOSessionUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	idpService := NewIdentityProviderService(storage, nil, clock)
	validator := NewOAuthValidatorService(idpService)

	svc := NewOAuthService(storage, crypto, nil, nil, clock, ssoUseCase, validator)

	tenantUUID := uuid.New()
	tenant := &model.Tenant{
		ID:     tenantUUID,
		Domain: "my-tenant.com",
		Scheme: "https",
		Config: model.TenantConfig{
			RedirectWhitelist:  []string{"https://my-tenant.com"},
			DefaultRedirectURI: "https://my-tenant.com",
		},
	}

	// Mock an application link carrying a malicious backchannel destination hook
	activeApps := []model.Application{
		{
			ID:                   uuid.New(),
			ClientID:             "compromised-client",
			IsEnabled:            true,
			BackChannelLogoutURI: "https://malicious-attacker-site.com", // Dangerous unwhitelisted destination!
			SigningAlgorithm:     model.AlgRS256,
		},
	}

	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(tenant, nil)
	storage.RevokeSessionMock.Expect(minimock.AnyContext, tenantUUID, "user-uuid", "user-uuid:33").Return(nil)
	storage.GetApplicationsLogoutContextBySessionMock.Expect(minimock.AnyContext, tenantUUID, "user-uuid:33").Return(activeApps, nil)

	ssoUseCase.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: "spz_session_default", MaxAge: -1}, nil
	})

	// CRITICAL MINIMOCK ASSERTION GATE:
	// Because validation happens early inside ProcessLogoutRequest, the engine must drop the operation
	// before calling the signer. Thus, SignLogoutToken must NEVER be invoked for an untrusted URI.
	// Minimock assertion explicitly enforcing that SignLogoutToken
	// must NEVER be invoked for an untrusted, unwhitelisted destination.
	crypto.SignLogoutTokenMock.Set(func(ctx context.Context, claims model.LogoutTokenClaims, alg model.SignatureAlgorithm) (string, error) {
		t.Fatalf("SECURITY FAULT: System attempted to cryptographically sign an OIDC logout token for an un-whitelisted endpoint!")
		return "", nil
	})
	crypto.SignLogoutTokenMock.Optional()

	cmd := port.LogoutRequestCommand{
		TenantID:              tenantUUID,
		ActiveSessionID:       "user-uuid:33",
		PostLogoutRedirectURI: "https://my-tenant.com",
		RequestHost:           "my-tenant.com",
	}

	_, err := svc.ProcessLogoutRequest(context.Background(), cmd)
	if err != nil {
		t.Fatalf("unexpected logout processing failure: %v", err)
	}
}
