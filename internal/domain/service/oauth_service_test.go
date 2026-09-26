package service

import (
	"context"
	"errors"
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
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	ssoUseCase := portmock.NewSSOSessionUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)
	idpService := NewIdentityProviderService(storage, adminStorage, crypto, clock)
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
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	ssoUseCase := portmock.NewSSOSessionUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)
	idpService := NewIdentityProviderService(storage, adminStorage, crypto, clock)
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
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	ssoUseCase := portmock.NewSSOSessionUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)
	idpService := NewIdentityProviderService(storage, adminStorage, crypto, clock)
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
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	ssoUseCase := portmock.NewSSOSessionUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	// Initialize standard internal dependency validation layer
	idpService := NewIdentityProviderService(storage, adminStorage, crypto, clock)
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
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	ssoUseCase := portmock.NewSSOSessionUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	idpService := NewIdentityProviderService(storage, adminStorage, crypto, clock)
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
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	ssoUseCase := portmock.NewSSOSessionUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	idpService := NewIdentityProviderService(storage, adminStorage, crypto, clock)
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
func TestOAuthService_ProcessJWKSetRetrieval(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		crypto := portmock.NewCryptoMock(ctrl)
		svc := NewOAuthService(storage, nil, nil, nil, nil, nil, nil)
		svc.crypto = crypto

		tenantUUID := uuid.New()
		storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(&model.Tenant{ID: tenantUUID}, nil)

		expectedJWKS := []map[string]any{
			{"kty": "RSA", "kid": "key-1"},
		}
		crypto.JWKSForTenantMock.Expect(minimock.AnyContext, "example.com", "https").Return(expectedJWKS, nil)

		res, err := svc.ProcessJWKSetRetrieval(context.Background(), tenantUUID, "example.com", "https")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		keys, ok := res["keys"].([]map[string]any)
		if !ok || len(keys) != 1 || keys[0]["kid"] != "key-1" {
			t.Fatalf("unexpected jwks result: %v", res)
		}
	})

	t.Run("TenantNotFound", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		svc := NewOAuthService(storage, nil, nil, nil, nil, nil, nil)

		tenantUUID := uuid.New()
		storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(nil, port.ErrTenantNotFound)

		_, err := svc.ProcessJWKSetRetrieval(context.Background(), tenantUUID, "example.com", "https")
		if err == nil {
			t.Fatal("expected error for non-existent tenant")
		}
	})
}

func TestOAuthService_TokenRevocation(t *testing.T) {
	t.Run("ProcessTokenRevocation_MissingToken", func(t *testing.T) {
		svc := NewOAuthService(nil, nil, nil, nil, nil, nil, nil)
		err := svc.ProcessTokenRevocation(context.Background(), port.RevokeTokenCommand{
			TenantID:    uuid.New(),
			ClientID:    "client-1",
			TokenString: "",
		})
		if err == nil {
			t.Fatal("expected error on empty token")
		}
	})

	t.Run("ProcessTokenRevocation_UnparseableToken_RFC7009Compliance", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		crypto := portmock.NewCryptoMock(ctrl)
		svc := NewOAuthService(nil, nil, nil, nil, nil, nil, nil)
		svc.crypto = crypto

		crypto.ExtractUnverifiedRevocationMetadataMock.Expect("corrupted-token").Return("", "", errors.New("unparseable"))

		err := svc.ProcessTokenRevocation(context.Background(), port.RevokeTokenCommand{
			TenantID:    uuid.New(),
			ClientID:    "client-1",
			TokenString: "corrupted-token",
		})
		if err != nil {
			t.Fatalf("expected nil per RFC 7009 on unparseable token, got %v", err)
		}
	})

	t.Run("ProcessTokenRevocation_ClientMismatch", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		crypto := portmock.NewCryptoMock(ctrl)
		svc := NewOAuthService(nil, nil, nil, nil, nil, nil, nil)
		svc.crypto = crypto

		crypto.ExtractUnverifiedRevocationMetadataMock.Expect("valid-token").Return("token-jti", "other-client", nil)

		err := svc.ProcessTokenRevocation(context.Background(), port.RevokeTokenCommand{
			TenantID:    uuid.New(),
			ClientID:    "client-1",
			TokenString: "valid-token",
		})
		if err == nil {
			t.Fatal("expected error on client mismatch")
		}
	})

	t.Run("ProcessTokenRevocation_Success", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		crypto := portmock.NewCryptoMock(ctrl)
		now := time.Now().Truncate(time.Second)
		clock := portmock.NewMockClock(now)
		svc := NewOAuthService(storage, nil, nil, nil, clock, nil, nil)
		svc.crypto = crypto

		crypto.ExtractUnverifiedRevocationMetadataMock.Expect("valid-token").Return("token-jti", "client-1", nil)
		storage.RevokeTokenMock.Expect(minimock.AnyContext, "token-jti", now.Add(24*time.Hour)).Return(nil)

		err := svc.ProcessTokenRevocation(context.Background(), port.RevokeTokenCommand{
			TenantID:    uuid.New(),
			ClientID:    "client-1",
			TokenString: "valid-token",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("RevokeTokenDirect", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		crypto := portmock.NewCryptoMock(ctrl)
		now := time.Now().Truncate(time.Second)
		clock := portmock.NewMockClock(now)
		svc := NewOAuthService(storage, nil, nil, nil, clock, nil, nil)
		svc.crypto = crypto

		tenantUUID := uuid.New()
		crypto.ExtractUnverifiedRevocationMetadataMock.Expect("my-token").Return("jti-123", "any-client", nil)
		storage.RevokeTokenMock.Expect(minimock.AnyContext, "jti-123", now.Add(24*time.Hour)).Return(nil)

		err := svc.RevokeToken(context.Background(), tenantUUID, "any-client", "my-token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestOAuthService_TokenIntrospection(t *testing.T) {
	tenantID := uuid.New()

	t.Run("UnauthenticatedClient", func(t *testing.T) {
		svc := NewOAuthService(nil, nil, nil, nil, nil, nil, nil)
		_, err := svc.ProcessTokenIntrospection(context.Background(), port.IntrospectTokenCommand{
			TenantID:              tenantID,
			IsClientAuthenticated: false,
			TargetTokenString:     "some-token",
		})
		if err == nil {
			t.Fatal("expected error when client is unauthenticated")
		}
	})

	t.Run("EmptyToken", func(t *testing.T) {
		svc := NewOAuthService(nil, nil, nil, nil, nil, nil, nil)
		_, err := svc.ProcessTokenIntrospection(context.Background(), port.IntrospectTokenCommand{
			TenantID:              tenantID,
			IsClientAuthenticated: true,
			TargetTokenString:     "",
		})
		if err == nil {
			t.Fatal("expected error on empty token")
		}
	})

	t.Run("InvalidSignature_ActiveFalse", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		crypto := portmock.NewCryptoMock(ctrl)
		svc := NewOAuthService(nil, nil, nil, nil, nil, nil, nil)
		svc.crypto = crypto

		crypto.VerifyTokenMock.Expect("invalid-token").Return(nil, errors.New("bad sig"))

		resp, err := svc.ProcessTokenIntrospection(context.Background(), port.IntrospectTokenCommand{
			TenantID:              tenantID,
			IsClientAuthenticated: true,
			TargetTokenString:     "invalid-token",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Active {
			t.Error("expected active=false for invalid token")
		}
	})

	t.Run("CrossTenantAttempt_ActiveFalse", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		crypto := portmock.NewCryptoMock(ctrl)
		svc := NewOAuthService(nil, nil, nil, nil, nil, nil, nil)
		svc.crypto = crypto

		otherTenantID := uuid.New()
		crypto.VerifyTokenMock.Expect("cross-tenant-token").Return(map[string]any{
			"tid": otherTenantID.String(),
		}, nil)

		resp, err := svc.ProcessTokenIntrospection(context.Background(), port.IntrospectTokenCommand{
			TenantID:              tenantID,
			IsClientAuthenticated: true,
			TargetTokenString:     "cross-tenant-token",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Active {
			t.Error("expected active=false for cross-tenant token")
		}
	})

	t.Run("RevokedToken_ActiveFalse", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		crypto := portmock.NewCryptoMock(ctrl)
		svc := NewOAuthService(storage, nil, nil, nil, nil, nil, nil)
		svc.crypto = crypto

		crypto.VerifyTokenMock.Expect("revoked-token").Return(map[string]any{
			"tid": tenantID.String(),
			"jti": "revoked-jti",
		}, nil)
		storage.IsTokenRevokedMock.Expect(minimock.AnyContext, "revoked-jti").Return(true, nil)

		resp, err := svc.ProcessTokenIntrospection(context.Background(), port.IntrospectTokenCommand{
			TenantID:              tenantID,
			IsClientAuthenticated: true,
			TargetTokenString:     "revoked-token",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Active {
			t.Error("expected active=false for revoked token")
		}
	})

	t.Run("ValidBearerToken_Success", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		crypto := portmock.NewCryptoMock(ctrl)
		svc := NewOAuthService(storage, nil, nil, nil, nil, nil, nil)
		svc.crypto = crypto

		crypto.VerifyTokenMock.Expect("valid-bearer-token").Return(map[string]any{
			"tid":       tenantID.String(),
			"jti":       "valid-jti",
			"sub":       "user-123",
			"client_id": "client-abc",
			"scope":     "openid profile",
			"iss":       "https://tenant.example.com",
			"pid":       "default",
			"exp":       int64(1700000000),
			"iat":       int64(1699999000),
		}, nil)
		storage.IsTokenRevokedMock.Expect(minimock.AnyContext, "valid-jti").Return(false, nil)

		resp, err := svc.IntrospectToken(context.Background(), tenantID, "client-abc", "valid-bearer-token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Active {
			t.Error("expected active=true")
		}
		if resp.TokenType != "Bearer" {
			t.Errorf("expected TokenType Bearer, got %s", resp.TokenType)
		}
		if resp.Subject != "user-123" || resp.ClientID != "client-abc" {
			t.Errorf("unexpected subject or client: %v", resp)
		}
	})

	t.Run("ValidDPoPToken_Success", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		crypto := portmock.NewCryptoMock(ctrl)
		svc := NewOAuthService(storage, nil, nil, nil, nil, nil, nil)
		svc.crypto = crypto

		crypto.VerifyTokenMock.Expect("valid-dpop-token").Return(map[string]any{
			"tid": tenantID.String(),
			"jti": "dpop-jti",
			"sub": "user-dpop",
			"azp": "client-dpop",
			"cnf": map[string]any{
				"jkt": "thumbprint-xyz",
			},
		}, nil)
		storage.IsTokenRevokedMock.Expect(minimock.AnyContext, "dpop-jti").Return(false, nil)

		resp, err := svc.IntrospectToken(context.Background(), tenantID, "client-dpop", "valid-dpop-token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Active {
			t.Error("expected active=true")
		}
		if resp.TokenType != "DPoP" {
			t.Errorf("expected TokenType DPoP, got %s", resp.TokenType)
		}
		if resp.Confirmation == nil || resp.Confirmation.JKT != "thumbprint-xyz" {
			t.Errorf("unexpected confirmation: %v", resp.Confirmation)
		}
	})
}

func TestOAuthService_RotateRefreshToken(t *testing.T) {
	tenantID := uuid.New()
	clientID := "client-test"
	now := time.Now().Truncate(time.Second)

	t.Run("InvalidRefreshTokenSignature", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		crypto := portmock.NewCryptoMock(ctrl)
		svc := NewOAuthService(nil, nil, nil, nil, nil, nil, nil)
		svc.crypto = crypto

		crypto.VerifyTokenMock.Expect("invalid-rt").Return(nil, errors.New("bad sig"))

		_, err := svc.RotateRefreshToken(context.Background(), port.RotateRefreshTokenCommand{
			TenantID:     tenantID,
			ClientID:     clientID,
			RefreshToken: "invalid-rt",
		})
		if !errors.Is(err, port.ErrInvalidGrant) {
			t.Fatalf("expected ErrInvalidGrant, got %v", err)
		}
	})

	t.Run("MissingJTIOFid", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		crypto := portmock.NewCryptoMock(ctrl)
		svc := NewOAuthService(nil, nil, nil, nil, nil, nil, nil)
		svc.crypto = crypto

		crypto.VerifyTokenMock.Expect("missing-fields-rt").Return(map[string]any{
			"sub": "user-1",
		}, nil)

		_, err := svc.RotateRefreshToken(context.Background(), port.RotateRefreshTokenCommand{
			TenantID:     tenantID,
			ClientID:     clientID,
			RefreshToken: "missing-fields-rt",
		})
		if !errors.Is(err, port.ErrInvalidGrant) {
			t.Fatalf("expected ErrInvalidGrant, got %v", err)
		}
	})

	t.Run("ReuseDetection_FamilyRevocation", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		crypto := portmock.NewCryptoMock(ctrl)
		clock := portmock.NewMockClock(now)
		svc := NewOAuthService(storage, nil, nil, nil, clock, nil, nil)
		svc.crypto = crypto

		crypto.VerifyTokenMock.Expect("used-rt").Return(map[string]any{
			"jti": "rt-jti",
			"fid": "family-123",
			"sid": "session-456",
			"sub": "user-789",
		}, nil)

		storage.GetRefreshTokenMock.Expect(minimock.AnyContext, "used-rt").Return(&model.RefreshToken{
			TokenID:       "rt-jti",
			TokenFamilyID: "family-123",
			TenantID:      tenantID,
			ClientID:      clientID,
			SessionID:     "session-456",
			Subject:       "user-789",
			IsUsed:        true, // Already used token!
			ExpiresAt:     now.Add(time.Hour),
		}, nil)

		storage.RevokeRefreshTokenFamilyMock.Expect(minimock.AnyContext, "family-123").Return(nil)
		storage.RevokeSessionMock.Expect(minimock.AnyContext, tenantID, "user-789", clientID).Return(nil)

		_, err := svc.RotateRefreshToken(context.Background(), port.RotateRefreshTokenCommand{
			TenantID:     tenantID,
			ClientID:     clientID,
			RefreshToken: "used-rt",
		})
		if err == nil {
			t.Fatal("expected error on token reuse")
		}
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		crypto := portmock.NewCryptoMock(ctrl)
		clock := portmock.NewMockClock(now)
		svc := NewOAuthService(storage, nil, nil, nil, clock, nil, nil)
		svc.crypto = crypto

		crypto.VerifyTokenMock.Expect("valid-rt").Return(map[string]any{
			"jti": "rt-jti",
			"fid": "family-123",
			"sid": "session-456",
			"sub": "user-789",
			"pid": "default",
		}, nil)

		storage.GetRefreshTokenMock.Expect(minimock.AnyContext, "valid-rt").Return(&model.RefreshToken{
			TokenID:       "rt-jti",
			TokenFamilyID: "family-123",
			TenantID:      tenantID,
			ClientID:      clientID,
			SessionID:     "session-456",
			Subject:       "user-789",
			IsUsed:        false,
			ExpiresAt:     now.Add(time.Hour),
			Scopes:        []string{"read"},
		}, nil)

		storage.MarkRefreshTokenUsedMock.Expect(minimock.AnyContext, "valid-rt").Return(nil)

		app := &model.Application{
			ClientID:  clientID,
			IsEnabled: true,
		}
		profile := &model.ApplicationProfile{
			IsEnabled:            true,
			AccessTokenLifetime:  time.Minute * 15,
			RefreshTokenLifetime: time.Hour * 24,
			SigningAlgorithm:     model.AlgRS256,
		}
		group := &model.ApplicationGroup{
			IsEnabled: true,
		}

		storage.GetApplicationByClientIDMock.Expect(minimock.AnyContext, tenantID, clientID).Return(app, profile, group, nil)
		storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantID).Return(&model.Tenant{
			ID:     tenantID,
			Domain: "example.com",
			Scheme: "https",
		}, nil)

		crypto.SignAccessTokenMock.Set(func(ctx context.Context, claims model.TokenClaims, alg model.SignatureAlgorithm) (string, error) {
			if claims.Subject != "user-789" {
				t.Errorf("expected subject user-789, got %s", claims.Subject)
			}
			return "signed-access-token", nil
		})

		storage.SaveRefreshTokenMock.Set(func(ctx context.Context, token model.RefreshToken) error {
			if token.TokenFamilyID != "family-123" {
				t.Errorf("expected inherited family ID family-123, got %s", token.TokenFamilyID)
			}
			return nil
		})

		res, err := svc.RotateRefreshToken(context.Background(), port.RotateRefreshTokenCommand{
			TenantID:     tenantID,
			ClientID:     clientID,
			RefreshToken: "valid-rt",
		})
		if err != nil {
			t.Fatalf("unexpected error rotating refresh token: %v", err)
		}
		if res.AccessToken != "signed-access-token" {
			t.Errorf("expected signed access token, got %s", res.AccessToken)
		}
		if res.RefreshToken == "" {
			t.Error("expected non-empty rotated refresh token")
		}
	})
}
