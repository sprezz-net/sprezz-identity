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
	validator := NewOAuthValidatorService()

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
	validator := NewOAuthValidatorService()

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
	validator := NewOAuthValidatorService()

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
