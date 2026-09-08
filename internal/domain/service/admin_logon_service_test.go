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

func TestAdminLogonService_InitiateAdminLogon_Success(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	fedLogin := portmock.NewFederatedLoginUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewAdminLogonService(storage, nil, nil, nil, nil, fedLogin, clock, "local", "admin.com")

	tenantUUID := uuid.New()
	providerUUID := uuid.New()

	storage.GetIdentityProvidersMock.Expect(minimock.AnyContext, tenantUUID).Return([]model.IdentityProvider{
		{
			ID:      providerUUID,
			IDPType: model.OpenIDConnectIDPType,
			Alias:   "admin-sso",
			Enabled: true,
			Config: model.IdentityProviderConfig{
				ClientID:              "admin_ui",
				AuthorizationEndpoint: "https://auth",
				TokenEndpoint:         "https://token",
			},
		},
	}, nil)

	fedLogin.InitiateFederatedLoginMock.Expect(minimock.AnyContext, port.InitiateFederatedLoginCommand{
		TenantID:           tenantUUID,
		IdentityProviderID: providerUUID,
		ClientID:           "admin_ui",
		RequestedScopes:    []string{"openid", "profile", "email"},
		LocalCallbackURI:   "https://callback",
		FinalTargetURI:     "https://final",
	}).Return(&port.InitiateFederatedLoginResponse{
		TargetRedirectURL: "https://redirect-url",
	}, nil)

	resp, err := svc.InitiateAdminLogon(context.Background(), tenantUUID, "https://callback", "https://final")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.TargetRedirectURL != "https://redirect-url" {
		t.Errorf("expected redirect URL 'https://redirect-url', got '%s'", resp.TargetRedirectURL)
	}
}

func TestAdminLogonService_InitiateAdminLogon_OnDemandDCR_Success(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	fedClient := portmock.NewFederationClientMock(ctrl)
	fedLogin := portmock.NewFederatedLoginUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewAdminLogonService(storage, adminStorage, auth, crypto, fedClient, fedLogin, clock, "local", "admin.com")

	tenantUUID := uuid.New()
	adminTenantUUID := uuid.New()
	providerUUID := uuid.New()

	storage.GetIdentityProvidersMock.Expect(minimock.AnyContext, tenantUUID).Return([]model.IdentityProvider{
		{
			ID:      providerUUID,
			IDPType: model.OpenIDConnectIDPType,
			Alias:   "admin-sso",
			Enabled: true,
			Config: model.IdentityProviderConfig{
				DiscoveryEndpoint: "https://admin.com/.well-known/openid-configuration",
				ClientID:          "", // Triggers DCR!
			},
		},
	}, nil)

	storage.ResolveTenantByDomainMock.Expect(minimock.AnyContext, "admin.com").Return(&model.Tenant{
		ID:     adminTenantUUID,
		Domain: "admin.com",
	}, nil)

	crypto.SignSoftwareStatementMock.Set(func(ctx context.Context, issuer string, audience string, claims model.SoftwareStatementClaims, issuedAt time.Time, expiresAt time.Time) (string, error) {
		expectedSoftwareID := model.AdminUIProfileName + ";" + model.LocalAdminUIGroupName
		if claims.SoftwareID != expectedSoftwareID {
			t.Errorf("expected software ID '%s', got '%s'", expectedSoftwareID, claims.SoftwareID)
		}
		return "signed-statement-jwt", nil
	})

	auth.RegisterDynamicApplicationMock.Set(func(ctx context.Context, tenantID uuid.UUID, payload model.DynamicRegistrationPayload) (*model.Application, string, error) {
		if payload.SoftwareStatement != "signed-statement-jwt" {
			t.Errorf("expected software statement 'signed-statement-jwt', got '%s'", payload.SoftwareStatement)
		}
		return &model.Application{ClientID: "registered-client-id"}, "plaintext-secret", nil
	})

	adminStorage.CreateIdentityProviderMock.Set(func(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) error {
		if provider.Config.ClientID != "registered-client-id" {
			t.Errorf("expected client ID 'registered-client-id', got '%s'", provider.Config.ClientID)
		}
		if provider.Config.ClientSecret != "plaintext-secret" {
			t.Errorf("expected client secret 'plaintext-secret', got '%s'", provider.Config.ClientSecret)
		}
		return nil
	})

	fedClient.FetchOIDCDiscoveryMetadataMock.Expect(minimock.AnyContext, "https://admin.com/.well-known/openid-configuration").Return(&model.OIDCDiscoveryMetadata{
		AuthorizationEndpoint: "https://admin.com/oauth/authorize",
		TokenEndpoint:         "https://admin.com/oauth/token",
		JwksURI:               "https://admin.com/.well-known/jwks.json",
	}, nil)

	fedLogin.InitiateFederatedLoginMock.Expect(minimock.AnyContext, port.InitiateFederatedLoginCommand{
		TenantID:           tenantUUID,
		IdentityProviderID: providerUUID,
		ClientID:           "admin_ui",
		RequestedScopes:    []string{"openid", "profile", "email"},
		LocalCallbackURI:   "https://callback",
		FinalTargetURI:     "https://final",
	}).Return(&port.InitiateFederatedLoginResponse{
		TargetRedirectURL: "https://admin.com/oauth/authorize?client_id=registered-client-id",
	}, nil)

	resp, err := svc.InitiateAdminLogon(context.Background(), tenantUUID, "https://callback", "https://final")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.TargetRedirectURL != "https://admin.com/oauth/authorize?client_id=registered-client-id" {
		t.Errorf("expected redirect URL 'https://admin.com/oauth/authorize?client_id=registered-client-id', got '%s'", resp.TargetRedirectURL)
	}
}

func TestAdminLogonService_InitiateAdminLogon_DiscoveryPersist_Success(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	fedClient := portmock.NewFederationClientMock(ctrl)
	fedLogin := portmock.NewFederatedLoginUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewAdminLogonService(storage, adminStorage, auth, crypto, fedClient, fedLogin, clock, "local", "admin.com")

	tenantUUID := uuid.New()
	providerUUID := uuid.New()

	storage.GetIdentityProvidersMock.Expect(minimock.AnyContext, tenantUUID).Return([]model.IdentityProvider{
		{
			ID:      providerUUID,
			IDPType: model.OpenIDConnectIDPType,
			Alias:   "admin-sso",
			Enabled: true,
			Config: model.IdentityProviderConfig{
				DiscoveryEndpoint:     "https://admin.com/.well-known/openid-configuration",
				ClientID:              "already-provisioned-id", // Bypasses DCR!
				AuthorizationEndpoint: "",                       // Triggers Discovery!
				TokenEndpoint:         "",                       // Triggers Discovery!
			},
		},
	}, nil)

	fedClient.FetchOIDCDiscoveryMetadataMock.Expect(minimock.AnyContext, "https://admin.com/.well-known/openid-configuration").Return(&model.OIDCDiscoveryMetadata{
		AuthorizationEndpoint: "https://admin.com/oauth/authorize",
		TokenEndpoint:         "https://admin.com/oauth/token",
		JwksURI:               "https://admin.com/.well-known/jwks.json",
	}, nil)

	// ASSERTION: Ensure CreateIdentityProvider is called to persist the discovered metadata back to the DB!
	adminStorage.CreateIdentityProviderMock.Set(func(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) error {
		if provider.Config.AuthorizationEndpoint != "https://admin.com/oauth/authorize" {
			t.Errorf("expected auth endpoint 'https://admin.com/oauth/authorize', got '%s'", provider.Config.AuthorizationEndpoint)
		}
		if provider.Config.TokenEndpoint != "https://admin.com/oauth/token" {
			t.Errorf("expected token endpoint 'https://admin.com/oauth/token', got '%s'", provider.Config.TokenEndpoint)
		}
		if provider.Config.JwksURI != "https://admin.com/.well-known/jwks.json" {
			t.Errorf("expected jwks uri 'https://admin.com/.well-known/jwks.json', got '%s'", provider.Config.JwksURI)
		}
		return nil
	})

	fedLogin.InitiateFederatedLoginMock.Expect(minimock.AnyContext, port.InitiateFederatedLoginCommand{
		TenantID:           tenantUUID,
		IdentityProviderID: providerUUID,
		ClientID:           "admin_ui",
		RequestedScopes:    []string{"openid", "profile", "email"},
		LocalCallbackURI:   "https://callback",
		FinalTargetURI:     "https://final",
	}).Return(&port.InitiateFederatedLoginResponse{
		TargetRedirectURL: "https://admin.com/oauth/authorize?client_id=already-provisioned-id",
	}, nil)

	resp, err := svc.InitiateAdminLogon(context.Background(), tenantUUID, "https://callback", "https://final")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.TargetRedirectURL != "https://admin.com/oauth/authorize?client_id=already-provisioned-id" {
		t.Errorf("expected redirect URL 'https://admin.com/oauth/authorize?client_id=already-provisioned-id', got '%s'", resp.TargetRedirectURL)
	}
}
