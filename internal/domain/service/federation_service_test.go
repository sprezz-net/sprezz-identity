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

func TestFederationService_InitiateFederatedLogin_Success(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	fedClient := portmock.NewFederationClientMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewFederationService(storage, fedClient, crypto, clock)

	tenantUUID := uuid.New()
	providerUUID := uuid.New()

	storage.GetIdentityProviderByUUIDMock.Expect(minimock.AnyContext, tenantUUID, providerUUID).Return(&model.IdentityProvider{
		ID:          providerUUID,
		Enabled:     true,
		PartitionID: 1,
		Config: model.IdentityProviderConfig{
			DiscoveryEndpoint: "https://external-idp.com/.well-known/openid-configuration",
			ClientID:          "client-abc",
			Scopes:            []string{"openid", "profile"},
		},
	}, nil)

	fedClient.FetchOIDCDiscoveryMetadataMock.Expect(minimock.AnyContext, "https://external-idp.com/.well-known/openid-configuration").Return(&model.OIDCDiscoveryMetadata{
		AuthorizationEndpoint: "https://external-idp.com/oauth/authorize",
		TokenEndpoint:         "https://external-idp.com/oauth/token",
		JwksURI:               "https://external-idp.com/jwks.json",
	}, nil)

	storage.SaveOutboundHandshakeMock.Set(func(ctx context.Context, session model.OutboundHandshakeSession) error {
		return nil
	})

	cmd := port.InitiateFederatedLoginCommand{
		TenantID:           tenantUUID,
		IdentityProviderID: providerUUID,
		ClientID:           "client-abc",
		RequestedScopes:    []string{"openid", "profile"},
		LocalCallbackURI:   "https://callback",
		FinalTargetURI:     "https://final",
	}

	resp, err := svc.InitiateFederatedLogin(context.Background(), cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.TargetRedirectURL == "" {
		t.Error("expected non-empty target redirect URL")
	}
}

func TestFederationService_ExecuteFederatedCallback_JITProvisioning(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	fedClient := portmock.NewFederationClientMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewFederationService(storage, fedClient, crypto, clock)

	tenantUUID := uuid.New()
	providerUUID := uuid.New()
	stateToken := "state-123"

	// 1. Mock Outbound Handshake Session
	storage.GetAndConsumeOutboundHandshakeMock.Expect(minimock.AnyContext, tenantUUID, stateToken).Return(&model.OutboundHandshakeSession{
		ID:                 stateToken,
		TenantID:           tenantUUID,
		PartitionID:        2,
		IdentityProviderID: providerUUID,
		ExpiresAt:          now.Add(10 * time.Minute),
		CallbackURI:        "https://callback",
		TargetURI:          "https://target",
	}, nil)

	// 2. Mock Identity Provider
	storage.GetIdentityProviderByUUIDMock.Expect(minimock.AnyContext, tenantUUID, providerUUID).Return(&model.IdentityProvider{
		ID:          providerUUID,
		Enabled:     true,
		PartitionID: 2,
		Config: model.IdentityProviderConfig{
			ClientID:          "client-abc",
			TokenEndpoint:     "https://idp.com/token",
			JwksURI:           "https://idp.com/keys",
			AutoProvisionUser: true,
			AutoVerifyEmail:   true,
		},
	}, nil)

	// 3. Mock Exchange Code for Tokens
	fedClient.ExchangeAuthorizationCodeMock.Set(func(ctx context.Context, tokenEndpoint string, params port.OutboundOIDCParams, code string, codeVerifier string) (*port.UpstreamTokenSet, error) {
		return &port.UpstreamTokenSet{
			AccessToken: "access-token-123",
			IDToken:     "id-token-123",
			ExpiresIn:   3600,
		}, nil
	})

	// 4. Mock Verify External Token
	crypto.VerifyExternalTokenWithProviderMock.Expect(minimock.AnyContext, "id-token-123", "https://idp.com/keys", "").Return(map[string]any{
		"sub":            "upstream-sub-123",
		"email":          "jit-admin@example.com",
		"email_verified": true,
		"name":           "JIT Administrator",
	}, nil)

	// 5. Mock Resolve Tenant
	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(&model.Tenant{
		ID:   tenantUUID,
		Name: "Test Tenant",
	}, nil)

	// 6. Mock GetUserIdentityByProviderAndExternalID -> return not found to trigger Strategy B
	storage.GetUserIdentityByProviderAndExternalIDMock.Expect(minimock.AnyContext, tenantUUID, int64(2), providerUUID, "upstream-sub-123").Return(nil, port.ErrSessionNotFound)

	// 7. Mock FindProfileByEmail -> return user profile not found to trigger JIT creation
	storage.FindProfileByEmailMock.Expect(minimock.AnyContext, int64(2), "jit-admin@example.com").Return(nil, port.ErrUserProfileNotFound)

	// 8. Mock SaveUserProfile -> expect newly JIT created profile
	storage.SaveUserProfileMock.Set(func(ctx context.Context, tenantID uuid.UUID, partitionID int64, profile model.UserProfile) error {
		if profile.Email != "jit-admin@example.com" {
			t.Errorf("expected JIT profile email 'jit-admin@example.com', got '%s'", profile.Email)
		}
		if !profile.EmailVerified {
			t.Error("expected JIT profile to be email verified")
		}
		if profile.Name != "JIT Administrator" {
			t.Errorf("expected JIT profile display name 'JIT Administrator', got '%s'", profile.Name)
		}
		return nil
	})

	// 9. Mock UpsertUserIdentity
	storage.UpsertUserIdentityMock.Set(func(ctx context.Context, tenantID uuid.UUID, partitionID int64, identity model.UserIdentity) error {
		if identity.ExternalIdentityID != "upstream-sub-123" {
			t.Errorf("expected identity external ID 'upstream-sub-123', got '%s'", identity.ExternalIdentityID)
		}
		return nil
	})

	// 10. Mock SaveFederatedSession
	storage.SaveFederatedSessionMock.Set(func(ctx context.Context, session model.FederatedSession) error {
		return nil
	})

	cmd := port.FederatedCallbackCommand{
		TenantID:      tenantUUID,
		IncomingState: stateToken,
		IncomingCode:  "code-123",
		SessionID:     "native-session-999",
	}

	resp, err := svc.ExecuteFederatedCallback(context.Background(), cmd)
	if err != nil {
		t.Fatalf("ExecuteFederatedCallback returned unexpected error: %v", err)
	}

	if resp.UpstreamAccessToken != "access-token-123" {
		t.Errorf("expected UpstreamAccessToken 'access-token-123', got '%s'", resp.UpstreamAccessToken)
	}
}

func TestFederationService_ExecuteFederatedCallback_FailsIfEmailUnverified(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	fedClient := portmock.NewFederationClientMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewFederationService(storage, fedClient, crypto, clock)

	tenantUUID := uuid.New()
	providerUUID := uuid.New()
	stateToken := "state-123"

	// 1. Mock Outbound Handshake Session
	storage.GetAndConsumeOutboundHandshakeMock.Expect(minimock.AnyContext, tenantUUID, stateToken).Return(&model.OutboundHandshakeSession{
		ID:                 stateToken,
		TenantID:           tenantUUID,
		PartitionID:        2,
		IdentityProviderID: providerUUID,
		ExpiresAt:          now.Add(10 * time.Minute),
		CallbackURI:        "https://callback",
		TargetURI:          "https://target",
	}, nil)

	// 2. Mock Identity Provider
	storage.GetIdentityProviderByUUIDMock.Expect(minimock.AnyContext, tenantUUID, providerUUID).Return(&model.IdentityProvider{
		ID:          providerUUID,
		Enabled:     true,
		PartitionID: 2,
		Config: model.IdentityProviderConfig{
			ClientID:          "client-abc",
			TokenEndpoint:     "https://idp.com/token",
			JwksURI:           "https://idp.com/keys",
			AutoProvisionUser: true,
			AutoVerifyEmail:   true,
		},
	}, nil)

	// 3. Mock Exchange Code for Tokens
	fedClient.ExchangeAuthorizationCodeMock.Set(func(ctx context.Context, tokenEndpoint string, params port.OutboundOIDCParams, code string, codeVerifier string) (*port.UpstreamTokenSet, error) {
		return &port.UpstreamTokenSet{
			AccessToken: "access-token-123",
			IDToken:     "id-token-123",
			ExpiresIn:   3600,
		}, nil
	})

	// 4. Mock Verify External Token -> Set email_verified: false!
	crypto.VerifyExternalTokenWithProviderMock.Expect(minimock.AnyContext, "id-token-123", "https://idp.com/keys", "").Return(map[string]any{
		"sub":            "upstream-sub-123",
		"email":          "unverified-admin@example.com",
		"email_verified": false, // Unverified upstream email!
		"name":           "JIT Administrator",
	}, nil)

	// 5. Mock Resolve Tenant
	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(&model.Tenant{
		ID:   tenantUUID,
		Name: "Test Tenant",
	}, nil)

	// 6. Mock GetUserIdentityByProviderAndExternalID -> return not found to trigger Strategy B
	storage.GetUserIdentityByProviderAndExternalIDMock.Expect(minimock.AnyContext, tenantUUID, int64(2), providerUUID, "upstream-sub-123").Return(nil, port.ErrSessionNotFound)

	cmd := port.FederatedCallbackCommand{
		TenantID:      tenantUUID,
		IncomingState: stateToken,
		IncomingCode:  "code-123",
		SessionID:     "native-session-999",
	}

	_, err := svc.ExecuteFederatedCallback(context.Background(), cmd)
	if err == nil {
		t.Fatal("expected ExecuteFederatedCallback to return an error, got nil")
	}

	expectedErrorStr := "federation_service: dynamic profile link blocked - external provider email is unverified"
	if err.Error() != expectedErrorStr {
		t.Errorf("expected error '%s', got '%s'", expectedErrorStr, err.Error())
	}
}
