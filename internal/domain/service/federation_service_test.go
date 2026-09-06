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
