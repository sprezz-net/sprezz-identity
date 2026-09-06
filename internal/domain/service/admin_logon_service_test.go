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
