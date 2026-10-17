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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminLogonService_InitiateAdminLogon_Success(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)

	allowTenant(storage)
	fedLogin := portmock.NewFederatedLoginUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewAdminLogonService(storage, nil, nil, nil, nil, fedLogin, clock, "local", "admin.com")

	tenantUUID := uuid.New()
	flowSessionID := uuid.New()
	providerUUID := uuid.New()

	allowAdminPartition(storage, tenantUUID)
	storage.GetIdentityProviderByAliasMock.Expect(minimock.AnyContext, tenantUUID, model.AdminSSOAliasName).Return(&model.IdentityProvider{
		ID:          providerUUID,
		IDPType:     model.OpenIDConnectIDPType,
		Alias:       model.AdminSSOAliasName,
		Enabled:     true,
		PartitionID: testAdminPartitionID,
		Issuer:      "https://admin.com",
		Config: model.IdentityProviderConfig{
			ClientID:              "admin_ui",
			AuthorizationEndpoint: "https://auth",
			TokenEndpoint:         "https://token",
		},
	}, nil)

	fedLogin.InitiateFederatedLoginMock.Expect(minimock.AnyContext, port.InitiateFederatedLoginCommand{
		TenantID:           tenantUUID,
		IdentityProviderID: providerUUID,
		ClientID:           "admin_ui",
		RequestedScopes:    []string{"openid", "profile", "email"},
		LocalCallbackURI:   "https://callback",
		FinalTargetURI:     "https://final",
		FlowSessionID:      flowSessionID,
	}).Return(&port.InitiateFederatedLoginResponse{
		TargetRedirectURL: "https://redirect-url",
	}, nil)

	resp, err := svc.InitiateAdminLogon(context.Background(), tenantUUID, flowSessionID, "https://callback", "https://final")
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

	allowTenant(storage)
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	auth := portmock.NewAuthUseCaseMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	fedClient := portmock.NewFederationClientMock(ctrl)
	fedLogin := portmock.NewFederatedLoginUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewAdminLogonService(storage, adminStorage, auth, crypto, fedClient, fedLogin, clock, "local", "admin.com")

	tenantUUID := uuid.New()
	flowSessionID := uuid.New()
	adminTenantUUID := uuid.New()
	providerUUID := uuid.New()

	allowAdminPartition(storage, tenantUUID)
	storage.GetIdentityProviderByAliasMock.Expect(minimock.AnyContext, tenantUUID, model.AdminSSOAliasName).Return(&model.IdentityProvider{
		ID:          providerUUID,
		IDPType:     model.OpenIDConnectIDPType,
		Alias:       model.AdminSSOAliasName,
		Enabled:     true,
		PartitionID: testAdminPartitionID,
		Config: model.IdentityProviderConfig{
			DiscoveryEndpoint: "https://admin.com/.well-known/openid-configuration",
			ClientID:          "", // Triggers DCR!
		},
	}, nil)

	storage.ResolveTenantByDomainMock.Expect(minimock.AnyContext, "admin.com").Return(&model.Tenant{
		ID:       adminTenantUUID,
		Domain:   "admin.com",
		IsActive: true,
	}, nil)

	crypto.SignSoftwareStatementMock.Set(func(ctx context.Context, issuer string, audience string, claims model.SoftwareStatementClaims, issuedAt time.Time, expiresAt time.Time, notBefore time.Time) (string, error) {
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
		Issuer:                "https://admin.com",
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
		FlowSessionID:      flowSessionID,
	}).Return(&port.InitiateFederatedLoginResponse{
		TargetRedirectURL: "https://admin.com/oauth/authorize?client_id=registered-client-id",
	}, nil)

	resp, err := svc.InitiateAdminLogon(context.Background(), tenantUUID, flowSessionID, "https://callback", "https://final")
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

	allowTenant(storage)
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	auth := portmock.NewAuthUseCaseMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	fedClient := portmock.NewFederationClientMock(ctrl)
	fedLogin := portmock.NewFederatedLoginUseCaseMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewAdminLogonService(storage, adminStorage, auth, crypto, fedClient, fedLogin, clock, "local", "admin.com")

	tenantUUID := uuid.New()
	flowSessionID := uuid.New()
	providerUUID := uuid.New()

	allowAdminPartition(storage, tenantUUID)
	storage.GetIdentityProviderByAliasMock.Expect(minimock.AnyContext, tenantUUID, model.AdminSSOAliasName).Return(&model.IdentityProvider{
		ID:          providerUUID,
		IDPType:     model.OpenIDConnectIDPType,
		Alias:       model.AdminSSOAliasName,
		Enabled:     true,
		PartitionID: testAdminPartitionID,
		Config: model.IdentityProviderConfig{
			DiscoveryEndpoint:     "https://admin.com/.well-known/openid-configuration",
			ClientID:              "already-provisioned-id", // Bypasses DCR!
			AuthorizationEndpoint: "",                       // Triggers Discovery!
			TokenEndpoint:         "",                       // Triggers Discovery!
		},
	}, nil)

	fedClient.FetchOIDCDiscoveryMetadataMock.Expect(minimock.AnyContext, "https://admin.com/.well-known/openid-configuration").Return(&model.OIDCDiscoveryMetadata{
		Issuer:                "https://admin.com",
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
		FlowSessionID:      flowSessionID,
	}).Return(&port.InitiateFederatedLoginResponse{
		TargetRedirectURL: "https://admin.com/oauth/authorize?client_id=already-provisioned-id",
	}, nil)

	resp, err := svc.InitiateAdminLogon(context.Background(), tenantUUID, flowSessionID, "https://callback", "https://final")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.TargetRedirectURL != "https://admin.com/oauth/authorize?client_id=already-provisioned-id" {
		t.Errorf("expected redirect URL 'https://admin.com/oauth/authorize?client_id=already-provisioned-id', got '%s'", resp.TargetRedirectURL)
	}
}

// testAdminPartitionID is the id the tests give the administrative partition of a tenant.
const testAdminPartitionID = int64(18)

func allowAdminPartition(storage *portmock.StorageMock, tenantID uuid.UUID) {
	storage.GetPartitionByAliasMock.Optional().Set(func(ctx context.Context, id uuid.UUID, alias string) (*model.Partition, error) {
		if id != tenantID || alias != model.AdminPartitionAliasName {
			return nil, port.ErrPartitionNotFound
		}
		return &model.Partition{ID: testAdminPartitionID, TenantID: id, AliasName: alias}, nil
	})
}

// The console signs in to the fixed administrative partition. A provider anywhere else would let the sign-in
// complete and then fail the guard of the console, so it is refused before anything starts.
func TestAdminLogonService_InitiateAdminLogon_RefusesAProviderOutsideTheAdministrativePartition(t *testing.T) {
	for name, partitionID := range map[string]int64{"another partition": testAdminPartitionID + 1, "no partition": 0} {
		t.Run(name, func(t *testing.T) {
			ctrl := minimock.NewController(t)
			storage := portmock.NewStorageMock(ctrl)
			allowTenant(storage)
			fedLogin := portmock.NewFederatedLoginUseCaseMock(ctrl) // strict: no federated login may start
			svc := NewAdminLogonService(storage, nil, nil, nil, nil, fedLogin, portmock.NewMockClock(time.Now()), "local", "admin.com")
			tenantUUID := uuid.New()
			allowAdminPartition(storage, tenantUUID)
			storage.GetIdentityProviderByAliasMock.Return(&model.IdentityProvider{
				ID: uuid.New(), IDPType: model.OpenIDConnectIDPType, Alias: model.AdminSSOAliasName, Enabled: true, PartitionID: partitionID,
				Config: model.IdentityProviderConfig{ClientID: "admin_ui", AuthorizationEndpoint: "https://auth", TokenEndpoint: "https://token"}, Issuer: "https://admin.com",
			}, nil)

			_, err := svc.InitiateAdminLogon(context.Background(), tenantUUID, uuid.New(), "https://callback", "https://final")

			require.ErrorIs(t, err, port.ErrInvalidRequest)
			assert.Contains(t, err.Error(), model.AdminPartitionAliasName)
		})
	}
}

func TestAdminLogonService_InitiateAdminLogon_RefusesATenantWithoutAnAdministrativePartition(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	allowTenant(storage)
	svc := NewAdminLogonService(storage, nil, nil, nil, nil, portmock.NewFederatedLoginUseCaseMock(ctrl), portmock.NewMockClock(time.Now()), "local", "admin.com")
	tenantUUID := uuid.New()
	storage.GetPartitionByAliasMock.Return(nil, port.ErrPartitionNotFound)
	storage.GetIdentityProviderByAliasMock.Return(&model.IdentityProvider{ID: uuid.New(), IDPType: model.OpenIDConnectIDPType, Alias: model.AdminSSOAliasName, Enabled: true}, nil)

	_, err := svc.InitiateAdminLogon(context.Background(), tenantUUID, uuid.New(), "https://callback", "https://final")

	require.ErrorIs(t, err, port.ErrPartitionNotFound)
}

// ---- finding the provider the console signs in through ----

func newAdminSSOLookupFixture(t *testing.T) (*AdminLogonService, *portmock.StorageMock, uuid.UUID) {
	t.Helper()
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	allowTenant(storage)
	// strict federated login: nothing may start for a provider that fails a check
	svc := NewAdminLogonService(storage, nil, nil, nil, nil, portmock.NewFederatedLoginUseCaseMock(ctrl), portmock.NewMockClock(time.Now()), "local", "admin.com")
	tenantID := uuid.New()
	allowAdminPartition(storage, tenantID)
	return svc, storage, tenantID
}

func TestAdminLogonService_InitiateAdminLogon_FindsTheProviderByItsAlias(t *testing.T) {
	svc, storage, tenantID := newAdminSSOLookupFixture(t)
	storage.GetIdentityProviderByAliasMock.Expect(minimock.AnyContext, tenantID, "admin-sso").Return(nil, port.ErrIdentityProviderNotFound)

	_, err := svc.InitiateAdminLogon(context.Background(), tenantID, uuid.New(), "https://callback", "https://final")

	require.ErrorIs(t, err, port.ErrIdentityProviderNotFound)
	assert.Equal(t, "admin-sso", model.AdminSSOAliasName, "the alias the console and the tenant bootstrap agree on")
}

func TestAdminLogonService_InitiateAdminLogon_RefusesAProviderThatIsNotOIDC(t *testing.T) {
	svc, storage, tenantID := newAdminSSOLookupFixture(t)
	storage.GetIdentityProviderByAliasMock.Return(&model.IdentityProvider{ID: uuid.New(), IDPType: model.UsernamePasswordIDPType, Alias: model.AdminSSOAliasName, Enabled: true, PartitionID: testAdminPartitionID}, nil)

	_, err := svc.InitiateAdminLogon(context.Background(), tenantID, uuid.New(), "https://callback", "https://final")

	require.ErrorIs(t, err, port.ErrIdentityProviderNotFound)
}

func TestAdminLogonService_InitiateAdminLogon_RefusesADisabledProvider(t *testing.T) {
	svc, storage, tenantID := newAdminSSOLookupFixture(t)
	storage.GetIdentityProviderByAliasMock.Return(&model.IdentityProvider{ID: uuid.New(), IDPType: model.OpenIDConnectIDPType, Alias: model.AdminSSOAliasName, Enabled: false, PartitionID: testAdminPartitionID}, nil)

	_, err := svc.InitiateAdminLogon(context.Background(), tenantID, uuid.New(), "https://callback", "https://final")

	require.ErrorIs(t, err, port.ErrIdentityProviderDisabled, "an administrator who disabled the provider switched console sign-in off")
}

func TestAdminLogonService_InitiateAdminLogon_ALookupThatReturnsNothingIsRefused(t *testing.T) {
	svc, storage, tenantID := newAdminSSOLookupFixture(t)
	storage.GetIdentityProviderByAliasMock.Return(nil, nil) // a misbehaving adapter must not cause a nil dereference

	_, err := svc.InitiateAdminLogon(context.Background(), tenantID, uuid.New(), "https://callback", "https://final")

	require.ErrorIs(t, err, port.ErrIdentityProviderNotFound)
}
