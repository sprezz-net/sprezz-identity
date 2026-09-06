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
