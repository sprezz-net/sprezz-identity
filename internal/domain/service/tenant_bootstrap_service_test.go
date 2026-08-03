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

func TestTenantBootstrapService_BootstrapAdminTenant_InitialCreation(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	service := NewTenantBootstrapService(storage, portmock.NewMockClock(time.Now()))

	domain := "admin.example.com"

	// Mock ResolveTenantByDomain to return ErrTenantNotFound
	storage.ResolveTenantByDomainMock.Expect(context.Background(), domain).Return(nil, port.ErrTenantNotFound)

	// Mock CreateTenant
	storage.CreateTenantMock.Set(validateTenant(t, domain))

	// Mock CreateIdentityProvider
	storage.CreateIdentityProviderMock.Set(validateIdentityProvider(t))

	tenant, err := service.BootstrapAdminTenant(context.Background(), domain)
	if err != nil {
		t.Fatalf("unexpected error during initial bootstrap: %v", err)
	}

	if tenant == nil {
		t.Fatal("expected returned tenant to be non-nil")
	}
	if tenant.Domain != domain {
		t.Errorf("expected tenant domain %s, got %s", domain, tenant.Domain)
	}
}

func validateTenant(t *testing.T, expectedDomain string) func(context.Context, model.Tenant) error {
	return func(ctx context.Context, tenant model.Tenant) error {
		if tenant.Domain != expectedDomain {
			t.Errorf("expected tenant domain %s, got %s", expectedDomain, tenant.Domain)
		}
		if tenant.Name != expectedDomain {
			t.Errorf("expected tenant name %s, got %s", expectedDomain, tenant.Name)
		}
		if tenant.ID == uuid.Nil {
			t.Error("expected non-nil tenant ID")
		}
		if !tenant.IsActive {
			t.Error("expected tenant to be active")
		}
		return nil
	}
}

func validateIdentityProvider(t *testing.T) func(context.Context, uuid.UUID, model.IdentityProvider) error {
	return func(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) error {
		if provider.TenantID != tenantID {
			t.Errorf("expected provider tenant ID %s, got %s", tenantID, provider.TenantID)
		}
		if provider.IDPType != model.UsernamePasswordIDPType {
			t.Errorf("expected provider type %s, got %s", model.UsernamePasswordIDPType, provider.IDPType)
		}
		if !provider.Enabled {
			t.Error("expected provider to be enabled")
		}
		if provider.Alias != "username-password" {
			t.Errorf("expected provider alias 'username-password', got %q", provider.Alias)
		}
		return nil
	}
}
