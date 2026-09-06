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
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	tenantUseCase := portmock.NewTenantUseCaseMock(ctrl)
	clock := portmock.NewMockClock(time.Now())

	service := NewTenantBootstrapService(storage, adminStorage, tenantUseCase, clock, "unittest")

	domain := "admin.example.com"
	tenantID := uuid.New()

	// 1. ResolveTenantByDomain -> ErrTenantNotFound (forces bootstrapNewTenant)
	storage.ResolveTenantByDomainMock.Expect(minimock.AnyContext, domain).Return(nil, port.ErrTenantNotFound)

	// 2. tenantUseCase.CreateTenant -> returns createdTenant
	defaultPart := int64(1)
	createdTenant := &model.Tenant{
		ID:               tenantID,
		Name:             "Administrative Tenant",
		Domain:           domain,
		IsActive:         true,
		DefaultPartition: &defaultPart,
	}
	tenantUseCase.CreateTenantMock.Set(func(ctx context.Context, cmd port.CreateTenantCommand) (*model.Tenant, error) {
		if cmd.DomainName != domain {
			t.Errorf("expected domain %s, got %s", domain, cmd.DomainName)
		}
		return createdTenant, nil
	})

	// 3. adminStorage.CreateTenant -> saves final master configurations
	adminStorage.CreateTenantMock.Set(func(ctx context.Context, tenant model.Tenant) error {
		if tenant.ID != tenantID {
			t.Errorf("expected tenant ID %s, got %s", tenantID, tenant.ID)
		}
		return nil
	})

	// 4. storage.GetEnabledIdentityProviders -> returns empty on first call, then username-password provider
	localIDPID := uuid.New()
	var getEnabledCount int
	storage.GetEnabledIdentityProvidersMock.Set(func(ctx context.Context, tID uuid.UUID) ([]model.IdentityProvider, error) {
		getEnabledCount++
		if getEnabledCount == 1 {
			return nil, port.ErrIdentityProviderNotFound
		}
		return []model.IdentityProvider{
			{ID: localIDPID, IDPType: model.UsernamePasswordIDPType},
		}, nil
	})

	// 5. storage.ResolveTenantByUUID -> returns tenant
	storage.ResolveTenantByUUIDMock.Set(func(ctx context.Context, tID uuid.UUID) (*model.Tenant, error) {
		return createdTenant, nil
	})

	// 6. adminStorage.CreateIdentityProvider -> registers local username-password provider
	adminStorage.CreateIdentityProviderMock.Set(func(ctx context.Context, tID uuid.UUID, provider model.IdentityProvider) error {
		if tID != tenantID {
			t.Errorf("expected tenant ID %s, got %s", tenantID, tID)
		}
		if provider.IDPType != model.UsernamePasswordIDPType {
			t.Errorf("expected provider type %s, got %s", model.UsernamePasswordIDPType, provider.IDPType)
		}
		return nil
	})

	// 7. storage.GetApplicationByClientID -> returns ErrApplicationNotFound to trigger ensureAdminApplicationProfileAndGroup
	storage.GetApplicationByClientIDMock.Expect(minimock.AnyContext, tenantID, "admin_ui").Return(nil, nil, nil, port.ErrApplicationNotFound)

	// 8. adminStorage.CreateApplicationProfile -> registers app profile
	adminStorage.CreateApplicationProfileMock.Set(func(ctx context.Context, tID uuid.UUID, profile model.ApplicationProfile) error {
		return nil
	})

	// 9. adminStorage.CreateApplicationGroup -> registers app group
	adminStorage.CreateApplicationGroupMock.Set(func(ctx context.Context, tID uuid.UUID, group model.ApplicationGroup) error {
		return nil
	})

	// 10. adminStorage.CreateApplication -> registers app
	adminStorage.CreateApplicationMock.Set(func(ctx context.Context, tID uuid.UUID, app model.Application) error {
		return nil
	})

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

func TestTenantBootstrapService_BootstrapAdminTenant_OidcProviderPreExists(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	tenantUseCase := portmock.NewTenantUseCaseMock(ctrl)
	clock := portmock.NewMockClock(time.Now())

	service := NewTenantBootstrapService(storage, adminStorage, tenantUseCase, clock, "unittest")

	domain := "admin.example.com"
	tenantID := uuid.New()

	// 1. ResolveTenantByDomain -> ErrTenantNotFound (forces bootstrapNewTenant)
	storage.ResolveTenantByDomainMock.Expect(minimock.AnyContext, domain).Return(nil, port.ErrTenantNotFound)

	// 2. tenantUseCase.CreateTenant -> returns createdTenant
	defaultPart := int64(1)
	createdTenant := &model.Tenant{
		ID:               tenantID,
		Name:             "Administrative Tenant",
		Domain:           domain,
		IsActive:         true,
		DefaultPartition: &defaultPart,
	}
	tenantUseCase.CreateTenantMock.Set(func(ctx context.Context, cmd port.CreateTenantCommand) (*model.Tenant, error) {
		return createdTenant, nil
	})

	// 3. adminStorage.CreateTenant -> saves final master configurations
	adminStorage.CreateTenantMock.Set(func(ctx context.Context, tenant model.Tenant) error {
		return nil
	})

	// 4. GetEnabledIdentityProviders returns an OIDC provider first (pre-existing)
	var getEnabledCount int
	storage.GetEnabledIdentityProvidersMock.Set(func(ctx context.Context, tID uuid.UUID) ([]model.IdentityProvider, error) {
		getEnabledCount++
		if getEnabledCount == 1 {
			// Pre-existing OIDC provider
			return []model.IdentityProvider{
				{ID: uuid.New(), IDPType: model.OpenIDConnectIDPType},
			}, nil
		}
		// Second call (in Stage 4 setup) returns the registered local login provider
		return []model.IdentityProvider{
			{ID: uuid.New(), IDPType: model.UsernamePasswordIDPType},
		}, nil
	})

	// 5. storage.ResolveTenantByUUID -> returns tenant
	storage.ResolveTenantByUUIDMock.Set(func(ctx context.Context, tID uuid.UUID) (*model.Tenant, error) {
		return createdTenant, nil
	})

	// 6. adminStorage.CreateIdentityProvider -> MUST be called for UsernamePasswordIDPType
	var createIDPCallCount int
	adminStorage.CreateIdentityProviderMock.Set(func(ctx context.Context, tID uuid.UUID, provider model.IdentityProvider) error {
		createIDPCallCount++
		if provider.IDPType != model.UsernamePasswordIDPType {
			t.Errorf("expected provider type %s, got %s", model.UsernamePasswordIDPType, provider.IDPType)
		}
		return nil
	})

	// 7. GetApplicationByClientID -> returns ErrApplicationNotFound
	storage.GetApplicationByClientIDMock.Expect(minimock.AnyContext, tenantID, "admin_ui").Return(nil, nil, nil, port.ErrApplicationNotFound)

	// 8. adminStorage.CreateApplicationProfile -> registers app profile
	adminStorage.CreateApplicationProfileMock.Set(func(ctx context.Context, tID uuid.UUID, profile model.ApplicationProfile) error {
		return nil
	})

	// 9. adminStorage.CreateApplicationGroup -> registers app group
	adminStorage.CreateApplicationGroupMock.Set(func(ctx context.Context, tID uuid.UUID, group model.ApplicationGroup) error {
		return nil
	})

	// 10. adminStorage.CreateApplication -> registers app
	adminStorage.CreateApplicationMock.Set(func(ctx context.Context, tID uuid.UUID, app model.Application) error {
		return nil
	})

	_, err := service.BootstrapAdminTenant(context.Background(), domain)
	if err != nil {
		t.Fatalf("unexpected error during initial bootstrap: %v", err)
	}

	if createIDPCallCount != 1 {
		t.Errorf("expected CreateIdentityProvider to be called exactly 1 time for username-password IDP, called %d times", createIDPCallCount)
	}
}
