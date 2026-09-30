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

func newBootstrapFixture(t *testing.T, providers []model.IdentityProvider) (*TenantBootstrapService, *portmock.AdminStorageMock, string) {
	t.Helper()
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	tenantUseCase := portmock.NewTenantUseCaseMock(ctrl)
	clock := portmock.NewMockClock(time.Now())

	svc := NewTenantBootstrapService(storage, adminStorage, tenantUseCase, clock, "unittest")

	domain := "admin.example.com"
	tenantID := uuid.New()
	defaultPart := int64(1)
	created := &model.Tenant{ID: tenantID, Name: "Administrative Tenant", Domain: domain, IsActive: true, DefaultPartition: &defaultPart}

	storage.ResolveTenantByDomainMock.Expect(minimock.AnyContext, domain).Return(nil, port.ErrTenantNotFound)
	tenantUseCase.CreateTenantMock.Set(func(ctx context.Context, cmd port.CreateTenantCommand) (*model.Tenant, error) {
		return created, nil
	})
	storage.GetEnabledIdentityProvidersMock.Set(func(ctx context.Context, tID uuid.UUID) ([]model.IdentityProvider, error) {
		return providers, nil
	})
	storage.ResolveTenantByUUIDMock.Set(func(ctx context.Context, tID uuid.UUID) (*model.Tenant, error) {
		return created, nil
	})
	storage.GetApplicationByClientIDMock.Expect(minimock.AnyContext, tenantID, "admin_ui").Return(nil, nil, nil, port.ErrApplicationNotFound)

	return svc, adminStorage, domain
}

func TestTenantBootstrapService_FlagsEverythingAsSystemManaged(t *testing.T) {
	localID := uuid.New()
	ssoID := uuid.New()
	svc, adminStorage, domain := newBootstrapFixture(t, []model.IdentityProvider{
		{ID: ssoID, IDPType: model.OpenIDConnectIDPType, Alias: "admin-sso", Enabled: true},
		{ID: localID, IDPType: model.UsernamePasswordIDPType, Enabled: true},
	})

	var savedTenant model.Tenant
	adminStorage.CreateTenantMock.Set(func(ctx context.Context, tenant model.Tenant) error {
		savedTenant = tenant
		return nil
	})
	adminStorage.CreateApplicationProfileMock.Set(func(ctx context.Context, tID uuid.UUID, p model.ApplicationProfile) error {
		assert.True(t, p.IsSystem, "admin profile must be system-managed")
		return nil
	})
	adminStorage.CreateApplicationGroupMock.Set(func(ctx context.Context, tID uuid.UUID, g model.ApplicationGroup) error {
		assert.True(t, g.IsSystem, "group %s must be system-managed", g.GroupName)
		return nil
	})
	adminStorage.CreateApplicationMock.Set(func(ctx context.Context, tID uuid.UUID, app model.Application) error {
		assert.True(t, app.IsSystem, "admin application must be system-managed")
		return nil
	})

	_, err := svc.BootstrapAdminTenant(context.Background(), domain)
	require.NoError(t, err)
	assert.True(t, savedTenant.IsSystem, "admin tenant must be system-managed")
}

func TestTenantBootstrapService_NoAdminSSO_LeavesGroupWithoutDefault(t *testing.T) {
	localID := uuid.New()
	svc, adminStorage, domain := newBootstrapFixture(t, []model.IdentityProvider{
		{ID: localID, IDPType: model.UsernamePasswordIDPType, Enabled: true},
	})

	adminStorage.CreateTenantMock.Set(func(ctx context.Context, tenant model.Tenant) error { return nil })
	adminStorage.CreateApplicationProfileMock.Set(func(ctx context.Context, tID uuid.UUID, p model.ApplicationProfile) error { return nil })
	adminStorage.CreateApplicationMock.Set(func(ctx context.Context, tID uuid.UUID, app model.Application) error { return nil })
	adminStorage.CreateApplicationGroupMock.Set(func(ctx context.Context, tID uuid.UUID, g model.ApplicationGroup) error {
		if g.GroupName == model.AdminUIGroupName {
			assert.Nil(t, g.DefaultIDPID, "a missing admin SSO provider must not be persisted as uuid.Nil")
			assert.NotNil(t, g.AllowedIDPIDs, "allowed providers must be an empty slice, never nil")
			assert.Empty(t, g.AllowedIDPIDs)
		}
		return nil
	})

	_, err := svc.BootstrapAdminTenant(context.Background(), domain)
	require.NoError(t, err)
}
