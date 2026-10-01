package service

import (
	"context"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A tenant switched off by hand must not lock every administrator out for good: the bootstrap that runs at every
// start forces the administrative tenant back on.
func TestTenantBootstrapService_ReactivatesAnInactiveAdministrativeTenant(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	svc := NewTenantBootstrapService(storage, adminStorage, portmock.NewTenantUseCaseMock(ctrl), portmock.NewMockClock(time.Now()), "unittest")

	domain := "admin.example.com"
	part := int64(1)
	existing := &model.Tenant{ID: uuid.New(), Domain: domain, Scheme: "https", IsSystem: true, IsActive: false, DefaultPartition: &part}
	storage.ResolveTenantByDomainMock.Return(existing, nil)

	var saved []model.Tenant
	adminStorage.CreateTenantMock.Set(func(ctx context.Context, tenant model.Tenant) error {
		saved = append(saved, tenant)
		return nil
	})
	// The rest of the bootstrap (provider and application checks) is not what this test is about.
	storage.GetEnabledIdentityProvidersMock.Optional().Return([]model.IdentityProvider{{ID: uuid.New(), IDPType: model.UsernamePasswordIDPType, Enabled: true}}, nil)
	storage.ResolveTenantByUUIDMock.Optional().Return(existing, nil)
	storage.GetApplicationByClientIDMock.Optional().Return(nil, nil, nil, nil)
	adminStorage.CreateApplicationProfileMock.Optional().Return(nil)
	adminStorage.CreateApplicationGroupMock.Optional().Return(nil)
	adminStorage.CreateApplicationMock.Optional().Return(nil)

	tenant, err := svc.BootstrapAdminTenant(context.Background(), domain)

	require.NoError(t, err)
	assert.True(t, tenant.IsActive)
	require.NotEmpty(t, saved, "the corrected tenant is written back")
	assert.True(t, saved[0].IsActive)
}
