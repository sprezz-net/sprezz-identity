package service_test

import (
	"context"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"
	"sprezz-identity/internal/domain/service"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type appServiceFixture struct {
	svc      *service.ApplicationService
	storage  *portmock.StorageMock
	admin    *portmock.AdminStorageMock
	tenantID uuid.UUID
}

func newAppServiceFixture(t *testing.T) *appServiceFixture {
	t.Helper()
	mc := minimock.NewController(t)
	storage := portmock.NewStorageMock(mc)
	admin := portmock.NewAdminStorageMock(mc)
	clock := portmock.NewMockClock(time.Now())
	crypto := portmock.NewCryptoMock(mc)

	return &appServiceFixture{
		svc:      service.NewApplicationService(storage, admin, clock, crypto),
		storage:  storage,
		admin:    admin,
		tenantID: uuid.New(),
	}
}

func (f *appServiceFixture) stubApplication(app model.Application) {
	f.storage.GetApplicationByClientIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, clientID string) (*model.Application, *model.ApplicationProfile, *model.ApplicationGroup, error) {
		return &app, &model.ApplicationProfile{TokenEndpointAuthMethod: model.AuthMethodClientSecretPost}, &model.ApplicationGroup{}, nil
	})
}

func TestApplicationService_SystemApplication_IsProtected(t *testing.T) {
	f := newAppServiceFixture(t)
	f.stubApplication(model.Application{ID: uuid.New(), ClientID: "admin_ui", IsSystem: true, IsEnabled: true})

	t.Run("update", func(t *testing.T) {
		err := f.svc.UpdateApplication(context.Background(), port.UpdateApplicationCommand{TenantID: f.tenantID, ClientID: "admin_ui"})
		assert.ErrorIs(t, err, port.ErrSystemManaged)
	})

	t.Run("delete", func(t *testing.T) {
		err := f.svc.DeleteApplication(context.Background(), f.tenantID, "admin_ui")
		assert.ErrorIs(t, err, port.ErrSystemManaged)
	})

	t.Run("toggle", func(t *testing.T) {
		_, err := f.svc.ToggleApplicationStatus(context.Background(), f.tenantID, "admin_ui")
		assert.ErrorIs(t, err, port.ErrSystemManaged)
	})

	t.Run("reset secret", func(t *testing.T) {
		err := f.svc.ResetApplicationSecret(context.Background(), port.ResetApplicationSecretCommand{
			TenantID:   f.tenantID,
			ClientID:   "admin_ui",
			OnDelivery: func(string) error { return nil },
		})
		assert.ErrorIs(t, err, port.ErrSystemManaged)
	})
}

func TestApplicationService_UpdateApplication_PreservesDisabledState(t *testing.T) {
	f := newAppServiceFixture(t)
	f.stubApplication(model.Application{ID: uuid.New(), ClientID: "app-1", IsEnabled: false})

	f.admin.UpdateApplicationMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, clientID string, app model.Application) error {
		assert.False(t, app.IsEnabled, "a plain edit must not re-enable a disabled application")
		return nil
	})

	err := f.svc.UpdateApplication(context.Background(), port.UpdateApplicationCommand{
		TenantID:        f.tenantID,
		ClientID:        "app-1",
		ApplicationName: "Renamed",
	})
	require.NoError(t, err)
}

func TestApplicationService_UpdateApplication_ExplicitEnable(t *testing.T) {
	f := newAppServiceFixture(t)
	f.stubApplication(model.Application{ID: uuid.New(), ClientID: "app-1", IsEnabled: false})
	enable := true

	f.admin.UpdateApplicationMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, clientID string, app model.Application) error {
		assert.True(t, app.IsEnabled)
		return nil
	})

	err := f.svc.UpdateApplication(context.Background(), port.UpdateApplicationCommand{
		TenantID:  f.tenantID,
		ClientID:  "app-1",
		IsEnabled: &enable,
	})
	require.NoError(t, err)
}

func TestApplicationService_CreateApplication_RequiresDeliveryCallback(t *testing.T) {
	f := newAppServiceFixture(t)

	_, err := f.svc.CreateApplication(context.Background(), port.CreateApplicationCommand{
		TenantID: f.tenantID,
		ClientID: "app-1",
	})
	assert.Error(t, err)
}
