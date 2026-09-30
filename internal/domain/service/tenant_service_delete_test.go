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

func newTenantDeleteFixture(t *testing.T, tenant *model.Tenant) (*TenantService, *portmock.AdminStorageMock) {
	t.Helper()
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	clock := portmock.NewMockClock(time.Now())

	storage.ResolveTenantByUUIDMock.Set(func(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
		return tenant, nil
	})

	svc := NewTenantService(storage, adminStorage, clock, nil, "unittest", "admin.example.com")
	return svc, adminStorage
}

func TestTenantService_DeleteTenant_SystemTenantIsNeverDeleted(t *testing.T) {
	tenant := &model.Tenant{ID: uuid.New(), Name: "Administrative Tenant", Domain: "admin.example.com", IsSystem: true}
	svc, adminStorage := newTenantDeleteFixture(t, tenant)

	adminStorage.DeleteTenantMock.Optional().Set(func(ctx context.Context, id uuid.UUID) error {
		t.Error("the system tenant must never reach the storage delete")
		return nil
	})

	// Even a correct confirmation from another tenant's session must not succeed.
	err := svc.DeleteTenant(context.Background(), port.DeleteTenantCommand{
		TenantID:       tenant.ID,
		Confirmation:   tenant.Domain,
		ActingTenantID: uuid.New(),
	})
	assert.ErrorIs(t, err, port.ErrSystemManaged)
}

func TestTenantService_DeleteTenant_RequiresTypedConfirmation(t *testing.T) {
	tests := []struct {
		name         string
		confirmation string
	}{
		{name: "empty", confirmation: ""},
		{name: "tenant name instead of domain", confirmation: "Customer Tenant"},
		{name: "wrong case", confirmation: "Customer.Example.COM"},
		{name: "with whitespace", confirmation: " customer.example.com "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant := &model.Tenant{ID: uuid.New(), Name: "Customer Tenant", Domain: "customer.example.com"}
			svc, adminStorage := newTenantDeleteFixture(t, tenant)

			adminStorage.DeleteTenantMock.Optional().Set(func(ctx context.Context, id uuid.UUID) error {
				t.Error("a wrong confirmation must not delete anything")
				return nil
			})

			err := svc.DeleteTenant(context.Background(), port.DeleteTenantCommand{
				TenantID:       tenant.ID,
				Confirmation:   tt.confirmation,
				ActingTenantID: uuid.New(),
			})

			var verr *port.ValidationError
			require.ErrorAs(t, err, &verr)
			assert.Contains(t, verr.Fields, "confirmation")
		})
	}
}

func TestTenantService_DeleteTenant_CannotDeleteActingTenant(t *testing.T) {
	tenant := &model.Tenant{ID: uuid.New(), Name: "Customer Tenant", Domain: "customer.example.com"}
	svc, adminStorage := newTenantDeleteFixture(t, tenant)

	adminStorage.DeleteTenantMock.Optional().Set(func(ctx context.Context, id uuid.UUID) error {
		t.Error("the acting tenant must not be deleted")
		return nil
	})

	err := svc.DeleteTenant(context.Background(), port.DeleteTenantCommand{
		TenantID:       tenant.ID,
		Confirmation:   tenant.Domain,
		ActingTenantID: tenant.ID,
	})

	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
}

func TestTenantService_DeleteTenant_Success(t *testing.T) {
	tenant := &model.Tenant{ID: uuid.New(), Name: "Customer Tenant", Domain: "customer.example.com"}
	svc, adminStorage := newTenantDeleteFixture(t, tenant)

	adminStorage.DeleteTenantMock.Set(func(ctx context.Context, id uuid.UUID) error {
		assert.Equal(t, tenant.ID, id)
		return nil
	})

	err := svc.DeleteTenant(context.Background(), port.DeleteTenantCommand{
		TenantID:       tenant.ID,
		Confirmation:   "customer.example.com",
		ActingTenantID: uuid.New(),
		ActingUserID:   "admin-user",
	})
	require.NoError(t, err)
}

func TestTenantService_DeleteTenant_UnknownTenant(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	clock := portmock.NewMockClock(time.Now())

	storage.ResolveTenantByUUIDMock.Set(func(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
		return nil, port.ErrTenantNotFound
	})
	svc := NewTenantService(storage, adminStorage, clock, nil, "unittest", "admin.example.com")

	err := svc.DeleteTenant(context.Background(), port.DeleteTenantCommand{TenantID: uuid.New()})
	assert.ErrorIs(t, err, port.ErrTenantNotFound)
}
