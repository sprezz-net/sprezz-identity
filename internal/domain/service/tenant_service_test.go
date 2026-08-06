package service

import (
	"context"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestTenantService_CreateTenant(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewTenantService(storage, clock)

	storage.CreateTenantMock.Set(func(ctx context.Context, tenant model.Tenant) error {
		return nil
	})

	storage.CreatePartitionMock.Set(func(ctx context.Context, tenantID uuid.UUID, name, aliasName string) (*model.Partition, error) {
		return &model.Partition{ID: 1, TenantID: tenantID, Name: name, AliasName: aliasName}, nil
	})

	tenant, err := svc.CreateTenant(context.Background(), "My Tenant", "my-tenant.com")
	if err != nil {
		t.Fatal(err)
	}
	if tenant.Name != "My Tenant" || tenant.Domain != "my-tenant.com" {
		t.Error("unexpected tenant attributes")
	}
}

func TestTenantService_GetTenant(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	svc := NewTenantService(storage, portmock.NewMockClock(time.Now()))

	id := uuid.New()
	storage.ResolveTenantByIDMock.Expect(context.Background(), id).Return(&model.Tenant{ID: id, Name: "Hello"}, nil)

	tenant, err := svc.GetTenant(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if tenant.Name != "Hello" {
		t.Error("unexpected tenant name")
	}
}

func TestTenantService_ToggleSignup(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	svc := NewTenantService(storage, portmock.NewMockClock(time.Now()))

	id := uuid.New()
	storage.ResolveTenantByIDMock.Expect(context.Background(), id).Return(&model.Tenant{
		ID:     id,
		Name:   "Hello",
		Config: model.TenantConfig{AllowSignup: false},
	}, nil)
	storage.CreateTenantMock.Set(func(ctx context.Context, tenant model.Tenant) error {
		if !tenant.Config.AllowSignup {
			t.Error("expected allow signup to be toggled to true")
		}
		return nil
	})

	tenant, err := svc.ToggleSignup(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !tenant.Config.AllowSignup {
		t.Error("expected toggled allow signup")
	}
}

func TestTenantService_UpdateTenant(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	svc := NewTenantService(storage, portmock.NewMockClock(time.Now()))

	id := uuid.New()
	storage.ResolveTenantByIDMock.Expect(context.Background(), id).Return(&model.Tenant{ID: id, Name: "Hello"}, nil)
	storage.CreateTenantMock.Set(func(ctx context.Context, tenant model.Tenant) error {
		if tenant.Name != "Updated" {
			t.Errorf("expected updated name, got %s", tenant.Name)
		}
		return nil
	})

	tenant, err := svc.UpdateTenant(context.Background(), id, "Updated", "new-domain.com", model.TenantConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if tenant.Name != "Updated" {
		t.Error("unexpected name after update")
	}
}
