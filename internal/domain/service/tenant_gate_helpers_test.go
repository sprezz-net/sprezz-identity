package service

import (
	"context"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/google/uuid"
)

// allowTenant makes the storage mock report an active tenant for any lookup, so tests of behaviour that sits behind
// the tenant gate do not have to repeat the stub. Tests of the gate itself stub the tenant explicitly.
func allowTenant(storage *portmock.StorageMock) {
	storage.ResolveTenantByUUIDMock.Optional().Set(func(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
		return &model.Tenant{ID: id, Domain: "test.com", IsActive: true}, nil
	})
}
