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
)

type tenantFixture struct {
	svc     *service.AdminTenantService
	storage *portmock.StorageMock
	admin   *portmock.AdminStorageMock
	tenants *portmock.TenantUseCaseMock
	system  model.Tenant
	acme    model.Tenant
	globex  model.Tenant
}

func newTenantFixture(t *testing.T) *tenantFixture {
	t.Helper()
	mc := minimock.NewController(t)
	f := &tenantFixture{
		storage: portmock.NewStorageMock(mc),
		admin:   portmock.NewAdminStorageMock(mc),
		tenants: portmock.NewTenantUseCaseMock(mc),
		system:  model.Tenant{ID: uuid.New(), Name: "Administrative Tenant", Domain: "admin.example.com", IsSystem: true, Scheme: "https"},
		acme:    model.Tenant{ID: uuid.New(), Name: "Acme", Domain: "acme.example.com", Scheme: "https"},
		globex:  model.Tenant{ID: uuid.New(), Name: "Globex", Domain: "globex.example.com", Scheme: "https"},
	}
	f.acme.Config = model.TenantConfig{
		PredefinedScopes: []string{"openid", "profile"}, PredefinedAudiences: []string{"https://api.acme.example"},
		DefaultRedirectURI: "https://acme.example.com/cb", RedirectWhitelist: []string{"https://acme.example.com/cb"},
		AllowSignup: true, DefaultAAL: 2, ACREssential: true, EncryptedAdminSecret: "sealed",
		ACRToLevels: map[string]model.Levels{"gold": {AAL: 3}},
	}
	f.svc = service.NewAdminTenantService(f.storage, f.admin, portmock.NewMockClock(time.Now()), f.tenants)
	f.resolveByID()
	f.admin.GetAllTenantUsageMock.Optional().Return([]model.TenantUsage{{TenantID: f.acme.ID, Users: 5, Applications: 2}}, nil)
	return f
}

func (f *tenantFixture) all() []model.Tenant {
	return []model.Tenant{f.system, f.acme, f.globex}
}

func (f *tenantFixture) resolveByID() {
	f.storage.ResolveTenantByUUIDMock.Optional().Set(func(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
		for _, t := range f.all() {
			if t.ID == id {
				clone := t
				return &clone, nil
			}
		}
		return nil, port.ErrTenantNotFound
	})
}

// captureSave records the tenant written by CreateTenant and fails when nothing may be written.
func (f *tenantFixture) captureSave() *model.Tenant {
	saved := &model.Tenant{}
	f.admin.CreateTenantMock.Optional().Set(func(ctx context.Context, t model.Tenant) error {
		*saved = t
		return nil
	})
	return saved
}

func (f *tenantFixture) forbidSave(t *testing.T) {
	t.Helper()
	f.admin.CreateTenantMock.Optional().Set(func(ctx context.Context, tenant model.Tenant) error {
		t.Error("this change must not be written")
		return nil
	})
}
