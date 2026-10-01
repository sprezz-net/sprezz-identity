package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

const (
	testAdminHost       = "admin-domain.com"
	testAdminCookieName = "spz_session_" + model.AdminPartitionAliasName
	testAdminPartition  = int64(12)
)

type adminGuardFixture struct {
	adapter  *HttpAdapter
	storage  *portmock.StorageMock
	sso      *portmock.SSOSessionUseCaseMock
	tenantID uuid.UUID
	userID   uuid.UUID
}

// newAdminGuardFixture wires an adapter whose admin partition and cookie naming resolve normally.
func newAdminGuardFixture(t *testing.T) *adminGuardFixture {
	t.Helper()
	ctrl := minimock.NewController(t)
	adapter, _, tuc, storage, sso := buildLocalAdminTestAdapter(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: testAdminHost, Name: "Administrative Tenant", IsSystem: true, Scheme: "http", IsActive: true}
	tuc.ResolveTenantContextMock.Optional().Set(func(ctx context.Context, host string) (*model.Tenant, error) { return tenant, nil })

	storage.GetPartitionByAliasMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, alias string) (*model.Partition, error) {
		return &model.Partition{ID: testAdminPartition, TenantID: tID, AliasName: alias}, nil
	})
	sso.BuildSessionCookieMock.Optional().Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: testAdminCookieName}, nil
	})
	sso.ParseSessionCookieMock.Optional().Set(func(ctx context.Context, value string) (string, string, error) {
		stage, payload, found := strings.Cut(value, ":")
		if !found {
			return "", "", fmt.Errorf("corrupt cookie")
		}
		return stage, payload, nil
	})

	return &adminGuardFixture{adapter: adapter, storage: storage, sso: sso, tenantID: tenantID, userID: uuid.New()}
}

func (f *adminGuardFixture) do(method, path string, configure func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Host = testAdminHost
	if configure != nil {
		configure(req)
	}
	rec := httptest.NewRecorder()
	f.adapter.Router().ServeHTTP(rec, req)
	return rec
}

func (f *adminGuardFixture) withCookie(value string) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: testAdminCookieName, Value: value}) }
}

func (f *adminGuardFixture) bearer() string {
	return fmt.Sprintf("bearer:%s:%d", f.userID, testAdminPartition)
}

func (f *adminGuardFixture) stubProfile(profile *model.UserProfile, err error) {
	f.storage.GetUserProfileByIDAndPartitionAliasMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, alias string, id uuid.UUID) (*model.UserProfile, error) {
		return profile, err
	})
}

func (f *adminGuardFixture) activeProfile() *model.UserProfile {
	return &model.UserProfile{ID: f.userID, TenantID: f.tenantID, PartitionID: testAdminPartition, LifecycleState: model.LifecycleActivated}
}
