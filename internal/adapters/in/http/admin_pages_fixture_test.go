package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

// pagesFixture is an adapter with a valid admin session and mocked application and identity provider use cases.
type pagesFixture struct {
	t        *testing.T
	adapter  *HttpAdapter
	apps     *portmock.AdminApplicationUseCaseMock
	idps     *portmock.IdentityProviderUseCaseMock
	storage  *portmock.StorageMock
	tenant   *model.Tenant
	tenantID uuid.UUID
	userID   uuid.UUID
}

func newPagesFixture(t *testing.T) *pagesFixture {
	t.Helper()
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	tuc := portmock.NewTenantUseCaseMock(ctrl)
	sso := portmock.NewSSOSessionUseCaseMock(ctrl)
	apps := portmock.NewAdminApplicationUseCaseMock(ctrl)
	idps := portmock.NewIdentityProviderUseCaseMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: testAdminHost, Name: "Administrative Tenant", IsSystem: true, Scheme: "http"}
	userID := uuid.New()

	tuc.ResolveTenantContextMock.Optional().Set(func(ctx context.Context, host string) (*model.Tenant, error) { return tenant, nil })
	storage.GetPartitionByAliasMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, alias string) (*model.Partition, error) {
		return &model.Partition{ID: testAdminPartition, TenantID: tID, AliasName: alias}, nil
	})
	sso.BuildSessionCookieMock.Optional().Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: testAdminCookieName}, nil
	})
	sso.ParseSessionCookieMock.Optional().Set(func(ctx context.Context, value string) (string, string, error) {
		stage, payload, _ := strings.Cut(value, ":")
		return stage, payload, nil
	})
	storage.GetUserProfileByIDAndPartitionAliasMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, alias string, id uuid.UUID) (*model.UserProfile, error) {
		return &model.UserProfile{ID: userID, TenantID: tID, PartitionID: testAdminPartition, LifecycleState: model.LifecycleActivated}, nil
	})

	adapter := NewHttpAdapter(tuc, portmock.NewAuthUseCaseMock(ctrl), portmock.NewFederatedLoginUseCaseMock(ctrl), nil, sso,
		portmock.NewUserProfileUseCaseMock(ctrl), portmock.NewUserRegistrationUseCaseMock(ctrl), portmock.NewLocalAuthUseCaseMock(ctrl),
		apps, nil, idps, storage, portmock.NewCryptoMock(ctrl), "unittest", testAdminHost)

	return &pagesFixture{t: t, adapter: adapter, apps: apps, idps: idps, storage: storage, tenant: tenant, tenantID: tenantID, userID: userID}
}

// do issues a request carrying a valid admin session. Extra headers and a form body are optional.
func (f *pagesFixture) do(method, path string, form url.Values, headers map[string]string) *httptest.ResponseRecorder {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Host = testAdminHost
	req.AddCookie(&http.Cookie{Name: testAdminCookieName, Value: fmt.Sprintf("bearer:%s:%d", f.userID, testAdminPartition)})
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.adapter.Router().ServeHTTP(rec, req)
	return rec
}

// htmx marks a request as an htmx navigation, which receives fragments instead of full pages.
func htmx() map[string]string {
	return map[string]string{model.HeaderHxRequest: "true"}
}

func (f *pagesFixture) stubDashboard(apps int, groups []model.ApplicationGroup, profiles []model.ApplicationProfile) {
	f.apps.GetApplicationDashboardMock.Optional().Set(func(ctx context.Context, tID uuid.UUID) ([]model.ApplicationSummary, []model.ApplicationProfile, []model.ApplicationGroup, error) {
		return make([]model.ApplicationSummary, apps), profiles, groups, nil
	})
}
