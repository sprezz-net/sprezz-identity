package http

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	sessions liveSessions
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
	f := &adminGuardFixture{adapter: adapter, storage: storage, sso: sso, tenantID: tenantID, userID: uuid.New()}
	f.sessions = stubSessions(sso)
	return f
}

// liveSessions maps a cookie value to the live session behind it. A value that is not in the table is not a session.
type liveSessions map[string]*model.SSOSession

// stubSessions makes ResolveSession answer from a table, like the domain does for stored sessions.
func stubSessions(sso *portmock.SSOSessionUseCaseMock) liveSessions {
	sessions := liveSessions{}
	sso.ResolveSessionMock.Optional().Set(func(ctx context.Context, tenantID uuid.UUID, value string) (*model.SSOSession, error) {
		if session, ok := sessions[value]; ok && session.TenantID == tenantID {
			return session, nil
		}
		return nil, port.ErrSessionNotFound
	})
	return sessions
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

// bearer registers a live administrative session for the fixture user and returns the cookie value that carries it.
func (f *adminGuardFixture) bearer() string {
	return f.sessionFor(f.userID, testAdminPartition)
}

// sessionFor registers a live session of a user in a partition and returns its cookie value.
func (f *adminGuardFixture) sessionFor(userID uuid.UUID, partitionID int64) string {
	value := "opaque-" + uuid.NewString()
	f.sessions[value] = &model.SSOSession{ID: uuid.New(), TenantID: f.tenantID, PartitionID: partitionID, UserProfileID: userID}
	return value
}

func (f *adminGuardFixture) stubProfile(profile *model.UserProfile, err error) {
	f.storage.GetUserProfileByIDAndPartitionAliasMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, alias string, id uuid.UUID) (*model.UserProfile, error) {
		return profile, err
	})
}

func (f *adminGuardFixture) activeProfile() *model.UserProfile {
	return &model.UserProfile{ID: f.userID, TenantID: f.tenantID, PartitionID: testAdminPartition, LifecycleState: model.LifecycleActivated}
}
