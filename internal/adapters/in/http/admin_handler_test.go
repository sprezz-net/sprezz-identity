package http

import (
	"context"
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

func buildLocalAdminTestAdapter(ctrl *minimock.Controller) (*HttpAdapter, *portmock.AdminLogonUseCaseMock, *portmock.TenantUseCaseMock, *portmock.StorageMock, *portmock.SSOSessionUseCaseMock) {
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthUseCaseMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	aluc := portmock.NewAdminLogonUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)
	lauc := portmock.NewLocalAuthUseCaseMock(ctrl)

	adapter := NewHttpAdapter(tuc, auth, fuc, aluc, suc, upuc, uruc, lauc, nil, nil, nil, storage, crypto, "unittest", "admin-domain.com")
	return adapter, aluc, tuc, storage, suc
}

func TestHttpAdapter_AdminOIDC_Initiation_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, aluc, tuc, storage, suc := buildLocalAdminTestAdapter(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "admin-domain.com", Name: "Administrative Tenant", Scheme: "http", IsActive: true}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	storage.GetPartitionByAliasMock.Expect(minimock.AnyContext, tenantID, model.AdminPartitionAliasName).Return(&model.Partition{
		ID:        1,
		TenantID:  tenantID,
		Name:      "Sprezz Admin",
		AliasName: model.AdminPartitionAliasName,
	}, nil)

	suc.BuildSessionCookieMock.Optional().Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		return &port.CookieIntentResponse{CookieName: "spz_session_" + model.AdminPartitionAliasName}, nil
	})
	pendingAdminFlow := model.SSOSession{ID: uuid.New(), TenantID: tenantID, PartitionID: 1, State: model.SSOSessionPending}
	suc.StartFlowMock.Set(func(ctx context.Context, cmd port.StartFlowCommand) (*port.StartedFlow, error) {
		if cmd.TenantID != tenantID || cmd.PartitionID != 1 {
			t.Errorf("the admin sign-in starts in the administrative partition, got %+v", cmd)
		}
		return &port.StartedFlow{
			Session: pendingAdminFlow,
			Cookie:  &port.CookieIntentResponse{CookieName: "spz_session_" + model.AdminPartitionAliasName, CookieValue: "pending-secret", MaxAge: 900},
		}, nil
	})

	aluc.InitiateAdminLogonMock.Expect(minimock.AnyContext, tenantID, pendingAdminFlow.ID, "http://admin-domain.com/oauth/federation/callback", "http://admin-domain.com/admin").Return(&port.InitiateFederatedLoginResponse{
		TargetRedirectURL: "https://admin.com/oauth/authorize?client_id=registered-client-id",
		StateToken:        "test-state-token",
	}, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Host = "admin-domain.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	if location != "https://admin.com/oauth/authorize?client_id=registered-client-id" {
		t.Errorf("expected redirect location, got %s", location)
	}

	var pending *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "spz_session_"+model.AdminPartitionAliasName && c.Value != "" {
			pending = c
		}
	}
	if pending == nil || pending.Value != "pending-secret" || !pending.HttpOnly || pending.MaxAge != 900 {
		t.Errorf("expected the pending session cookie to be set HttpOnly for 15 minutes, got %+v", pending)
	}
}

func TestHttpAdapter_AdminDashboard_AuthorizedSession_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, tuc, storage, ssoMock := buildLocalAdminTestAdapter(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "admin-domain.com", Name: "Administrative Tenant", Scheme: "http", IsActive: true}
	userUUID := uuid.New()
	adminPartitionID := int64(12)

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	storage.GetPartitionByAliasMock.Expect(minimock.AnyContext, tenantID, model.AdminPartitionAliasName).Return(&model.Partition{
		ID:        adminPartitionID,
		TenantID:  tenantID,
		Name:      "Sprezz Admin",
		AliasName: model.AdminPartitionAliasName,
	}, nil)

	ssoMock.ResolveSessionMock.Set(func(ctx context.Context, tID uuid.UUID, value string) (*model.SSOSession, error) {
		if value != testSessionSecret || tID != tenantID {
			return nil, port.ErrSessionNotFound
		}
		return &model.SSOSession{ID: uuid.New(), TenantID: tenantID, PartitionID: adminPartitionID, UserProfileID: userUUID}, nil
	})

	ssoMock.BuildSessionCookieMock.Expect(minimock.AnyContext, port.CookieIntentCommand{
		TenantID:       tenantID,
		PartitionID:    adminPartitionID,
		LifecycleStage: "clear",
		RequestHost:    "admin-domain.com",
	}).Return(&port.CookieIntentResponse{
		CookieName: "spz_session_" + model.AdminPartitionAliasName,
	}, nil)

	storage.GetUserProfileByIDAndPartitionAliasMock.Expect(minimock.AnyContext, tenantID, model.AdminPartitionAliasName, userUUID).Return(&model.UserProfile{
		ID:                userUUID,
		TenantID:          tenantID,
		PartitionID:       adminPartitionID,
		Email:             "admin@sprezz.com",
		PreferredUsername: "admin@sprezz.com",
		Name:              "Main Admin",
		LifecycleState:    model.LifecycleActivated,
		Blocked:           false,
	}, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Host = "admin-domain.com"
	req.AddCookie(&http.Cookie{
		Name:  "spz_session_" + model.AdminPartitionAliasName,
		Value: testSessionSecret,
	})
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Administrative Tenant") {
		t.Errorf("expected rendered dashboard to contain tenant name 'Administrative Tenant'")
	}
}
