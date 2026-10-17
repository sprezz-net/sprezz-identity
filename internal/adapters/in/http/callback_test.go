package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestHttpAdapter_HandleFederationCallback_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, _, _, tuc, fuc, suc, _, _ := setupTestEnv(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", IsActive: true}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	userProfileUUID := uuid.New()
	fuc.ExecuteFederatedCallbackMock.Set(func(ctx context.Context, cmd port.FederatedCallbackCommand) (*port.FederatedCallbackResponse, error) {
		if cmd.IncomingState != "mock-state" || cmd.IncomingCode != "mock-code" {
			t.Errorf("unexpected command parameters")
		}
		return &port.FederatedCallbackResponse{
			UserProfileID:       userProfileUUID,
			PartitionID:         123,
			UpstreamAccessToken: "access-123",
			TargetLandingURI:    "https://test.com/dashboard",
		}, nil
	})

	suc.CreateSessionMock.Set(func(ctx context.Context, cmd port.CreateSessionCommand) (*port.CreatedSession, error) {
		if cmd.UserProfileID != userProfileUUID || cmd.PartitionID != 123 || cmd.TenantID != tenantID {
			t.Errorf("expected a session for the federated user in partition 123, got %+v", cmd)
		}
		return &port.CreatedSession{
			Session: model.SSOSession{ID: uuid.New(), TenantID: tenantID, PartitionID: 123, UserProfileID: userProfileUUID},
			Cookie:  port.CookieIntentResponse{CookieName: "spz_session", CookieValue: "opaque-secret", MaxAge: 86400},
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, port.RouteFederationCallback+"?state=mock-state&code=mock-code", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if loc != "https://test.com/dashboard" {
		t.Fatalf("expected redirect to dashboard, got %s", loc)
	}

	found := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "spz_session" && c.Value == "opaque-secret" && c.HttpOnly {
			found = true
		}
	}
	if !found {
		t.Error("expected the opaque session cookie to be set HttpOnly")
	}
}

func TestHttpAdapter_HandleFederationCallback_Error(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, _, _, tuc, fuc, _, _, _ := setupTestEnv(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com", IsActive: true}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	fuc.ExecuteFederatedCallbackMock.Set(func(ctx context.Context, cmd port.FederatedCallbackCommand) (*port.FederatedCallbackResponse, error) {
		return nil, errors.New("invalid state token exchange")
	})

	req := httptest.NewRequest(http.MethodGet, port.RouteFederationCallback+"?state=bad-state&code=bad-code", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden, got %d", rec.Code)
	}
}
