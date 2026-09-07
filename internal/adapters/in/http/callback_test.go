package http

import (
	"context"
	"errors"
	"fmt"
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
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

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

	suc.BuildSessionCookieMock.Set(func(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
		expectedPayload := fmt.Sprintf("%s:123", userProfileUUID.String())
		if cmd.PayloadValue != expectedPayload {
			t.Errorf("expected session cookie payload '%s', got '%s'", expectedPayload, cmd.PayloadValue)
		}
		return &port.CookieIntentResponse{
			CookieName:  "spz_session",
			CookieValue: "cookie-val-123",
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
}

func TestHttpAdapter_HandleFederationCallback_Error(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, _, _, tuc, fuc, _, _, _ := setupTestEnv(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

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
