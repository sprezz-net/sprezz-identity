package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestHttpAdapter_PAR_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, storage, auth, _, tuc, _, _, _, _ := setupTestEnv(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	storage.GetApplicationByClientIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, clientID string) (*model.Application, *model.ApplicationProfile, *model.ApplicationGroup, error) {
		return &model.Application{ClientID: "test-client"},
			&model.ApplicationProfile{TokenEndpointAuthMethod: model.AuthMethodNone},
			&model.ApplicationGroup{},
			nil
	})

	auth.ProcessPushedAuthorizationMock.Set(func(ctx context.Context, cmd port.PushedAuthCommand) (*port.PushedAuthResponse, error) {
		return &port.PushedAuthResponse{
			RequestURI: "urn:ietf:params:oauth:request_uri:session123",
			ExpiresIn:  300,
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/oauth/par", strings.NewReader("client_id=test-client&redirect_uri=https://test.com/callback&scope=openid"))
	req.Header.Set(model.HeaderContentType, model.ContentTypeFormUrlEncoded)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["request_uri"] != "urn:ietf:params:oauth:request_uri:session123" {
		t.Fatalf("unexpected PAR request URI response: %v", resp)
	}
}
