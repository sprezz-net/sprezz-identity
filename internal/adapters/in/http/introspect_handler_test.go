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

func TestHttpAdapter_Introspect_Success(t *testing.T) {
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

	auth.ProcessTokenIntrospectionMock.Set(func(ctx context.Context, cmd port.IntrospectTokenCommand) (*model.IntrospectionResponse, error) {
		return &model.IntrospectionResponse{
			Active:    true,
			ClientID:  cmd.ClientID,
			Subject:   "user-123",
			ExpiresAt: 1234567,
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader("client_id=test-client&token=token-to-introspect"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["active"] != true || resp["sub"] != "user-123" {
		t.Fatalf("unexpected introspection response: %v", resp)
	}
}
