package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestHttpAdapter_Revoke_Success(t *testing.T) {
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

	auth.ProcessTokenRevocationMock.Set(func(ctx context.Context, cmd port.RevokeTokenCommand) error {
		if cmd.ClientID != "test-client" || cmd.TokenString != "token-to-revoke" {
			t.Errorf("unexpected parameters: clientID=%s, token=%s", cmd.ClientID, cmd.TokenString)
		}
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader("client_id=test-client&token=token-to-revoke"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}
