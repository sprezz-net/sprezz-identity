package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/gojuno/minimock/v3"
)

func TestHttpAdapter_UserInfo_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, auth, _, _, _, _, _, _ := setupTestEnv(ctrl)

	auth.ProcessUserInfoRequestMock.Set(func(ctx context.Context, cmd port.UserInfoRequestCommand) (*model.OIDCTokenClaims, error) {
		if !strings.Contains(cmd.AuthorizationHeader, "token123") {
			t.Errorf("unexpected authorization header: %s", cmd.AuthorizationHeader)
		}
		return &model.OIDCTokenClaims{
			BaseTokenClaims: model.BaseTokenClaims{
				Subject: "user-123",
			},
			Email:             "test@example.com",
			Name:              "Test User",
			PreferredUsername: "testuser",
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer token123")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["sub"] != "user-123" || resp["email"] != "test@example.com" {
		t.Fatalf("unexpected userinfo response: %v", resp)
	}
}

func TestHttpAdapter_UserInfo_Unauthorized(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, auth, _, _, _, _, _, _ := setupTestEnv(ctrl)

	auth.ProcessUserInfoRequestMock.Set(func(ctx context.Context, cmd port.UserInfoRequestCommand) (*model.OIDCTokenClaims, error) {
		return nil, errors.New("invalid signature")
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer badtoken")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}
