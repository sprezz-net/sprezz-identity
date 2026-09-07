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

func TestHttpAdapter_SignUpForm_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, _, _, tuc, _, suc, _, uruc := setupTestEnv(ctrl)
	mockSessionCookie(suc)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}
	provider := model.IdentityProvider{
		ID:       uuid.New(),
		TenantID: tenantID,
		IDPType:  model.UsernamePasswordIDPType,
		Enabled:  true,
	}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	uruc.GetSignupContextMock.Set(func(ctx context.Context, cmd port.GetSignupContextCommand) (*port.SignupContextResponse, error) {
		return &port.SignupContextResponse{
			Provider: &provider,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, port.RouteWebSignUp, nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}

func TestHttpAdapter_SignUpForm_Forbidden(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, _, _, tuc, _, suc, _, uruc := setupTestEnv(ctrl)
	mockSessionCookie(suc)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	uruc.GetSignupContextMock.Set(func(ctx context.Context, cmd port.GetSignupContextCommand) (*port.SignupContextResponse, error) {
		return &port.SignupContextResponse{}, nil
	})

	req := httptest.NewRequest(http.MethodGet, port.RouteWebSignUp, nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
}

func TestHttpAdapter_SignUpWithTx_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	adapter, _, _, _, tuc, _, _, _, uruc := setupTestEnv(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}
	providerID := uuid.New()
	provider := model.IdentityProvider{
		ID:          providerID,
		TenantID:    tenantID,
		IDPType:     model.UsernamePasswordIDPType,
		Enabled:     true,
		PartitionID: 5,
	}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return tenant, nil
	})

	// EXPECT: GetSignupContext command MUST receive "tx_signup_789"
	uruc.GetSignupContextMock.Set(func(ctx context.Context, cmd port.GetSignupContextCommand) (*port.SignupContextResponse, error) {
		if cmd.InteractionID != "tx_signup_789" {
			t.Errorf("expected InteractionID 'tx_signup_789', got '%s'", cmd.InteractionID)
		}
		return &port.SignupContextResponse{
			Provider: &provider,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, port.RouteWebSignUp+"?tx=tx_signup_789", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, "tx_signup_789") {
		t.Error("expected sign up template to render hidden input with interaction id 'tx_signup_789'")
	}
}
