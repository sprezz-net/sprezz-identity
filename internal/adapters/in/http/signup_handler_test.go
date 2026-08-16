package http

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sprezz-identity/internal/adapters/out/clock"
	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestHttpAdapter_SignUpForm_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}
	provider := &model.IdentityProvider{
		ID:       uuid.New(),
		TenantID: tenantID,
		IDPType:  model.UsernamePasswordIDPType,
		Enabled:  true,
		Config: model.IdentityProviderConfig{
			UsernameField: "preferredUsername",
		},
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetIdentityProviderByTypeMock.Expect(minimock.AnyContext, tenantID, model.UsernamePasswordIDPType).Return(provider, nil)

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "<form") {
		t.Fatalf("expected response body to contain sign-up form")
	}
}

func TestHttpAdapter_SignUpForm_Forbidden(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetIdentityProviderByTypeMock.Expect(minimock.AnyContext, tenantID, model.UsernamePasswordIDPType).Return(nil, fmt.Errorf("not configured"))

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	req := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
}

func TestHttpAdapter_SignUpSubmit_PasswordsMismatch(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)

	tenantID := uuid.New()
	tenant := &model.Tenant{ID: tenantID, Domain: "test.com"}
	provider := &model.IdentityProvider{
		ID:       uuid.New(),
		TenantID: tenantID,
		IDPType:  model.UsernamePasswordIDPType,
		Enabled:  true,
		Config: model.IdentityProviderConfig{
			UsernameField: "preferredUsername",
		},
	}

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return tenant, nil
	})
	storage.GetIdentityProviderByTypeMock.Expect(minimock.AnyContext, tenantID, model.UsernamePasswordIDPType).Return(provider, nil)

	adapter := NewHttpAdapter(auth, storage, crypto, clock.NewSystemClock(), "unittest", "admin-domain.com")

	body := "name=Test+User&username=testuser&email=test@test.com&password=Password123&confirm_password=different"
	req := httptest.NewRequest(http.MethodPost, "/sign-up", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "test.com"
	rec := httptest.NewRecorder()

	adapter.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "passwords do not match") {
		t.Fatalf("expected error message in output, got: %s", rec.Body.String())
	}
}
