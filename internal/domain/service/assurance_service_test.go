package service

import (
	"context"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestAssuranceService_AssertActionTrust_Success(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	svc := NewAssuranceService(storage)

	tenantUUID := uuid.New()
	providerUUID := uuid.New()

	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(&model.Tenant{
		ID: tenantUUID,
		Config: model.TenantConfig{
			ACRToLevels: map[string]model.Levels{
				"aal1": {AAL: 1},
			},
		},
	}, nil)

	storage.GetIdentityProvidersMock.Expect(minimock.AnyContext, tenantUUID).Return([]model.IdentityProvider{
		{
			ID:      providerUUID,
			Enabled: true,
			Config: model.IdentityProviderConfig{
				AAL: 1,
				IAL: 1,
			},
		},
	}, nil)

	cmd := port.SecurityAccessAssertion{
		TenantID:     tenantUUID,
		ProviderID:   providerUUID,
		TargetAction: "profile_view",
	}

	err := svc.AssertActionTrust(context.Background(), cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAssuranceService_AssertActionTrust_InsufficientAAL(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	svc := NewAssuranceService(storage)

	tenantUUID := uuid.New()
	providerUUID := uuid.New()

	// Tenant config requires high AAL for password change (e.g. AAL 2)
	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(&model.Tenant{
		ID: tenantUUID,
		Config: model.TenantConfig{
			PasswordAAL: 2,
		},
	}, nil)

	storage.GetIdentityProvidersMock.Expect(minimock.AnyContext, tenantUUID).Return([]model.IdentityProvider{
		{
			ID:      providerUUID,
			Enabled: true,
			Config: model.IdentityProviderConfig{
				AAL: 1, // High security action requires AAL 2 but provider only has 1
				IAL: 1,
			},
		},
	}, nil)

	cmd := port.SecurityAccessAssertion{
		TenantID:     tenantUUID,
		ProviderID:   providerUUID,
		TargetAction: "change_password",
	}

	err := svc.AssertActionTrust(context.Background(), cmd)
	if err == nil {
		t.Fatal("expected error regarding insufficient AAL level, got nil")
	}
}
