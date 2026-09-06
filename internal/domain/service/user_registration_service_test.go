package service

import (
	"context"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestUserRegistrationService_GetSignupContext_WithSession(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewUserRegistrationService(storage, nil, clock)

	tenantID := uuid.New()
	sessionUUID := uuid.New()
	partitionID := int64(42)

	storage.GetInteractionSessionMock.Expect(minimock.AnyContext, tenantID, sessionUUID).Return(&model.InteractionSession{
		ID:          sessionUUID,
		PartitionID: partitionID,
		ClientID:    "test-client",
	}, nil)

	storage.GetIdentityProvidersByTypeAndPartitionMock.Expect(minimock.AnyContext, tenantID, partitionID, model.UsernamePasswordIDPType).Return([]model.IdentityProvider{
		{
			ID:          uuid.New(),
			IDPType:     model.UsernamePasswordIDPType,
			PartitionID: partitionID,
			Enabled:     true,
			Alias:       "local-login",
		},
	}, nil)

	cmd := port.GetSignupContextCommand{
		TenantID:       tenantID,
		InteractionID:  sessionUUID.String(),
		ConsumeSession: false,
	}

	resp, err := svc.GetSignupContext(context.Background(), cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Provider == nil {
		t.Fatal("expected provider to be returned")
	}
	if resp.Provider.Alias != "local-login" {
		t.Errorf("expected provider alias 'local-login', got %s", resp.Provider.Alias)
	}
}

func TestUserRegistrationService_GetSignupContext_DirectAccessFallback(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewUserRegistrationService(storage, nil, clock)

	tenantID := uuid.New()
	defaultPartID := int64(100)

	// Direct access (empty interactionID) triggers ResolveTenantByUUID lookup
	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantID).Return(&model.Tenant{
		ID:               tenantID,
		DefaultPartition: &defaultPartID,
	}, nil)

	// Should fetch providers under default partition (100)
	storage.GetIdentityProvidersByTypeAndPartitionMock.Expect(minimock.AnyContext, tenantID, defaultPartID, model.UsernamePasswordIDPType).Return(nil, nil)

	// Since partition resolution returns empty, the direct access fallback triggers GetEnabledIdentityProviders
	storage.GetEnabledIdentityProvidersMock.Expect(minimock.AnyContext, tenantID).Return([]model.IdentityProvider{
		{
			ID:          uuid.New(),
			IDPType:     model.UsernamePasswordIDPType,
			PartitionID: defaultPartID,
			Enabled:     true,
			Alias:       "fallback-local-login",
		},
	}, nil)

	cmd := port.GetSignupContextCommand{
		TenantID:       tenantID,
		InteractionID:  "", // Direct access
		ConsumeSession: false,
	}

	resp, err := svc.GetSignupContext(context.Background(), cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Provider == nil {
		t.Fatal("expected fallback provider to be resolved")
	}
	if resp.Provider.Alias != "fallback-local-login" {
		t.Errorf("expected fallback provider alias 'fallback-local-login', got %s", resp.Provider.Alias)
	}
}
