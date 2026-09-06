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

func TestSSOSessionService_BuildSessionCookie_ExplicitPartition(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	svc := NewSSOSessionService(storage, "local")

	tenantID := uuid.New()
	partitionID := int64(42)

	storage.GetPartitionByIDMock.Expect(minimock.AnyContext, tenantID, partitionID).Return(&model.Partition{
		ID:        partitionID,
		Name:      "test-partition",
		AliasName: "test_part",
	}, nil)

	cmd := port.CookieIntentCommand{
		TenantID:       tenantID,
		PartitionID:    partitionID,
		LifecycleStage: "handshake",
		PayloadValue:   "some-state-token",
		RequestHost:    "localhost",
	}

	resp, err := svc.BuildSessionCookie(context.Background(), cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.CookieName != "spz_session_test_part" {
		t.Errorf("expected cookie name 'spz_session_test_part', got '%s'", resp.CookieName)
	}
	if resp.CookieValue != "handshake:some-state-token" {
		t.Errorf("expected cookie value 'handshake:some-state-token', got '%s'", resp.CookieValue)
	}
	if resp.Secure {
		t.Error("expected Secure to be false for localhost in local env")
	}
}

func TestSSOSessionService_BuildSessionCookie_ZeroPartition_Fallback(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	svc := NewSSOSessionService(storage, "production")

	tenantID := uuid.New()
	defaultPartID := int64(100)

	// Mock resolve tenant to get default partition ID 100
	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantID).Return(&model.Tenant{
		ID:               tenantID,
		DefaultPartition: &defaultPartID,
	}, nil)

	// Mock partition resolution with partition ID 100
	storage.GetPartitionByIDMock.Expect(minimock.AnyContext, tenantID, defaultPartID).Return(&model.Partition{
		ID:        defaultPartID,
		Name:      "default-partition",
		AliasName: "default",
	}, nil)

	cmd := port.CookieIntentCommand{
		TenantID:       tenantID,
		PartitionID:    0, // Trigger fallback
		LifecycleStage: "bearer",
		PayloadValue:   "some-session-token",
		RequestHost:    "login.sprezz.com",
	}

	resp, err := svc.BuildSessionCookie(context.Background(), cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// In production, cookie gets __Host- prefix
	if resp.CookieName != "__Host-spz_session_default" {
		t.Errorf("expected cookie name '__Host-spz_session_default', got '%s'", resp.CookieName)
	}
	if resp.CookieValue != "bearer:some-session-token" {
		t.Errorf("expected cookie value 'bearer:some-session-token', got '%s'", resp.CookieValue)
	}
	if !resp.Secure {
		t.Error("expected Secure to be true in production env")
	}
}

func TestSSOSessionService_ParseSessionCookie(t *testing.T) {
	svc := NewSSOSessionService(nil, "local")

	tests := []struct {
		name          string
		cookieValue   string
		expectedStage string
		expectedPay   string
		expectErr     bool
	}{
		{
			name:          "Valid handshake",
			cookieValue:   "handshake:my-payload",
			expectedStage: "handshake",
			expectedPay:   "my-payload",
			expectErr:     false,
		},
		{
			name:          "Valid bearer",
			cookieValue:   "bearer:user-token-abc",
			expectedStage: "bearer",
			expectedPay:   "user-token-abc",
			expectErr:     false,
		},
		{
			name:        "Empty cookie",
			cookieValue: "",
			expectErr:   true,
		},
		{
			name:        "No separator",
			cookieValue: "invalidcookievalue",
			expectErr:   true,
		},
		{
			name:        "Invalid lifecycle stage",
			cookieValue: "unknown:payload",
			expectErr:   true,
		},
		{
			name:        "Empty payload",
			cookieValue: "bearer:",
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stage, payload, err := svc.ParseSessionCookie(context.Background(), tt.cookieValue)
			if (err != nil) != tt.expectErr {
				t.Fatalf("unexpected error presence: %v", err)
			}
			if !tt.expectErr {
				if stage != tt.expectedStage {
					t.Errorf("expected stage %q, got %q", tt.expectedStage, stage)
				}
				if payload != tt.expectedPay {
					t.Errorf("expected payload %q, got %q", tt.expectedPay, payload)
				}
			}
		})
	}
}
