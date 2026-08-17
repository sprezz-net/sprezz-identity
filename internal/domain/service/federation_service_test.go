package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/google/uuid"
)

func TestBuildOutboundOidcIntent(t *testing.T) {
	tenantID := uuid.New()
	providerID := uuid.New()
	fixedTime := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	clock := portmock.NewMockClock(fixedTime) // Aligned with your MockClock helper

	tests := []struct {
		name        string
		request     model.OutboundOidcRequest
		setupMock   func(m *portmock.StorageMock)
		expectError bool
	}{
		{
			name: "Successful Standard Outbound Generation with Absolute TargetURI",
			request: model.OutboundOidcRequest{
				ClientID:    "admin_ui",
				RedirectURI: "https://sprezz.local",
				TargetURI:   "https://sprezz.local", // Aligned with TargetURI
				IdentityProvider: &model.IdentityProvider{
					ID:       providerID,
					TenantID: tenantID,
					Config: model.IdentityProviderConfig{
						AuthorizationEndpoint: "https://idp.com",
						PkceEnabled:           true,
						ParEnabled:            false,
						Scopes:                []string{"openid", "profile"},
					},
				},
			},
			setupMock: func(m *portmock.StorageMock) {
				// Verify handshake data gets persisted to DB securely
				m.SaveOutboundHandshakeMock.Set(func(ctx context.Context, session model.OutboundHandshakeSession) error {
					if session.TargetURI != "https://sprezz.local" {
						return errors.New("mock: invalid TargetURI persisted")
					}
					return nil
				})
			},
			expectError: false,
		},
		{
			name: "Fails When Upstream Identity Provider Context Is Missing",
			request: model.OutboundOidcRequest{
				ClientID:         "admin_ui",
				RedirectURI:      "https://sprezz.local",
				TargetURI:        "https://sprezz.local",
				IdentityProvider: nil,
			},
			setupMock:   func(m *portmock.StorageMock) {},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storageMock := portmock.NewStorageMock(t) // Minimock standard initialization
			tt.setupMock(storageMock)

			svc := NewOAuthService(storageMock, nil, nil, nil, clock)
			intent, handshake, err := svc.BuildOutboundOidcIntent(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected tracking validation failure but code execution path returned green")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected calculation failure: %v", err)
			}

			if intent.AuthURL == "" || intent.State == "" {
				t.Errorf("failed to populate non-sensitive public transport parameters cleanly")
			}

			if handshake.TargetURI != tt.request.TargetURI {
				t.Errorf("handshake mismatch: expected TargetURI %s, got %s", tt.request.TargetURI, handshake.TargetURI)
			}
		})
	}
}

func TestValidateOutboundCallback(t *testing.T) {
	tenantID := uuid.New()
	fixedTime := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	clock := portmock.NewMockClock(fixedTime) // Aligned with your MockClock helper

	tests := []struct {
		name          string
		incomingState string
		setupMock     func(m *portmock.StorageMock)
		expectError   bool
	}{
		{
			name:          "Successful Handshake Verification and Deletion",
			incomingState: "valid-state-string",
			setupMock: func(m *portmock.StorageMock) {
				// Set behavior using your generated Minimock signature
				m.GetAndConsumeOutboundHandshakeMock.Expect(context.Background(), tenantID, "valid-state-string").Return(&model.OutboundHandshakeSession{
					ID:        "valid-state-string",
					TenantID:  tenantID,
					TargetURI: "https://sprezz.local",
					ExpiresAt: fixedTime.Add(2 * time.Minute),
				}, nil)
			},
			expectError: false,
		},
		{
			name:          "Fails When Outbound Redirection Lifespan Has Expired",
			incomingState: "expired-state-string",
			setupMock: func(m *portmock.StorageMock) {
				m.GetAndConsumeOutboundHandshakeMock.Expect(context.Background(), tenantID, "expired-state-string").Return(&model.OutboundHandshakeSession{
					ID:        "expired-state-string",
					TenantID:  tenantID,
					ExpiresAt: fixedTime.Add(-5 * time.Second), // Expired!
				}, nil)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storageMock := portmock.NewStorageMock(t) // Minimock standard initialization
			tt.setupMock(storageMock)

			svc := NewOAuthService(storageMock, nil, nil, nil, clock)
			handshake, err := svc.ValidateOutboundCallback(context.Background(), tenantID, tt.incomingState)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected structural callback rejection error path but returned nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected validation trace engine failure: %v", err)
			}

			if handshake == nil || handshake.TargetURI == "" {
				t.Errorf("handshake output lacks appropriate tracking parameters")
			}
		})
	}
}
