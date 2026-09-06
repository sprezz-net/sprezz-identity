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

func TestLocalAuthService_AuthenticateLocalCredentials_Success(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewLocalAuthService(storage, crypto, clock)

	tenantUUID := uuid.New()
	partitionID := int64(1)
	providerUUID := uuid.New()
	userID := uuid.New()
	identityID := uuid.New()

	storage.GetUserIdentityByIdentifierMock.Expect(minimock.AnyContext, tenantUUID, partitionID, providerUUID, "testuser").Return(&model.UserIdentity{
		ID:            identityID,
		UserProfileID: userID,
	}, nil)

	storage.GetIdentityProviderByUUIDMock.Expect(minimock.AnyContext, tenantUUID, providerUUID).Return(&model.IdentityProvider{
		ID:          providerUUID,
		PartitionID: partitionID,
		Enabled:     true,
	}, nil)

	storage.GetPasswordCredentialByProfileIDMock.Expect(minimock.AnyContext, tenantUUID, partitionID, userID, providerUUID).Return(&model.PasswordCredential{
		UserProfileID: userID,
		Argon2Hash:    "real-hash",
	}, nil)

	crypto.CompareCredentialMock.Expect("real-hash", "password123").Return(true, nil)

	storage.GetUserProfileByIDMock.Expect(minimock.AnyContext, tenantUUID, partitionID, userID).Return(&model.UserProfile{
		ID:             userID,
		LifecycleState: model.LifecycleActivated,
	}, nil)

	storage.IncrementUserIdentityLoginTrackerMock.Set(func(ctx context.Context, tenantID uuid.UUID, partitionID int64, identityID uuid.UUID, loginTime time.Time) error {
		return nil
	})

	cmd := port.LocalLoginCommand{
		TenantID:          tenantUUID,
		PartitionID:       partitionID,
		ProviderID:        providerUUID,
		Identifier:        "testuser",
		PlaintextPassword: "password123",
	}

	resp, err := svc.AuthenticateLocalCredentials(context.Background(), cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.UserProfileID != userID {
		t.Errorf("expected user profile ID %s, got %s", userID, resp.UserProfileID)
	}
}

func TestLocalAuthService_AuthenticateLocalCredentials_UserNotFound_TimingAttackMitigation(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewLocalAuthService(storage, crypto, clock)

	tenantUUID := uuid.New()
	partitionID := int64(1)
	providerUUID := uuid.New()

	// Storage returns identity not found error
	storage.GetUserIdentityByIdentifierMock.Expect(minimock.AnyContext, tenantUUID, partitionID, providerUUID, "nonexistent").Return(nil, port.ErrIdentityNotFound)

	// Crypto MUST run CompareCredential with dummy hash to prevent timing attacks
	crypto.CompareCredentialMock.Set(func(hash, pass string) (bool, error) {
		return false, nil
	})

	cmd := port.LocalLoginCommand{
		TenantID:          tenantUUID,
		PartitionID:       partitionID,
		ProviderID:        providerUUID,
		Identifier:        "nonexistent",
		PlaintextPassword: "somepassword",
	}

	_, err := svc.AuthenticateLocalCredentials(context.Background(), cmd)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestLocalAuthService_AuthenticateLocalCredentials_SelfResolve_Success(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewLocalAuthService(storage, crypto, clock)

	tenantUUID := uuid.New()
	partitionID := int64(42)
	providerUUID := uuid.New()
	userID := uuid.New()
	identityID := uuid.New()

	// Mock ResolveTenantByUUID to resolve default partition
	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(&model.Tenant{
		ID:               tenantUUID,
		DefaultPartition: &partitionID,
	}, nil)

	// Mock GetEnabledIdentityProviders to resolve the username-password provider
	storage.GetEnabledIdentityProvidersMock.Expect(minimock.AnyContext, tenantUUID).Return([]model.IdentityProvider{
		{
			ID:          providerUUID,
			TenantID:    tenantUUID,
			IDPType:     model.UsernamePasswordIDPType,
			PartitionID: partitionID,
			Enabled:     true,
		},
	}, nil)

	storage.GetUserIdentityByIdentifierMock.Expect(minimock.AnyContext, tenantUUID, partitionID, providerUUID, "testuser").Return(&model.UserIdentity{
		ID:            identityID,
		UserProfileID: userID,
	}, nil)

	storage.GetIdentityProviderByUUIDMock.Expect(minimock.AnyContext, tenantUUID, providerUUID).Return(&model.IdentityProvider{
		ID:          providerUUID,
		PartitionID: partitionID,
		Enabled:     true,
	}, nil)

	storage.GetPasswordCredentialByProfileIDMock.Expect(minimock.AnyContext, tenantUUID, partitionID, userID, providerUUID).Return(&model.PasswordCredential{
		UserProfileID: userID,
		Argon2Hash:    "real-hash",
	}, nil)

	crypto.CompareCredentialMock.Expect("real-hash", "password123").Return(true, nil)

	storage.GetUserProfileByIDMock.Expect(minimock.AnyContext, tenantUUID, partitionID, userID).Return(&model.UserProfile{
		ID:             userID,
		LifecycleState: model.LifecycleActivated,
	}, nil)

	storage.IncrementUserIdentityLoginTrackerMock.Set(func(ctx context.Context, tenantID uuid.UUID, partitionID int64, identityID uuid.UUID, loginTime time.Time) error {
		return nil
	})

	cmd := port.LocalLoginCommand{
		TenantID:          tenantUUID,
		PartitionID:       0,        // Triggers partition self-resolution!
		ProviderID:        uuid.Nil, // Triggers provider self-resolution!
		Identifier:        "testuser",
		PlaintextPassword: "password123",
	}

	resp, err := svc.AuthenticateLocalCredentials(context.Background(), cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.UserProfileID != userID {
		t.Errorf("expected user profile ID %s, got %s", userID, resp.UserProfileID)
	}
}
