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

func TestLocalAuthService_GetLoginContext_InteractionSessionZeroPartition_Fallback(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	now := time.Now()
	clock := portmock.NewMockClock(now)

	svc := NewLocalAuthService(storage, crypto, clock)

	tenantUUID := uuid.New()
	defaultPartitionID := int64(42)
	interactionID := uuid.New()
	clientUUID := uuid.New()
	groupUUID := uuid.New()

	// 1. Resolve Tenant Context
	storage.ResolveTenantByUUIDMock.Expect(minimock.AnyContext, tenantUUID).Return(&model.Tenant{
		ID:               tenantUUID,
		DefaultPartition: &defaultPartitionID,
		Config: model.TenantConfig{
			AllowSignup: false,
		},
	}, nil)

	// 2. Fetch enabled providers
	storage.GetEnabledIdentityProvidersMock.Expect(minimock.AnyContext, tenantUUID).Return([]model.IdentityProvider{
		{
			ID:          uuid.New(),
			TenantID:    tenantUUID,
			IDPType:     model.UsernamePasswordIDPType,
			PartitionID: defaultPartitionID,
			Enabled:     true,
			Alias:       "username-password",
		},
	}, nil)

	// 3. Resolve Interaction Session (with PartitionID = 0)
	storage.GetInteractionSessionMock.Expect(minimock.AnyContext, tenantUUID, interactionID).Return(&model.InteractionSession{
		ID:          interactionID,
		TenantID:    tenantUUID,
		ClientID:    "test_client",
		PartitionID: 0, // This is 0, mimicking our database condition!
	}, nil)

	// 4. Resolve application and group
	storage.GetApplicationByClientIDMock.Expect(minimock.AnyContext, tenantUUID, "test_client").Return(&model.Application{
		ID: clientUUID,
	}, &model.ApplicationProfile{}, &model.ApplicationGroup{
		ID:            groupUUID,
		AllowedIDPIDs: []uuid.UUID{uuid.New()},
	}, nil)

	// 5. Get identity providers by UUIDs for the group
	storage.GetIdentityProvidersByUUIDsMock.Set(func(ctx context.Context, tenantID uuid.UUID, uuids []uuid.UUID) ([]model.IdentityProvider, error) {
		return []model.IdentityProvider{
			{
				ID:          uuids[0],
				TenantID:    tenantID,
				IDPType:     model.UsernamePasswordIDPType,
				PartitionID: defaultPartitionID,
				Enabled:     true,
				Alias:       "username-password",
			},
		}, nil
	})

	cmd := port.GetLoginContextCommand{
		TenantID:      tenantUUID,
		InteractionID: interactionID.String(),
	}

	resp, err := svc.GetLoginContext(context.Background(), cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// ASSERTION: The partition ID must fallback to the tenant default partition ID (42) and NOT be overwritten by the session's 0!
	if resp.PartitionID != defaultPartitionID {
		t.Errorf("expected partition ID %d, got %d", defaultPartitionID, resp.PartitionID)
	}
}
