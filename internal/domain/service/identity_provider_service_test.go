package service

import (
	"context"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/alexedwards/argon2id"
	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestVerifyPassword_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	now := time.Now().Truncate(time.Second)
	clock := portmock.NewMockClock(now)
	service := NewIdentityProviderService(storage, nil, clock)

	tenantID := uuid.New()
	userID := uuid.New()
	providerID := uuid.New()

	password := "MySecretPassword1"
	hash, _ := argon2id.CreateHash(password, argon2id.DefaultParams)

	cred := &model.PasswordCredential{
		UserProfileID:           userID,
		IdentityProviderID:      providerID,
		Argon2Hash:              hash,
		FailedVerificationCount: 2,
	}

	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, 0, userID).Return(&model.UserProfile{ID: userID, PartitionID: 1, LifecycleState: model.LifecycleActivated}, nil)
	storage.GetIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{
		{
			ID:          providerID,
			TenantID:    tenantID,
			IDPType:     model.UsernamePasswordIDPType,
			Enabled:     true,
			PartitionID: 1,
			Config: model.IdentityProviderConfig{
				MaxFailedVerificationCount: 3,
				PasswordBlockedTime:        60,
			},
		},
	}, nil)
	storage.GetPasswordCredentialByProfileIDMock.Expect(context.Background(), tenantID, 1, userID, providerID).Return(cred, nil)
	storage.ResetPasswordCountersMock.Expect(context.Background(), tenantID, 1, userID, providerID).Return(nil)

	valid, err := service.VerifyPassword(context.Background(), tenantID, userID, password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected true, got false")
	}
}

func TestVerifyPassword_FailureAndBlocking(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	now := time.Now().Truncate(time.Second)
	clock := portmock.NewMockClock(now)
	service := NewIdentityProviderService(storage, nil, clock)

	tenantID := uuid.New()
	userID := uuid.New()
	providerID := uuid.New()

	password := "MySecretPassword1"
	hash, _ := argon2id.CreateHash(password, argon2id.DefaultParams)

	cred := &model.PasswordCredential{
		UserProfileID:           userID,
		IdentityProviderID:      providerID,
		Argon2Hash:              hash,
		FailedVerificationCount: 2, // Next failure should block
	}

	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, 0, userID).Return(&model.UserProfile{ID: userID, PartitionID: 1, LifecycleState: model.LifecycleActivated}, nil)
	storage.GetIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{
		{
			ID:          providerID,
			TenantID:    tenantID,
			IDPType:     model.UsernamePasswordIDPType,
			Enabled:     true,
			PartitionID: 1,
			Config: model.IdentityProviderConfig{
				MaxFailedVerificationCount: 3,
				PasswordBlockedTime:        60,
			},
		},
	}, nil)
	storage.GetPasswordCredentialByProfileIDMock.Expect(context.Background(), tenantID, 1, userID, providerID).Return(cred, nil)

	blockedTime := now.Add(60 * time.Second)
	storage.UpdatePasswordLockoutStateMock.Expect(context.Background(), tenantID, 1, userID, providerID, 3, &now, &blockedTime).Return(nil)

	valid, err := service.VerifyPassword(context.Background(), tenantID, userID, "WrongPassword")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected false, got true")
	}
}

func TestVerifyPassword_Blocked_RejectsWithinBlockedTime(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	now := time.Now().Truncate(time.Second)
	clock := portmock.NewMockClock(now)
	service := NewIdentityProviderService(storage, nil, clock)

	tenantID := uuid.New()
	userID := uuid.New()
	providerID := uuid.New()

	blockedUntil := now.Add(30 * time.Second)
	cred := &model.PasswordCredential{
		UserProfileID:           userID,
		IdentityProviderID:      providerID,
		BlockedUntil:            &blockedUntil,
		FailedVerificationCount: 3,
	}

	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, 0, userID).Return(&model.UserProfile{ID: userID, PartitionID: 1, LifecycleState: model.LifecycleActivated}, nil)
	storage.GetIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{
		{
			ID:          providerID,
			TenantID:    tenantID,
			IDPType:     model.UsernamePasswordIDPType,
			Enabled:     true,
			PartitionID: 1,
			Config: model.IdentityProviderConfig{
				MaxFailedVerificationCount: 3,
				PasswordBlockedTime:        60,
			},
		},
	}, nil)
	storage.GetPasswordCredentialByProfileIDMock.Expect(context.Background(), tenantID, 1, userID, providerID).Return(cred, nil)

	valid, err := service.VerifyPassword(context.Background(), tenantID, userID, "MySecretPassword1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected false (blocked), got true")
	}
}

func TestVerifyPassword_Blocked_Expires_UnblocksWithCorrectPassword(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	now := time.Now().Truncate(time.Second)
	clock := portmock.NewMockClock(now)
	service := NewIdentityProviderService(storage, nil, clock)

	tenantID := uuid.New()
	userID := uuid.New()
	providerID := uuid.New()

	password := "MySecretPassword1"
	hash, _ := argon2id.CreateHash(password, argon2id.DefaultParams)

	blockedUntil := now.Add(-30 * time.Second) // expired 30s ago
	cred := &model.PasswordCredential{
		UserProfileID:           userID,
		IdentityProviderID:      providerID,
		BlockedUntil:            &blockedUntil,
		FailedVerificationCount: 3,
		Argon2Hash:              hash,
	}

	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, 0, userID).Return(&model.UserProfile{ID: userID, PartitionID: 1, LifecycleState: model.LifecycleActivated}, nil)
	storage.GetIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{
		{
			ID:          providerID,
			TenantID:    tenantID,
			IDPType:     model.UsernamePasswordIDPType,
			Enabled:     true,
			PartitionID: 1,
			Config: model.IdentityProviderConfig{
				MaxFailedVerificationCount: 3,
				PasswordBlockedTime:        60,
			},
		},
	}, nil)
	storage.GetPasswordCredentialByProfileIDMock.Expect(context.Background(), tenantID, 1, userID, providerID).Return(cred, nil)
	storage.ResetPasswordCountersMock.Expect(context.Background(), tenantID, 1, userID, providerID).Return(nil)

	valid, err := service.VerifyPassword(context.Background(), tenantID, userID, password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected true, got false")
	}
}
