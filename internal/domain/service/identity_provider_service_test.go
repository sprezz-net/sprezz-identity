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
	service := NewIdentityProviderService(storage, clock)

	tenantID := uuid.New()
	userID := uuid.New()
	providerID := uuid.New()

	password := "MySecretPassword1"
	hash, _ := argon2id.CreateHash(password, argon2id.DefaultParams)

	identity := &model.UserIdentity{
		ID:                      uuid.New(),
		UserProfileID:           userID,
		IdentityProviderID:      providerID,
		Blocked:                 false,
		FailedVerificationCount: 2,
	}

	cred := &model.PasswordCredential{
		UserProfileID:      userID,
		IdentityProviderID: providerID,
		Argon2Hash:         hash,
	}

	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, userID).Return(&model.UserProfile{ID: userID, PartitionID: 1}, nil)
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
	storage.GetIdentityByProfileAndProviderMock.Expect(context.Background(), userID, providerID).Return(identity, nil)
	storage.GetPasswordCredentialMock.Expect(context.Background(), userID, providerID).Return(cred, nil)

	storage.UpsertIdentityMock.Set(func(ctx context.Context, ident model.UserIdentity) error {
		if ident.FailedVerificationCount != 0 {
			t.Errorf("expected failed verification count to be reset to 0, got %d", ident.FailedVerificationCount)
		}
		if ident.LastVerificationAttemptAt.IsZero() {
			t.Error("expected LastVerificationAttemptAt to be set")
		}
		return nil
	})

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
	service := NewIdentityProviderService(storage, clock)

	tenantID := uuid.New()
	userID := uuid.New()
	providerID := uuid.New()

	password := "MySecretPassword1"
	hash, _ := argon2id.CreateHash(password, argon2id.DefaultParams)

	identity := &model.UserIdentity{
		ID:                      uuid.New(),
		UserProfileID:           userID,
		IdentityProviderID:      providerID,
		Blocked:                 false,
		FailedVerificationCount: 2, // Next failure should block
	}

	cred := &model.PasswordCredential{
		UserProfileID:      userID,
		IdentityProviderID: providerID,
		Argon2Hash:         hash,
	}

	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, userID).Return(&model.UserProfile{ID: userID, PartitionID: 1}, nil)
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
	storage.GetIdentityByProfileAndProviderMock.Expect(context.Background(), userID, providerID).Return(identity, nil)
	storage.GetPasswordCredentialMock.Expect(context.Background(), userID, providerID).Return(cred, nil)

	storage.UpsertIdentityMock.Set(func(ctx context.Context, ident model.UserIdentity) error {
		if ident.FailedVerificationCount != 3 {
			t.Errorf("expected failed verification count to be 3, got %d", ident.FailedVerificationCount)
		}
		if !ident.Blocked {
			t.Error("expected identity to be blocked")
		}
		return nil
	})

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
	service := NewIdentityProviderService(storage, clock)

	tenantID := uuid.New()
	userID := uuid.New()
	providerID := uuid.New()

	identity := &model.UserIdentity{
		ID:                        uuid.New(),
		UserProfileID:             userID,
		IdentityProviderID:        providerID,
		Blocked:                   true,
		FailedVerificationCount:   3,
		LastVerificationAttemptAt: now.Add(-30 * time.Second), // 30s ago < 60s block time
	}

	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, userID).Return(&model.UserProfile{ID: userID, PartitionID: 1}, nil)
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
	storage.GetIdentityByProfileAndProviderMock.Expect(context.Background(), userID, providerID).Return(identity, nil)

	storage.UpsertIdentityMock.Set(func(ctx context.Context, ident model.UserIdentity) error {
		if !ident.LastVerificationAttemptAt.Equal(now) {
			t.Error("expected LastVerificationAttemptAt to be updated to now")
		}
		return nil
	})

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
	service := NewIdentityProviderService(storage, clock)

	tenantID := uuid.New()
	userID := uuid.New()
	providerID := uuid.New()

	password := "MySecretPassword1"
	hash, _ := argon2id.CreateHash(password, argon2id.DefaultParams)

	identity := &model.UserIdentity{
		ID:                        uuid.New(),
		UserProfileID:             userID,
		IdentityProviderID:        providerID,
		Blocked:                   true,
		FailedVerificationCount:   3,
		LastVerificationAttemptAt: now.Add(-90 * time.Second), // 90s ago > 60s block time
	}

	cred := &model.PasswordCredential{
		UserProfileID:      userID,
		IdentityProviderID: providerID,
		Argon2Hash:         hash,
	}

	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, userID).Return(&model.UserProfile{ID: userID, PartitionID: 1}, nil)
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
	storage.GetIdentityByProfileAndProviderMock.Expect(context.Background(), userID, providerID).Return(identity, nil)
	storage.GetPasswordCredentialMock.Expect(context.Background(), userID, providerID).Return(cred, nil)

	storage.UpsertIdentityMock.Set(func(ctx context.Context, ident model.UserIdentity) error {
		if ident.Blocked {
			t.Error("expected identity to be unblocked")
		}
		if ident.FailedVerificationCount != 0 {
			t.Errorf("expected failed count to be reset to 0, got %d", ident.FailedVerificationCount)
		}
		return nil
	})

	valid, err := service.VerifyPassword(context.Background(), tenantID, userID, password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected true, got false")
	}
}

func TestIdentityProviderService_AuthenticateUsernamePassword_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	now := time.Now().Truncate(time.Second)
	clock := portmock.NewMockClock(now)
	service := NewIdentityProviderService(storage, clock)

	tenantID := uuid.New()
	providerID := uuid.New()
	userProfileID := uuid.New()

	password := "SecretPass123!"
	hashedPassword, _ := argon2id.CreateHash(password, argon2id.DefaultParams)

	provider := model.IdentityProvider{
		ID:          providerID,
		TenantID:    tenantID,
		IDPType:     model.UsernamePasswordIDPType,
		Enabled:     true,
		Alias:       "username-password",
		PartitionID: 1,
		Config: model.IdentityProviderConfig{
			UsernameField:              "preferredUsername",
			MaxFailedVerificationCount: 5,
		},
	}

	profile := &model.UserProfile{
		ID:                userProfileID,
		PartitionID:       1,
		PreferredUsername: "john_doe",
	}

	cred := &model.PasswordCredential{
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		Argon2Hash:         hashedPassword,
	}

	identity := &model.UserIdentity{
		ID:                 uuid.New(),
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		LoginCount:         1,
	}

	var defaultPart int64 = 1
	storage.ResolveTenantByIDMock.Expect(context.Background(), tenantID).Return(&model.Tenant{ID: tenantID, DefaultPartition: &defaultPart}, nil)
	storage.GetEnabledIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{provider}, nil)
	storage.GetUserProfileByIdentifierMock.Expect(context.Background(), tenantID, providerID, "john_doe").Return(profile, nil)
	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, userProfileID).Return(profile, nil)
	storage.GetIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{provider}, nil)
	storage.GetIdentityByProfileAndProviderMock.Expect(context.Background(), userProfileID, providerID).Return(identity, nil)
	storage.GetPasswordCredentialMock.Expect(context.Background(), userProfileID, providerID).Return(cred, nil)

	var upserted model.UserIdentity
	storage.UpsertIdentityMock.Set(func(ctx context.Context, ident model.UserIdentity) error {
		upserted = ident
		return nil
	})

	result, err := service.AuthenticateUsernamePassword(context.Background(), tenantID, 0, "john_doe", password)
	if err != nil {
		t.Fatalf("unexpected error during authentication: %v", err)
	}

	if result.UserProfile.ID != userProfileID {
		t.Errorf("expected user profile ID %s, got %s", userProfileID, result.UserProfile.ID)
	}

	if upserted.LoginCount != 2 {
		t.Errorf("expected login count to be incremented to 2, got %d", upserted.LoginCount)
	}
}

func TestIdentityProviderService_AuthenticateUsernamePassword_Failure(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	now := time.Now().Truncate(time.Second)
	clock := portmock.NewMockClock(now)
	service := NewIdentityProviderService(storage, clock)

	tenantID := uuid.New()
	providerID := uuid.New()
	userProfileID := uuid.New()

	hashedPassword, _ := argon2id.CreateHash("SecretPass123!", argon2id.DefaultParams)

	provider := model.IdentityProvider{
		ID:          providerID,
		TenantID:    tenantID,
		IDPType:     model.UsernamePasswordIDPType,
		Enabled:     true,
		Alias:       "username-password",
		PartitionID: 1,
		Config: model.IdentityProviderConfig{
			UsernameField:              "preferredUsername",
			MaxFailedVerificationCount: 5,
		},
	}

	profile := &model.UserProfile{
		ID:                userProfileID,
		PartitionID:       1,
		PreferredUsername: "john_doe",
	}

	cred := &model.PasswordCredential{
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		Argon2Hash:         hashedPassword,
	}

	identity := &model.UserIdentity{
		ID:                 uuid.New(),
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		LoginCount:         1,
	}

	var defaultPart int64 = 1
	storage.ResolveTenantByIDMock.Expect(context.Background(), tenantID).Return(&model.Tenant{ID: tenantID, DefaultPartition: &defaultPart}, nil)
	storage.GetEnabledIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{provider}, nil)
	storage.GetUserProfileByIdentifierMock.Expect(context.Background(), tenantID, providerID, "john_doe").Return(profile, nil)
	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, userProfileID).Return(profile, nil)
	storage.GetIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{provider}, nil)
	storage.GetIdentityByProfileAndProviderMock.Expect(context.Background(), userProfileID, providerID).Return(identity, nil)
	storage.GetPasswordCredentialMock.Expect(context.Background(), userProfileID, providerID).Return(cred, nil)

	storage.UpsertIdentityMock.Return(nil)

	_, err := service.AuthenticateUsernamePassword(context.Background(), tenantID, 0, "john_doe", "WrongPass")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
