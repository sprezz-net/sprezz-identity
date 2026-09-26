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

func TestUserProfileService_CreateUserProfile(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	adminStorage := portmock.NewAdminStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	clock := portmock.NewMockClock(time.Now())

	svc := NewUserProfileService(storage, adminStorage, crypto, clock)

	tenantID := uuid.New()
	partitionID := int64(1)
	idpID := uuid.New()

	storage.SaveUserProfileMock.Set(func(ctx context.Context, tID uuid.UUID, pID int64, profile model.UserProfile) error {
		if tID != tenantID {
			t.Errorf("expected tenant ID %s, got %s", tenantID, tID)
		}
		if profile.Name != "Alice Smith" {
			t.Errorf("expected name 'Alice Smith', got %q", profile.Name)
		}
		return nil
	})

	crypto.HashCredentialMock.Expect("MySecretPassword").Return("hashed_pw", nil)

	storage.SavePasswordCredentialMock.Set(func(ctx context.Context, cred model.PasswordCredential) error {
		if cred.Argon2Hash != "hashed_pw" {
			t.Errorf("expected hashed password, got %q", cred.Argon2Hash)
		}
		return nil
	})

	storage.UpsertUserIdentityMock.Set(func(ctx context.Context, tID uuid.UUID, pID int64, identity model.UserIdentity) error {
		return nil
	})

	cmd := port.CreateUserProfileCommand{
		TenantID:           tenantID,
		PartitionID:        partitionID,
		IdentityProviderID: idpID,
		Username:           "alice",
		Email:              "alice@example.com",
		EmailVerified:      true,
		FirstName:          "Alice",
		LastName:           "Smith",
		Password:           "MySecretPassword",
		LifecycleState:     model.LifecycleActivated,
		CreatedAt:          time.Now(),
	}

	profile, err := svc.CreateUserProfile(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Name != "Alice Smith" {
		t.Errorf("expected profile name 'Alice Smith', got %q", profile.Name)
	}
}

func TestUserProfileService_ChangeUserPassword(t *testing.T) {
	t.Run("ValidationFailure", func(t *testing.T) {
		svc := NewUserProfileService(nil, nil, nil, nil)
		err := svc.ChangeUserPassword(context.Background(), port.ChangePasswordCommand{
			TenantID:        uuid.New(),
			PartitionID:     1,
			UserProfileID:   uuid.New(),
			CurrentPassword: "",
			NewPassword:     "NewValidPass123",
		})
		if err == nil {
			t.Fatal("expected error for empty current password")
		}

		err = svc.ChangeUserPassword(context.Background(), port.ChangePasswordCommand{
			TenantID:        uuid.New(),
			PartitionID:     1,
			UserProfileID:   uuid.New(),
			CurrentPassword: "pass",
			NewPassword:     string(make([]byte, 65)),
		})
		if err == nil {
			t.Fatal("expected error for new password exceeding 64 chars")
		}
	})

	t.Run("InvalidCurrentPassword", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		crypto := portmock.NewCryptoMock(ctrl)
		clock := portmock.NewMockClock(time.Now())
		svc := NewUserProfileService(storage, nil, crypto, clock)

		tenantID := uuid.New()
		partitionID := int64(1)
		userProfileID := uuid.New()
		idpID := uuid.New()

		storage.GetIdentityProvidersByTypeAndPartitionMock.Expect(minimock.AnyContext, tenantID, partitionID, model.UsernamePasswordIDPType).Return([]model.IdentityProvider{
			{ID: idpID, IDPType: model.UsernamePasswordIDPType},
		}, nil)

		storage.GetPasswordCredentialByProfileIDMock.Expect(minimock.AnyContext, tenantID, partitionID, userProfileID, idpID).Return(&model.PasswordCredential{
			UserProfileID:      userProfileID,
			IdentityProviderID: idpID,
			Argon2Hash:         "existing_hash",
		}, nil)

		crypto.CompareCredentialMock.Expect("existing_hash", "WrongPass").Return(false, nil)

		err := svc.ChangeUserPassword(context.Background(), port.ChangePasswordCommand{
			TenantID:        tenantID,
			PartitionID:     partitionID,
			UserProfileID:   userProfileID,
			CurrentPassword: "WrongPass",
			NewPassword:     "NewPass1234",
		})
		if err == nil {
			t.Fatal("expected error on invalid password")
		}
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		crypto := portmock.NewCryptoMock(ctrl)
		clock := portmock.NewMockClock(time.Now())
		svc := NewUserProfileService(storage, nil, crypto, clock)

		tenantID := uuid.New()
		partitionID := int64(1)
		userProfileID := uuid.New()
		idpID := uuid.New()

		storage.GetIdentityProvidersByTypeAndPartitionMock.Expect(minimock.AnyContext, tenantID, partitionID, model.UsernamePasswordIDPType).Return([]model.IdentityProvider{
			{ID: idpID, IDPType: model.UsernamePasswordIDPType},
		}, nil)

		storage.GetPasswordCredentialByProfileIDMock.Expect(minimock.AnyContext, tenantID, partitionID, userProfileID, idpID).Return(&model.PasswordCredential{
			UserProfileID:      userProfileID,
			IdentityProviderID: idpID,
			Argon2Hash:         "existing_hash",
		}, nil)

		crypto.CompareCredentialMock.Expect("existing_hash", "CorrectPass").Return(true, nil)
		crypto.HashCredentialMock.Expect("NewPass1234").Return("new_argon2_hash", nil)

		storage.SavePasswordCredentialMock.Set(func(ctx context.Context, cred model.PasswordCredential) error {
			if cred.Argon2Hash != "new_argon2_hash" {
				t.Errorf("expected hash 'new_argon2_hash', got %q", cred.Argon2Hash)
			}
			return nil
		})

		err := svc.ChangeUserPassword(context.Background(), port.ChangePasswordCommand{
			TenantID:        tenantID,
			PartitionID:     partitionID,
			UserProfileID:   userProfileID,
			CurrentPassword: "CorrectPass",
			NewPassword:     "NewPass1234",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestUserProfileService_ChangeUserEmail(t *testing.T) {
	t.Run("ValidationFailure", func(t *testing.T) {
		svc := NewUserProfileService(nil, nil, nil, nil)
		err := svc.ChangeUserEmail(context.Background(), port.ChangeEmailCommand{
			TenantID:        uuid.New(),
			PartitionID:     1,
			UserProfileID:   uuid.New(),
			CurrentPassword: "",
			NewEmail:        "",
		})
		if err == nil {
			t.Fatal("expected validation error")
		}
	})

	t.Run("InvalidPassword", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		crypto := portmock.NewCryptoMock(ctrl)
		clock := portmock.NewMockClock(time.Now())
		svc := NewUserProfileService(storage, nil, crypto, clock)

		tenantID := uuid.New()
		partitionID := int64(1)
		userProfileID := uuid.New()
		idpID := uuid.New()

		storage.GetIdentityProvidersByTypeAndPartitionMock.Expect(minimock.AnyContext, tenantID, partitionID, model.UsernamePasswordIDPType).Return([]model.IdentityProvider{
			{ID: idpID, IDPType: model.UsernamePasswordIDPType},
		}, nil)
		storage.GetPasswordCredentialByProfileIDMock.Expect(minimock.AnyContext, tenantID, partitionID, userProfileID, idpID).Return(&model.PasswordCredential{
			UserProfileID:      userProfileID,
			IdentityProviderID: idpID,
			Argon2Hash:         "pass_hash",
		}, nil)
		crypto.CompareCredentialMock.Expect("pass_hash", "bad_pass").Return(false, nil)

		err := svc.ChangeUserEmail(context.Background(), port.ChangeEmailCommand{
			TenantID:        tenantID,
			PartitionID:     partitionID,
			UserProfileID:   userProfileID,
			CurrentPassword: "bad_pass",
			NewEmail:        "new@example.com",
		})
		if err == nil {
			t.Fatal("expected error with bad password")
		}
	})

	t.Run("EmailCollision", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		crypto := portmock.NewCryptoMock(ctrl)
		clock := portmock.NewMockClock(time.Now())
		svc := NewUserProfileService(storage, nil, crypto, clock)

		tenantID := uuid.New()
		partitionID := int64(1)
		userProfileID := uuid.New()
		idpID := uuid.New()

		storage.GetIdentityProvidersByTypeAndPartitionMock.Expect(minimock.AnyContext, tenantID, partitionID, model.UsernamePasswordIDPType).Return([]model.IdentityProvider{
			{ID: idpID, IDPType: model.UsernamePasswordIDPType},
		}, nil)
		storage.GetPasswordCredentialByProfileIDMock.Expect(minimock.AnyContext, tenantID, partitionID, userProfileID, idpID).Return(&model.PasswordCredential{
			UserProfileID:      userProfileID,
			IdentityProviderID: idpID,
			Argon2Hash:         "pass_hash",
		}, nil)
		crypto.CompareCredentialMock.Expect("pass_hash", "good_pass").Return(true, nil)
		storage.FindProfileByEmailMock.Expect(minimock.AnyContext, tenantID, partitionID, "taken@example.com").Return(&model.UserProfile{
			ID:    uuid.New(), // Different profile ID
			Email: "taken@example.com",
		}, nil)

		err := svc.ChangeUserEmail(context.Background(), port.ChangeEmailCommand{
			TenantID:        tenantID,
			PartitionID:     partitionID,
			UserProfileID:   userProfileID,
			CurrentPassword: "good_pass",
			NewEmail:        "taken@example.com",
		})
		if err == nil {
			t.Fatal("expected error for collision email")
		}
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		adminStorage := portmock.NewAdminStorageMock(ctrl)
		crypto := portmock.NewCryptoMock(ctrl)
		clock := portmock.NewMockClock(time.Now())
		svc := NewUserProfileService(storage, adminStorage, crypto, clock)

		tenantID := uuid.New()
		partitionID := int64(1)
		userProfileID := uuid.New()
		idpID := uuid.New()

		storage.GetIdentityProvidersByTypeAndPartitionMock.Expect(minimock.AnyContext, tenantID, partitionID, model.UsernamePasswordIDPType).Return([]model.IdentityProvider{
			{ID: idpID, IDPType: model.UsernamePasswordIDPType},
		}, nil)
		storage.GetPasswordCredentialByProfileIDMock.Expect(minimock.AnyContext, tenantID, partitionID, userProfileID, idpID).Return(&model.PasswordCredential{
			UserProfileID:      userProfileID,
			IdentityProviderID: idpID,
			Argon2Hash:         "pass_hash",
		}, nil)
		crypto.CompareCredentialMock.Expect("pass_hash", "good_pass").Return(true, nil)
		storage.FindProfileByEmailMock.Expect(minimock.AnyContext, tenantID, partitionID, "unique@example.com").Return(nil, nil)
		storage.GetPartitionByIDMock.Expect(minimock.AnyContext, tenantID, partitionID).Return(&model.Partition{
			ID:        partitionID,
			TenantID:  tenantID,
			AliasName: "test-partition",
		}, nil)
		existingProfile := &model.UserProfile{
			ID:            userProfileID,
			Email:         "old@example.com",
			EmailVerified: true,
		}
		storage.GetUserProfileByIDAndPartitionAliasMock.Expect(minimock.AnyContext, tenantID, "test-partition", userProfileID).Return(existingProfile, nil)
		adminStorage.UpdateUserProfileMock.Set(func(ctx context.Context, tID uuid.UUID, pID int64, profile model.UserProfile) error {
			if profile.Email != "unique@example.com" {
				t.Errorf("expected email 'unique@example.com', got %q", profile.Email)
			}
			if profile.EmailVerified {
				t.Error("expected EmailVerified to be reset to false")
			}
			return nil
		})

		err := svc.ChangeUserEmail(context.Background(), port.ChangeEmailCommand{
			TenantID:        tenantID,
			PartitionID:     partitionID,
			UserProfileID:   userProfileID,
			CurrentPassword: "good_pass",
			NewEmail:        "unique@example.com",
		})
		if err != nil {
			t.Fatalf("unexpected error during valid email change: %v", err)
		}
	})
}

func TestUserProfileService_ChangeUserName(t *testing.T) {
	t.Run("ValidationFailure", func(t *testing.T) {
		svc := NewUserProfileService(nil, nil, nil, nil)
		err := svc.ChangeUserName(context.Background(), port.ChangeNameCommand{
			TenantID:      uuid.New(),
			PartitionID:   1,
			UserProfileID: uuid.New(),
			NewName:       "   ",
		})
		if err == nil {
			t.Fatal("expected validation error for empty name")
		}
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		adminStorage := portmock.NewAdminStorageMock(ctrl)
		clock := portmock.NewMockClock(time.Now())
		svc := NewUserProfileService(storage, adminStorage, nil, clock)

		tenantID := uuid.New()
		partitionID := int64(1)
		userProfileID := uuid.New()

		storage.GetPartitionByIDMock.Expect(minimock.AnyContext, tenantID, partitionID).Return(&model.Partition{
			ID:        partitionID,
			TenantID:  tenantID,
			AliasName: "part-alias",
		}, nil)
		storage.GetUserProfileByIDAndPartitionAliasMock.Expect(minimock.AnyContext, tenantID, "part-alias", userProfileID).Return(&model.UserProfile{
			ID:   userProfileID,
			Name: "Old Name",
		}, nil)
		adminStorage.UpdateUserProfileMock.Set(func(ctx context.Context, tID uuid.UUID, pID int64, profile model.UserProfile) error {
			if profile.Name != "Brand New Name" {
				t.Errorf("expected updated name 'Brand New Name', got %q", profile.Name)
			}
			return nil
		})

		err := svc.ChangeUserName(context.Background(), port.ChangeNameCommand{
			TenantID:      tenantID,
			PartitionID:   partitionID,
			UserProfileID: userProfileID,
			NewName:       "Brand New Name",
		})
		if err != nil {
			t.Fatalf("unexpected error changing name: %v", err)
		}
	})
}

func TestUserProfileService_DecoupleUserIdentity(t *testing.T) {
	t.Run("SingleIdentityCannotDecouple", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		svc := NewUserProfileService(storage, nil, nil, nil)

		tenantID := uuid.New()
		partitionID := int64(1)
		userProfileID := uuid.New()
		idp1 := uuid.New()

		storage.GetUserIdentitiesByProfileIDMock.Expect(minimock.AnyContext, tenantID, partitionID, userProfileID).Return([]model.UserIdentity{
			{IdentityProviderID: idp1},
		}, nil)

		err := svc.DecoupleUserIdentity(context.Background(), port.DecoupleIdentityCommand{
			TenantID:           tenantID,
			PartitionID:        partitionID,
			UserProfileID:      userProfileID,
			IdentityProviderID: idp1,
		})
		if err == nil {
			t.Fatal("expected error when decoupling only identity")
		}
	})

	t.Run("IdentityNotCoupled", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		svc := NewUserProfileService(storage, nil, nil, nil)

		tenantID := uuid.New()
		partitionID := int64(1)
		userProfileID := uuid.New()
		idp1 := uuid.New()
		idp2 := uuid.New()
		unlinkedIDP := uuid.New()

		storage.GetUserIdentitiesByProfileIDMock.Expect(minimock.AnyContext, tenantID, partitionID, userProfileID).Return([]model.UserIdentity{
			{IdentityProviderID: idp1},
			{IdentityProviderID: idp2},
		}, nil)

		err := svc.DecoupleUserIdentity(context.Background(), port.DecoupleIdentityCommand{
			TenantID:           tenantID,
			PartitionID:        partitionID,
			UserProfileID:      userProfileID,
			IdentityProviderID: unlinkedIDP,
		})
		if err == nil {
			t.Fatal("expected error when decoupling unlinked IDP")
		}
	})

	t.Run("DisallowedDecoupling", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		svc := NewUserProfileService(storage, nil, nil, nil)

		tenantID := uuid.New()
		partitionID := int64(1)
		userProfileID := uuid.New()
		idp1 := uuid.New()
		idp2 := uuid.New()

		storage.GetUserIdentitiesByProfileIDMock.Expect(minimock.AnyContext, tenantID, partitionID, userProfileID).Return([]model.UserIdentity{
			{IdentityProviderID: idp1},
			{IdentityProviderID: idp2},
		}, nil)
		storage.GetIdentityProviderByUUIDMock.Expect(minimock.AnyContext, tenantID, idp1).Return(&model.IdentityProvider{
			ID:      idp1,
			IDPType: model.UsernamePasswordIDPType,
			Config:  model.IdentityProviderConfig{AllowDecoupling: false},
		}, nil)

		err := svc.DecoupleUserIdentity(context.Background(), port.DecoupleIdentityCommand{
			TenantID:           tenantID,
			PartitionID:        partitionID,
			UserProfileID:      userProfileID,
			IdentityProviderID: idp1,
		})
		if err == nil {
			t.Fatal("expected error when IDP disallows decoupling")
		}
	})

	t.Run("Success", func(t *testing.T) {
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		svc := NewUserProfileService(storage, nil, nil, nil)

		tenantID := uuid.New()
		partitionID := int64(1)
		userProfileID := uuid.New()
		idp1 := uuid.New()
		idp2 := uuid.New()

		storage.GetUserIdentitiesByProfileIDMock.Expect(minimock.AnyContext, tenantID, partitionID, userProfileID).Return([]model.UserIdentity{
			{IdentityProviderID: idp1},
			{IdentityProviderID: idp2},
		}, nil)
		storage.GetIdentityProviderByUUIDMock.Expect(minimock.AnyContext, tenantID, idp2).Return(&model.IdentityProvider{
			ID:      idp2,
			IDPType: model.OpenIDConnectIDPType,
		}, nil)
		storage.RevokeSessionMock.Expect(minimock.AnyContext, tenantID, userProfileID.String(), idp2.String()).Return(nil)

		err := svc.DecoupleUserIdentity(context.Background(), port.DecoupleIdentityCommand{
			TenantID:           tenantID,
			PartitionID:        partitionID,
			UserProfileID:      userProfileID,
			IdentityProviderID: idp2,
		})
		if err != nil {
			t.Fatalf("unexpected error during decoupling: %v", err)
		}
	})
}

func TestUserProfileService_GetUserProfile(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	svc := NewUserProfileService(storage, nil, nil, nil)

	tenantID := uuid.New()
	partitionID := int64(1)
	userProfileID := uuid.New()

	storage.GetPartitionByIDMock.Expect(minimock.AnyContext, tenantID, partitionID).Return(&model.Partition{
		ID:        partitionID,
		TenantID:  tenantID,
		AliasName: "test-partition",
	}, nil)
	expectedProfile := &model.UserProfile{
		ID:   userProfileID,
		Name: "Alice Bob",
	}
	storage.GetUserProfileByIDAndPartitionAliasMock.Expect(minimock.AnyContext, tenantID, "test-partition", userProfileID).Return(expectedProfile, nil)

	profile, err := svc.GetUserProfile(context.Background(), port.GetUserProfileCommand{
		TenantID:      tenantID,
		PartitionID:   partitionID,
		UserProfileID: userProfileID,
	})
	if err != nil {
		t.Fatalf("unexpected error in GetUserProfile: %v", err)
	}
	if profile.ID != userProfileID {
		t.Errorf("expected profile ID %s, got %s", userProfileID, profile.ID)
	}
}

func TestUserProfileService_GetUserProfileDashboard(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	svc := NewUserProfileService(storage, nil, nil, nil)

	tenantID := uuid.New()
	partitionID := int64(1)
	userProfileID := uuid.New()

	storage.GetPartitionByIDMock.Expect(minimock.AnyContext, tenantID, partitionID).Return(&model.Partition{
		ID:        partitionID,
		TenantID:  tenantID,
		AliasName: "test-partition",
	}, nil)
	expectedProfile := &model.UserProfile{
		ID:   userProfileID,
		Name: "Alice Bob",
	}
	storage.GetUserProfileByIDAndPartitionAliasMock.Expect(minimock.AnyContext, tenantID, "test-partition", userProfileID).Return(expectedProfile, nil)

	identities := []model.UserIdentity{{UserProfileID: userProfileID}}
	storage.GetUserIdentitiesByProfileIDMock.Expect(minimock.AnyContext, tenantID, partitionID, userProfileID).Return(identities, nil)

	providers := []model.IdentityProvider{
		{ID: uuid.New(), PartitionID: partitionID, IDPType: model.UsernamePasswordIDPType},
		{ID: uuid.New(), PartitionID: 999, IDPType: model.OpenIDConnectIDPType},
	}
	storage.GetEnabledIdentityProvidersMock.Expect(minimock.AnyContext, tenantID).Return(providers, nil)

	dash, err := svc.GetUserProfileDashboard(context.Background(), port.GetUserProfileDashboardCommand{
		TenantID:      tenantID,
		PartitionID:   partitionID,
		UserProfileID: userProfileID,
	})
	if err != nil {
		t.Fatalf("unexpected error in GetUserProfileDashboard: %v", err)
	}
	if !dash.HasPasswordIDP {
		t.Error("expected HasPasswordIDP to be true")
	}
	if len(dash.Providers) != 1 {
		t.Errorf("expected 1 filtered provider for partition %d, got %d", partitionID, len(dash.Providers))
	}
}
