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
	crypto := portmock.NewCryptoMock(ctrl)
	clock := portmock.NewMockClock(time.Now())

	svc := NewUserProfileService(storage, crypto, clock)

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
