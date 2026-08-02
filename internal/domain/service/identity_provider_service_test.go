package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/alexedwards/argon2id"
	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestIdentityProviderService_AuthenticateUsernamePassword_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	service := NewIdentityProviderService(storage)

	tenantID := uuid.New()
	providerID := uuid.New()
	userProfileID := uuid.New()

	password := "SecretPass123!"
	hashedPassword, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		t.Fatalf("failed to create Argon2id hash: %v", err)
	}

	provider := model.IdentityProvider{
		ID:       providerID,
		TenantID: tenantID,
		IDPType:  model.UsernamePasswordIDPType,
		Enabled:  true,
		Alias:    "username-password",
		Config: model.IdentityProviderConfig{
			UsernameField: "preferredUsername",
		},
	}

	profile := &model.UserProfile{
		ID:                userProfileID,
		PreferredUsername: "john_doe",
		Name:              "John Doe",
		Email:             "john@example.com",
		EmailVerified:     true,
	}

	cred := &model.PasswordCredential{
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		Argon2Hash:         hashedPassword,
	}

	storage.GetEnabledIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{provider}, nil)
	storage.GetUserProfileByIdentifierMock.Expect(context.Background(), tenantID, providerID, "john_doe").Return(profile, nil)
	storage.GetPasswordCredentialMock.Expect(context.Background(), userProfileID, providerID).Return(cred, nil)

	// Return error indicating first login (no existing identity record)
	storage.GetIdentityByProfileAndProviderMock.Expect(context.Background(), userProfileID, providerID).Return(nil, errors.New("not found"))
	storage.UpsertIdentityMock.Set(func(ctx context.Context, identity model.UserIdentity) (err error) {
		if identity.UserProfileID != userProfileID {
			t.Errorf("expected UserProfileID %s, got %s", userProfileID, identity.UserProfileID)
		}
		if identity.IdentityProviderID != providerID {
			t.Errorf("expected IdentityProviderID %s, got %s", providerID, identity.IdentityProviderID)
		}
		if identity.ExternalIdentityID != userProfileID.String() {
			t.Errorf("expected ExternalIdentityID %s, got %s", userProfileID.String(), identity.ExternalIdentityID)
		}
		if identity.CoupledAt.IsZero() {
			t.Error("expected CoupledAt to be set")
		}
		if identity.LastLoginAt.IsZero() {
			t.Error("expected LastLoginAt to be set")
		}
		if identity.LoginCount != 1 {
			t.Errorf("expected LoginCount 1, got %d", identity.LoginCount)
		}
		return nil
	})

	result, err := service.AuthenticateUsernamePassword(context.Background(), tenantID, "john_doe", password)
	if err != nil {
		t.Fatalf("unexpected error during authentication: %v", err)
	}

	if result.UserProfile.ID != userProfileID {
		t.Errorf("expected user profile ID %s, got %s", userProfileID, result.UserProfile.ID)
	}
}

func TestIdentityProviderService_AuthenticateUsernamePassword_InvalidCredentials(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	service := NewIdentityProviderService(storage)

	tenantID := uuid.New()
	providerID := uuid.New()
	userProfileID := uuid.New()

	hashedPassword, _ := argon2id.CreateHash("SecretPass123!", argon2id.DefaultParams)

	provider := model.IdentityProvider{
		ID:       providerID,
		TenantID: tenantID,
		IDPType:  model.UsernamePasswordIDPType,
		Enabled:  true,
		Alias:    "username-password",
	}

	profile := &model.UserProfile{
		ID:                userProfileID,
		PreferredUsername: "john_doe",
	}

	cred := &model.PasswordCredential{
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		Argon2Hash:         hashedPassword,
	}

	storage.GetEnabledIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{provider}, nil)
	storage.GetUserProfileByIdentifierMock.Expect(context.Background(), tenantID, providerID, "john_doe").Return(profile, nil)
	storage.GetPasswordCredentialMock.Expect(context.Background(), userProfileID, providerID).Return(cred, nil)

	_, err := service.AuthenticateUsernamePassword(context.Background(), tenantID, "john_doe", "WrongPass!")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "invalid credentials" {
		t.Errorf("expected 'invalid credentials' error, got %q", err.Error())
	}
}

func TestIdentityProviderService_AuthenticateUsernamePassword_IncrementLoginCount(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	service := NewIdentityProviderService(storage)

	tenantID := uuid.New()
	providerID := uuid.New()
	userProfileID := uuid.New()

	password := "SecretPass123!"
	hashedPassword, _ := argon2id.CreateHash(password, argon2id.DefaultParams)

	provider := model.IdentityProvider{
		ID:       providerID,
		TenantID: tenantID,
		IDPType:  model.UsernamePasswordIDPType,
		Enabled:  true,
		Alias:    "username-password",
	}

	profile := &model.UserProfile{
		ID:                userProfileID,
		PreferredUsername: "john_doe",
	}

	cred := &model.PasswordCredential{
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		Argon2Hash:         hashedPassword,
	}

	existingIdentity := &model.UserIdentity{
		ID:                 uuid.New(),
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		LoginCount:         5,
		CoupledAt:          time.Now().Add(-24 * time.Hour),
	}

	storage.GetEnabledIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{provider}, nil)
	storage.GetUserProfileByIdentifierMock.Expect(context.Background(), tenantID, providerID, "john_doe").Return(profile, nil)
	storage.GetPasswordCredentialMock.Expect(context.Background(), userProfileID, providerID).Return(cred, nil)
	storage.GetIdentityByProfileAndProviderMock.Expect(context.Background(), userProfileID, providerID).Return(existingIdentity, nil)

	storage.UpsertIdentityMock.Set(func(ctx context.Context, identity model.UserIdentity) (err error) {
		if identity.LoginCount != 6 {
			t.Errorf("expected LoginCount 6, got %d", identity.LoginCount)
		}
		return nil
	})

	_, err := service.AuthenticateUsernamePassword(context.Background(), tenantID, "john_doe", password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
