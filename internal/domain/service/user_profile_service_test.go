package service

import (
	"context"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestUserProfileService_GetUserProfilesByTenant(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	svc := NewUserProfileService(storage)

	tenantID := uuid.New()

	storage.GetUserProfilesByTenantMock.Expect(context.Background(), tenantID).Return([]model.UserProfile{
		{Name: "Alice"},
	}, nil)

	profiles, err := svc.GetUserProfilesByTenant(context.Background(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].Name != "Alice" {
		t.Error("unexpected profiles")
	}
}

func TestUserProfileService_DeleteUserProfile(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	svc := NewUserProfileService(storage)

	tenantID := uuid.New()
	userID := uuid.New()

	storage.DeleteUserProfileMock.Expect(context.Background(), tenantID, userID).Return(nil)

	err := svc.DeleteUserProfile(context.Background(), tenantID, userID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUserProfileService_GetUserIdentities(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	svc := NewUserProfileService(storage)

	userID := uuid.New()

	storage.GetUserIdentitiesMock.Expect(context.Background(), userID).Return([]model.UserIdentity{
		{ExternalIdentityID: "ext1"},
	}, nil)

	identities, err := svc.GetUserIdentities(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 1 || identities[0].ExternalIdentityID != "ext1" {
		t.Error("unexpected user identities")
	}
}

func TestUserProfileService_DecoupleIdentity(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	svc := NewUserProfileService(storage)

	userID := uuid.New()
	idpID := uuid.New()

	storage.DecoupleIdentityMock.Expect(context.Background(), userID, idpID).Return(nil)

	err := svc.DecoupleIdentity(context.Background(), userID, idpID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUserProfileService_UpdateUserProfile(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	svc := NewUserProfileService(storage)

	tenantID := uuid.New()
	userID := uuid.New()

	profile := model.UserProfile{
		ID:                userID,
		PreferredUsername: "alice",
		Email:             "alice@example.com",
		Name:              "Alice",
	}
	storage.UpdateUserProfileMock.Expect(context.Background(), tenantID, profile).Return(nil)

	updated, err := svc.UpdateUserProfile(context.Background(), tenantID, profile)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Alice" {
		t.Error("unexpected updated profile name")
	}
}
