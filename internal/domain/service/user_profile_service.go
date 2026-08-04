package service

import (
	"context"
	"fmt"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

type UserProfileService struct {
	storage port.Storage
}

func NewUserProfileService(storage port.Storage) *UserProfileService {
	return &UserProfileService{storage: storage}
}

func (s *UserProfileService) GetUserProfilesByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.UserProfile, error) {
	return s.storage.GetUserProfilesByTenant(ctx, tenantID)
}

func (s *UserProfileService) DeleteUserProfile(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) error {
	return s.storage.DeleteUserProfile(ctx, tenantID, userID)
}

func (s *UserProfileService) GetUserIdentities(ctx context.Context, userProfileID uuid.UUID) ([]model.UserIdentity, error) {
	return s.storage.GetUserIdentities(ctx, userProfileID)
}

func (s *UserProfileService) DecoupleIdentity(ctx context.Context, userProfileID uuid.UUID, identityProviderID uuid.UUID) error {
	return s.storage.DecoupleIdentity(ctx, userProfileID, identityProviderID)
}

func (s *UserProfileService) UpdateUserProfile(ctx context.Context, tenantID uuid.UUID, profile model.UserProfile) (*model.UserProfile, error) {
	if profile.PreferredUsername == "" {
		return nil, fmt.Errorf("username is required")
	}
	if profile.Email == "" {
		return nil, fmt.Errorf("email is required")
	}

	err := s.storage.UpdateUserProfile(ctx, tenantID, profile)
	if err != nil {
		return nil, err
	}

	return &profile, nil
}
