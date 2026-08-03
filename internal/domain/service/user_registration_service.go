package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"
)

var (
	ErrPasswordTooShort     = errors.New("password must be at least 8 characters long")
	ErrRegistrationDisabled = errors.New("registration is disabled for this tenant")
)

type UserRegistrationService struct {
	storage port.Storage
}

func NewUserRegistrationService(s port.Storage) *UserRegistrationService {
	return &UserRegistrationService{
		storage: s,
	}
}

func (s *UserRegistrationService) RegisterUser(ctx context.Context, tenantID uuid.UUID, name, username, email, password string) (*model.UserProfile, error) {
	provider, err := s.storage.GetIdentityProviderByType(ctx, tenantID, model.UsernamePasswordIDPType)
	if err != nil {
		return nil, ErrRegistrationDisabled
	}

	username = strings.TrimSpace(username)
	email = strings.TrimSpace(email)
	name = strings.TrimSpace(name)

	if len(password) < 8 {
		return nil, ErrPasswordTooShort
	}

	// Email as Username mode standardizes username to email input
	if provider.Config.UsernameField == "email" {
		username = email
	}

	profile := model.UserProfile{
		PreferredUsername: username,
		Name:              name,
		Email:             email,
		EmailVerified:     false,
	}

	// Save profile to database (this checks collisions internally)
	if err := s.storage.SaveUserProfile(ctx, tenantID, profile); err != nil {
		return nil, err
	}

	// Resolve the newly created profile with UUID
	savedProfile, err := s.storage.GetUserProfileByIdentifier(ctx, tenantID, provider.ID, username)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve registered profile: %w", err)
	}

	// Hash password
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return nil, fmt.Errorf("password processing failed: %w", err)
	}

	// Save credential record
	cred := model.PasswordCredential{
		UserProfileID:      savedProfile.ID,
		IdentityProviderID: provider.ID,
		Argon2Hash:         hash,
	}
	if err := s.storage.SavePasswordCredential(ctx, cred); err != nil {
		return nil, fmt.Errorf("failed to store credentials: %w", err)
	}

	// Upsert initial identity record as well
	identity := model.UserIdentity{
		ID:                 uuid.New(),
		UserProfileID:      savedProfile.ID,
		IdentityProviderID: provider.ID,
		ExternalIdentityID: savedProfile.ID.String(),
		CoupledAt:          time.Now().Truncate(time.Second),
	}
	if err := s.storage.UpsertIdentity(ctx, identity); err != nil {
		return nil, fmt.Errorf("failed to couple user identity: %w", err)
	}

	return savedProfile, nil
}
