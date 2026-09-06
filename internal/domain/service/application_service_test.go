package service_test

import (
	"context"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"
	"sprezz-identity/internal/domain/service"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestApplicationService_CreateProfile_PublicEnforcement(t *testing.T) {
	storageMock := portmock.NewStorageMock(t)
	adminStorageMock := portmock.NewAdminStorageMock(t)
	clockMock := portmock.NewMockClock(time.Now())
	cryptoMock := portmock.NewCryptoMock(t)

	tenantID := uuid.New()

	// Assert that when creating a profile with "none" auth method, EnforceRTR is programmatically forced to true.
	adminStorageMock.CreateApplicationProfileMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, profile model.ApplicationProfile) error {
		assert.Equal(t, tenantID, tenantUUID)
		assert.Equal(t, model.AuthMethodNone, profile.TokenEndpointAuthMethod)
		assert.True(t, profile.EnforceRTR)
		return nil
	})

	svc := service.NewApplicationService(storageMock, adminStorageMock, clockMock, cryptoMock)

	cmd := port.CreateProfileCommand{
		TenantID:                tenantID,
		ProfileName:             "Test Public Profile",
		TokenEndpointAuthMethod: model.AuthMethodNone,
		EnforceRTR:              false, // Will be overridden to true
		SigningAlgorithm:        model.AlgRS256,
		GrantTypes:              []model.GrantType{model.GrantTypeAuthorizationCode},
		ResponseTypes:           []model.ResponseType{model.ResponseTypeCode},
	}

	err := svc.CreateProfile(context.Background(), cmd)
	assert.NoError(t, err)
}

func TestApplicationService_CreateApplication_ConfidentialSecretGeneration(t *testing.T) {
	storageMock := portmock.NewStorageMock(t)
	adminStorageMock := portmock.NewAdminStorageMock(t)
	clockMock := portmock.NewMockClock(time.Now())
	cryptoMock := portmock.NewCryptoMock(t)

	tenantID := uuid.New()
	profileID := uuid.New()
	groupID := uuid.New()

	// 1. Storage returns a confidential profile
	adminStorageMock.GetApplicationProfileByIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) (*model.ApplicationProfile, error) {
		assert.Equal(t, tenantID, tenantUUID)
		assert.Equal(t, profileID, id)
		return &model.ApplicationProfile{
			ID:                      profileID,
			TokenEndpointAuthMethod: model.AuthMethodClientSecretPost,
		}, nil
	})

	// 2. Crypto hashes the generated secret
	cryptoMock.HashCredentialMock.Set(func(secret string) (string, error) {
		assert.NotEmpty(t, secret)
		return "hashed-secret", nil
	})

	// 3. AdminStorage saves the new application node
	adminStorageMock.CreateApplicationMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, app model.Application) error {
		assert.Equal(t, tenantID, tenantUUID)
		assert.Equal(t, "hashed-secret", *app.ClientSecretHash)
		return nil
	})

	svc := service.NewApplicationService(storageMock, adminStorageMock, clockMock, cryptoMock)

	cmd := port.CreateApplicationCommand{
		TenantID:        tenantID,
		ClientID:        "conf-app",
		ApplicationName: "Confidential App",
		ProfileID:       profileID,
		GroupID:         groupID,
	}

	app, secret, err := svc.CreateApplication(context.Background(), cmd)
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.NotNil(t, app)
}
