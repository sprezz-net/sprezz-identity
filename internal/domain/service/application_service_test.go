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

	// Track whether our callback actually fired
	deliveryFired := false

	// 1. Storage returns a confidential profile policy template
	adminStorageMock.GetApplicationProfileByIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) (*model.ApplicationProfile, error) {
		assert.Equal(t, tenantID, tenantUUID)
		assert.Equal(t, profileID, id)
		return &model.ApplicationProfile{
			ID:                      profileID,
			TokenEndpointAuthMethod: model.AuthMethodClientSecretPost,
		}, nil
	})

	// 2. Crypto hashes the single-flight plaintext secret string parameter
	cryptoMock.HashCredentialMock.Set(func(secret string) (string, error) {
		assert.NotEmpty(t, secret)
		return "hashed-secret", nil
	})

	// 3. Stub out the atomic transaction infrastructure wrapper pipeline loop cleanly
	storageMock.InTransactionMock.Set(func(ctx context.Context, fn func(txRepo port.Storage) error) error {
		structWrapper := struct {
			port.Storage
			port.AdminStorage
		}{
			Storage:      storageMock,
			AdminStorage: adminStorageMock,
		}

		return fn(structWrapper)
	})

	// 4. AdminStorage saves the transaction-locked application record node entries
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
		// Verify secret delivery securely within our single-flight delivery channel hook
		OnDelivery: func(plaintextSecret string) error {
			assert.NotEmpty(t, plaintextSecret)
			deliveryFired = true
			return nil
		},
	}

	// Updated return assignment maps strictly to the 2-value return model tuple signature
	app, err := svc.CreateApplication(context.Background(), cmd)
	assert.NoError(t, err)
	assert.NotNil(t, app)
	assert.True(t, deliveryFired, "expected single-use token delivery handshake execution closure to fire")
}
