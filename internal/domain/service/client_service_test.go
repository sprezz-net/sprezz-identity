package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestClientService_GetClientsByTenant(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	svc := NewClientService(storage, crypto)

	tenantID := uuid.New()

	storage.GetClientsByTenantMock.Expect(context.Background(), tenantID).Return([]model.ClientApplication{
		{ClientID: "client1"},
	}, nil)

	clients, err := svc.GetClientsByTenant(context.Background(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].ClientID != "client1" {
		t.Error("unexpected clients returned")
	}
}

func TestClientService_CreateClient(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	svc := NewClientService(storage, crypto)

	tenantID := uuid.New()

	storage.SaveClientMock.Set(func(ctx context.Context, client model.ClientApplication) error {
		if client.ClientID != "newclient" {
			t.Errorf("unexpected client id: %s", client.ClientID)
		}
		return nil
	})

	client, err := svc.CreateClient(context.Background(), tenantID, model.ClientApplication{
		ClientID:   "newclient",
		ClientName: "New Client",
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.ClientName != "New Client" {
		t.Error("unexpected client attributes")
	}
}

func TestClientService_DeleteClient(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	svc := NewClientService(storage, crypto)

	tenantID := uuid.New()

	storage.DeleteClientMock.Expect(context.Background(), tenantID, "oldclient").Return(nil)

	err := svc.DeleteClient(context.Background(), tenantID, "oldclient")
	if err != nil {
		t.Fatal(err)
	}
}

func TestClientService_UpdateClient(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	svc := NewClientService(storage, crypto)

	tenantID := uuid.New()

	storage.GetClientMock.Expect(context.Background(), tenantID, "someclient").Return(&model.ClientApplication{
		ClientID:    "someclient",
		ClientName:  "Original Name",
		RedirectURI: "https://old.com",
	}, nil)

	storage.SaveClientMock.Set(func(ctx context.Context, client model.ClientApplication) error {
		if client.ClientName != "Updated Name" {
			t.Errorf("expected updated name, got %s", client.ClientName)
		}
		if client.RedirectURI != "https://new.com" {
			t.Errorf("expected updated redirect uri, got %s", client.RedirectURI)
		}
		return nil
	})

	client, err := svc.UpdateClient(context.Background(), tenantID, model.ClientApplication{
		ClientID:    "someclient",
		ClientName:  "Updated Name",
		RedirectURI: "https://new.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.ClientName != "Updated Name" {
		t.Error("expected updated client name")
	}
	if client.RedirectURI != "https://new.com" {
		t.Error("expected updated redirect uri")
	}
}

func TestClientService_ResetClientSecret_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	service := NewClientService(storage, crypto)

	tenantID := uuid.New()
	clientID := "client-test-123"
	mockHash := "$argon2id$v=19$m=65536,t=1,p=4$some-salt$some-hash"

	existingClient := &model.ClientApplication{
		ClientID:   clientID,
		TenantID:   tenantID,
		ClientType: model.ClientTypeConfidential, // Security baseline requirement met
	}

	// 1. Expect service to fetch the target application from database storage
	storage.GetClientMock.Expect(minimock.AnyContext, tenantID, clientID).Return(existingClient, nil)

	// 2. Expect service to hash the newly generated plain secret text statelessly
	crypto.HashCredentialMock.Set(func(secret string) (string, error) {
		if secret == "" {
			t.Error("expected generated plain client secret to be non-empty")
		}
		return mockHash, nil
	})

	// 3. Expect service to persist the final model with the hashed string value
	storage.SaveClientMock.Set(func(ctx context.Context, client model.ClientApplication) error {
		if client.ClientSecret == nil || *client.ClientSecret != mockHash {
			t.Errorf("expected client secret to be updated with hash %s, got %v", mockHash, client.ClientSecret)
		}
		return nil
	})

	client, plainSecret, err := service.ResetClientSecret(context.Background(), tenantID, clientID)
	if err != nil {
		t.Fatalf("unexpected error during credential rotation: %v", err)
	}

	if plainSecret == "" {
		t.Error("expected returned unhashed plain secret text to be non-empty")
	}
	if client.ClientSecret == nil || *client.ClientSecret != mockHash {
		t.Errorf("returned client state should track the updated hash")
	}
}

func TestClientService_ResetClientSecret_FailsForPublicClients(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	service := NewClientService(storage, crypto)

	tenantID := uuid.New()
	clientID := "public-client-abc"

	existingClient := &model.ClientApplication{
		ClientID:   clientID,
		TenantID:   tenantID,
		ClientType: model.ClientTypePublic, // Security boundary violation
	}

	storage.GetClientMock.Expect(minimock.AnyContext, tenantID, clientID).Return(existingClient, nil)

	// Execution must halt immediately before hashing or saving operations occur
	_, _, err := service.ResetClientSecret(context.Background(), tenantID, clientID)
	if err == nil {
		t.Fatal("expected rotation to fail for public applications, got nil")
	}

	if !strings.Contains(err.Error(), "cannot reset secret of a non-confidential client") {
		t.Errorf("unexpected error context string returned: %v", err)
	}
}

func TestClientService_ResetClientSecret_EmptyIdentifiers(t *testing.T) {
	ctrl := minimock.NewController(t)
	service := NewClientService(portmock.NewStorageMock(ctrl), portmock.NewCryptoMock(ctrl))

	// Verify empty Tenant ID validation gate
	_, _, err := service.ResetClientSecret(context.Background(), uuid.Nil, "client-id")
	if err == nil || !strings.Contains(err.Error(), "tenant identifier cannot be empty") {
		t.Errorf("expected empty tenant validation failure, got %v", err)
	}

	// Verify empty Client ID validation gate
	_, _, err = service.ResetClientSecret(context.Background(), uuid.New(), "")
	if err == nil || !strings.Contains(err.Error(), "client identifier cannot be empty") {
		t.Errorf("expected empty client validation failure, got %v", err)
	}
}

func TestClientService_ResetClientSecret_DatabaseFetchFailure(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	service := NewClientService(storage, crypto)

	tenantID := uuid.New()
	clientID := "unknown-app-id"

	storage.GetClientMock.Expect(minimock.AnyContext, tenantID, clientID).Return(nil, errors.New("sql: table row missing"))
	crypto.HashCredentialMock.Optional()

	_, _, err := service.ResetClientSecret(context.Background(), tenantID, clientID)
	if err == nil || !strings.Contains(err.Error(), "failed to locate client application") {
		t.Errorf("expected database lookup error propagation, got %v", err)
	}
}
