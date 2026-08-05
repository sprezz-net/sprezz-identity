package service

import (
	"context"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestClientService_GetClientsByTenant(t *testing.T) {
	ctrl := minimock.NewController(t)

	storage := portmock.NewStorageMock(ctrl)
	svc := NewClientService(storage)

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
	svc := NewClientService(storage)

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
	svc := NewClientService(storage)

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
	svc := NewClientService(storage)

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
