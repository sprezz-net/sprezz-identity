package service_test

import (
	"context"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"
	"sprezz-identity/internal/domain/service"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

type idpFixture struct {
	svc      *service.IdentityProviderService
	storage  *portmock.StorageMock
	admin    *portmock.AdminStorageMock
	tenantID uuid.UUID
}

func newIDPFixture(t *testing.T) *idpFixture {
	t.Helper()
	mc := minimock.NewController(t)
	storage, admin := portmock.NewStorageMock(mc), portmock.NewAdminStorageMock(mc)
	return &idpFixture{
		svc:      service.NewIdentityProviderService(storage, admin, portmock.NewCryptoMock(mc), portmock.NewMockClock(time.Now()), nil),
		storage:  storage,
		admin:    admin,
		tenantID: uuid.New(),
	}
}

// storedOIDC is a fully configured provider, including settings no page card edits.
func storedOIDC() model.IdentityProvider {
	return model.IdentityProvider{
		ID: uuid.New(), Name: "Corp", Alias: "corp", IDPType: model.OpenIDConnectIDPType, Enabled: true, PartitionID: 1,
		Issuer: "https://idp.example.com",
		Config: model.IdentityProviderConfig{
			DiscoveryEndpoint: "https://idp.example.com/.well-known/openid-configuration",
			ClientID:          "sprezz", ClientSecret: "s3cret", AuthenticationMethod: "client_secret_basic",
			Scopes: []string{"openid"}, AAL: 2, IAL: 2, PkceEnabled: true,
			DomainAliases: []string{"example.com"}, AutoProvisionUser: true, AutoVerifyEmail: true,
			AllowDecoupling: true, UserIdentifierClaim: "sub",
			AcrToTuple: map[string]model.AcrTuple{"gold": {AAL: 3, IAL: 2}},
		},
	}
}

func (f *idpFixture) stubStored(p model.IdentityProvider) {
	f.storage.GetIdentityProviderByUUIDMock.Set(func(ctx context.Context, tID, id uuid.UUID) (*model.IdentityProvider, error) {
		clone := p
		return &clone, nil
	})
}

func (f *idpFixture) captureSave() *model.IdentityProvider {
	saved := &model.IdentityProvider{}
	f.admin.CreateIdentityProviderMock.Set(func(ctx context.Context, tID uuid.UUID, p model.IdentityProvider) error {
		*saved = p
		return nil
	})
	return saved
}
