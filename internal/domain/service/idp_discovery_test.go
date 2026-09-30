package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"
	"sprezz-identity/internal/domain/service"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newDiscoveryFixture(t *testing.T) (*idpFixture, *portmock.FederationClientMock) {
	t.Helper()
	mc := minimock.NewController(t)
	fed := portmock.NewFederationClientMock(mc)
	f := newIDPFixture(t)
	f.svc = service.NewIdentityProviderService(f.storage, f.admin, portmock.NewCryptoMock(mc), portmock.NewMockClock(time.Now()), fed)
	return f, fed
}

func TestPatchIdentityProvider_ConnectionTakesTheIssuerFromTheProviderNotTheForm(t *testing.T) {
	f, fed := newDiscoveryFixture(t)
	before := storedOIDC()
	f.stubStored(before)
	saved := f.captureSave()
	fed.FetchOIDCDiscoveryMetadataMock.Return(&model.OIDCDiscoveryMetadata{
		Issuer: "https://login.example.com", AuthorizationEndpoint: "https://login.example.com/auth",
	}, nil)

	err := f.svc.PatchIdentityProvider(context.Background(), port.PatchIdentityProviderCommand{
		TenantID: f.tenantID, ID: before.ID, Section: port.IDPSectionConnection,
		DiscoveryEndpoint:    "https://login.example.com/.well-known/openid-configuration",
		Issuer:               "https://attacker.example.net", // a forged value must be ignored
		AuthenticationMethod: "client_secret_basic",
	})

	require.NoError(t, err)
	assert.Equal(t, "https://login.example.com", saved.Issuer)
	assert.Contains(t, saved.Config.DiscoveryResult, "login.example.com/auth", "the metadata snapshot is stored")
}

func TestPatchIdentityProvider_UnreachableDiscoveryBlocksTheSave(t *testing.T) {
	f, fed := newDiscoveryFixture(t)
	before := storedOIDC()
	f.stubStored(before)
	f.admin.CreateIdentityProviderMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, p model.IdentityProvider) error {
		t.Error("a provider whose metadata cannot be fetched must not be saved")
		return nil
	})
	fed.FetchOIDCDiscoveryMetadataMock.Return(nil, errors.New("dial tcp 10.0.0.5: connection refused"))

	err := f.svc.PatchIdentityProvider(context.Background(), port.PatchIdentityProviderCommand{
		TenantID: f.tenantID, ID: before.ID, Section: port.IDPSectionConnection,
		DiscoveryEndpoint: "https://idp.example.com/.well-known/openid-configuration", AuthenticationMethod: "client_secret_basic",
	})

	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr.Fields, "discovery_endpoint")
	assert.NotContains(t, verr.Fields["discovery_endpoint"], "10.0.0.5", "network details never reach the admin")
}

func TestPatchIdentityProvider_OtherSectionsDoNotContactTheProvider(t *testing.T) {
	f, _ := newDiscoveryFixture(t) // a strict mock: any fetch would fail the test
	before := storedOIDC()
	f.stubStored(before)
	f.captureSave()

	require.NoError(t, f.svc.PatchIdentityProvider(context.Background(), port.PatchIdentityProviderCommand{
		TenantID: f.tenantID, ID: before.ID, Section: port.IDPSectionGeneral, Name: "Renamed", Enabled: true,
	}))
}

func TestCreateIdentityProvider_FetchesMetadataAndRejectsPlainHTTP(t *testing.T) {
	f, fed := newDiscoveryFixture(t)
	f.storage.GetIdentityProvidersMock.Return(nil, nil)
	saved := f.captureSave()
	fed.FetchOIDCDiscoveryMetadataMock.Return(&model.OIDCDiscoveryMetadata{Issuer: "https://idp.example.com"}, nil)

	input := storedOIDC()
	input.Issuer = ""
	created, err := f.svc.CreateIdentityProvider(context.Background(), f.tenantID, input)
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example.com", created.Issuer)
	assert.Equal(t, "https://idp.example.com", saved.Issuer)

	insecure := storedOIDC()
	insecure.Config.DiscoveryEndpoint = "http://idp.example.com/.well-known/openid-configuration"
	_, err = f.svc.CreateIdentityProvider(context.Background(), f.tenantID, insecure)
	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr.Fields, "discovery_endpoint")
}
