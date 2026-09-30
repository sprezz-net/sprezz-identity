package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newDiscoveryFixture(t *testing.T) (*IdentityProviderService, *portmock.FederationClientMock) {
	t.Helper()
	ctrl := minimock.NewController(t)
	fc := portmock.NewFederationClientMock(ctrl)
	svc := NewIdentityProviderService(
		portmock.NewStorageMock(ctrl),
		portmock.NewAdminStorageMock(ctrl),
		portmock.NewCryptoMock(ctrl),
		portmock.NewMockClock(time.Now()),
		fc,
	)
	return svc, fc
}

func TestIdentityProviderService_DiscoverOIDC_DelegatesToFederationClient(t *testing.T) {
	svc, fc := newDiscoveryFixture(t)
	endpoint := "https://idp.example.com/.well-known/openid-configuration"
	want := &model.OIDCDiscoveryMetadata{
		Issuer:             "https://idp.example.com",
		ScopesSupported:    []string{"openid", "email"},
		ACRValuesSupported: []string{"mfa"},
	}

	fc.FetchOIDCDiscoveryMetadataMock.Expect(minimock.AnyContext, endpoint).Return(want, nil)

	got, err := svc.DiscoverOIDC(context.Background(), endpoint)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestIdentityProviderService_DiscoverOIDC_RequiresEndpoint(t *testing.T) {
	svc, _ := newDiscoveryFixture(t)

	got, err := svc.DiscoverOIDC(context.Background(), "")
	assert.Error(t, err)
	assert.Nil(t, got)
}

func TestIdentityProviderService_DiscoverOIDC_PropagatesClientErrors(t *testing.T) {
	svc, fc := newDiscoveryFixture(t)
	boom := errors.New("secure boundary restriction rejected target scheme")

	fc.FetchOIDCDiscoveryMetadataMock.Return(nil, boom)

	_, err := svc.DiscoverOIDC(context.Background(), "http://idp.example.com/.well-known/openid-configuration")
	assert.ErrorIs(t, err, boom)
}
