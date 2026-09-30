package service_test

import (
	"context"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplicationService_CreateGroup_PersistsNormalizedContent(t *testing.T) {
	f := newAppServiceFixture(t)
	ssoID := uuid.New()
	f.stubProviders(model.IdentityProvider{ID: ssoID, IDPType: model.OpenIDConnectIDPType})

	f.admin.CreateApplicationGroupMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, g model.ApplicationGroup) error {
		assert.Equal(t, "https://b.example.com/cb", g.RedirectURI, "the default redirect URI must be persisted")
		assert.Equal(t, []string{"https://a.example.com/cb", "https://b.example.com/cb"}, g.RedirectURIs)
		assert.Equal(t, "https://app.example.com/logout", g.FrontChannelLogoutURI)
		assert.NotNil(t, g.AllowedAudiences)
		assert.Equal(t, "partners", g.GroupName)
		return nil
	})

	_, err := f.svc.CreateGroup(context.Background(), port.CreateGroupCommand{
		TenantID:              f.tenantID,
		GroupName:             "  partners ",
		DefaultRedirectURI:    "https://b.example.com/cb",
		RedirectURIs:          []string{"https://a.example.com/cb", "https://b.example.com/cb", "https://a.example.com/cb"},
		FrontChannelLogoutURI: "https://app.example.com/logout",
		AllowedIDPIDs:         []uuid.UUID{ssoID},
	})
	require.NoError(t, err)
}

func TestApplicationService_CreateGroup_RejectsInvalidContentBeforeStorage(t *testing.T) {
	f := newAppServiceFixture(t)
	f.admin.CreateApplicationGroupMock.Optional().Set(func(ctx context.Context, tenantUUID uuid.UUID, g model.ApplicationGroup) error {
		t.Error("an invalid group must not be stored")
		return nil
	})

	_, err := f.svc.CreateGroup(context.Background(), port.CreateGroupCommand{
		TenantID:      f.tenantID,
		GroupName:     "bad",
		RedirectURIs:  []string{"http://app.example.com/cb", "https://*.example.com/cb"},
		AllowedIDPIDs: []uuid.UUID{uuid.New()},
	})

	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr.Fields, "redirect_uris")
}

func TestApplicationService_UpdateGroup_PersistsDefaultRedirect(t *testing.T) {
	f := newAppServiceFixture(t)
	groupID := uuid.New()
	ssoID := uuid.New()
	f.stubGroup(model.ApplicationGroup{ID: groupID, GroupName: "partners", IsEnabled: true})
	f.stubProviders(model.IdentityProvider{ID: ssoID, IDPType: model.OpenIDConnectIDPType})

	f.admin.UpdateApplicationGroupMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, g model.ApplicationGroup) error {
		assert.Equal(t, "https://a.example.com/cb", g.RedirectURI, "an unset default falls back to the first redirect URI")
		assert.Equal(t, []string{"openid"}, g.DefaultScopes)
		return nil
	})

	err := f.svc.UpdateGroup(context.Background(), port.UpdateGroupCommand{
		TenantID:      f.tenantID,
		ID:            groupID,
		GroupName:     "partners",
		RedirectURIs:  []string{"https://a.example.com/cb"},
		AllowedScopes: []string{"openid", "email"},
		DefaultScopes: []string{"openid"},
		AllowedIDPIDs: []uuid.UUID{ssoID},
	})
	require.NoError(t, err)
}

func TestApplicationService_UpdateGroup_RejectsDefaultScopeOutsideAllowed(t *testing.T) {
	f := newAppServiceFixture(t)
	groupID := uuid.New()
	f.stubGroup(model.ApplicationGroup{ID: groupID, GroupName: "partners"})

	err := f.svc.UpdateGroup(context.Background(), port.UpdateGroupCommand{
		TenantID:      f.tenantID,
		ID:            groupID,
		AllowedScopes: []string{"openid"},
		DefaultScopes: []string{"email"},
		AllowedIDPIDs: []uuid.UUID{uuid.New()},
	})

	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr.Fields, "default_scopes")
}
