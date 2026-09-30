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

func storedGroup(ssoID uuid.UUID) model.ApplicationGroup {
	return model.ApplicationGroup{
		ID:                     uuid.New(),
		GroupName:              "partners",
		IsEnabled:              true,
		RedirectURI:            "https://a.example.com/cb",
		RedirectURIs:           []string{"https://a.example.com/cb"},
		PostLogoutRedirectURIs: []string{"https://a.example.com/bye"},
		FrontChannelLogoutURI:  "https://a.example.com/front",
		AllowedScopes:          []string{"openid", "email"},
		DefaultScopes:          []string{"openid"},
		AllowedAudiences:       []string{"https://api.example.com"},
		AllowedIDPIDs:          []uuid.UUID{ssoID},
		DefaultIDPID:           &ssoID,
	}
}

func TestApplicationService_PatchGroup_TouchesOnlyTheSubmittedSection(t *testing.T) {
	ssoID := uuid.New()

	tests := []struct {
		name  string
		patch port.PatchGroupCommand
		check func(t *testing.T, before, after model.ApplicationGroup)
	}{
		{
			name:  "general",
			patch: port.PatchGroupCommand{Section: port.GroupSectionGeneral, GroupName: "renamed", IsEnabled: false},
			check: func(t *testing.T, before, after model.ApplicationGroup) {
				assert.Equal(t, "renamed", after.GroupName)
				assert.False(t, after.IsEnabled)
				assert.Equal(t, before.RedirectURIs, after.RedirectURIs)
				assert.Equal(t, before.AllowedScopes, after.AllowedScopes)
			},
		},
		{
			name: "redirects",
			patch: port.PatchGroupCommand{
				Section:            port.GroupSectionRedirects,
				RedirectURIs:       []string{"https://b.example.com/cb", "https://c.example.com/cb"},
				DefaultRedirectURI: "https://c.example.com/cb",
			},
			check: func(t *testing.T, before, after model.ApplicationGroup) {
				assert.Equal(t, []string{"https://b.example.com/cb", "https://c.example.com/cb"}, after.RedirectURIs)
				assert.Equal(t, "https://c.example.com/cb", after.RedirectURI)
				assert.Equal(t, before.GroupName, after.GroupName)
				assert.Equal(t, before.PostLogoutRedirectURIs, after.PostLogoutRedirectURIs)
			},
		},
		{
			name: "logout",
			patch: port.PatchGroupCommand{
				Section:                port.GroupSectionLogout,
				PostLogoutRedirectURIs: []string{"https://z.example.com/bye"},
				BackChannelLogoutURI:   "https://z.example.com/back",
			},
			check: func(t *testing.T, before, after model.ApplicationGroup) {
				assert.Equal(t, []string{"https://z.example.com/bye"}, after.PostLogoutRedirectURIs)
				assert.Equal(t, "https://z.example.com/back", after.BackChannelLogoutURI)
				assert.Empty(t, after.FrontChannelLogoutURI, "a cleared field is cleared")
				assert.Equal(t, before.RedirectURIs, after.RedirectURIs)
			},
		},
		{
			name: "scopes",
			patch: port.PatchGroupCommand{
				Section:       port.GroupSectionScopes,
				AllowedScopes: []string{"openid", "profile"},
				DefaultScopes: []string{"profile"},
			},
			check: func(t *testing.T, before, after model.ApplicationGroup) {
				assert.Equal(t, []string{"openid", "profile"}, after.AllowedScopes)
				assert.Equal(t, []string{"profile"}, after.DefaultScopes)
				assert.Empty(t, after.AllowedAudiences, "an empty audience list clears the audiences")
				assert.Equal(t, before.RedirectURIs, after.RedirectURIs)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newAppServiceFixture(t)
			before := storedGroup(ssoID)
			f.stubGroup(before)
			f.stubProviders(model.IdentityProvider{ID: ssoID, IDPType: model.OpenIDConnectIDPType})

			var after model.ApplicationGroup
			f.admin.UpdateApplicationGroupMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, g model.ApplicationGroup) error {
				after = g
				return nil
			})

			tt.patch.TenantID, tt.patch.ID = f.tenantID, before.ID
			require.NoError(t, f.svc.PatchGroup(context.Background(), tt.patch))
			tt.check(t, before, after)
			assert.Equal(t, []uuid.UUID{ssoID}, after.AllowedIDPIDs, "the sign-in methods are never touched by other sections")
		})
	}
}
