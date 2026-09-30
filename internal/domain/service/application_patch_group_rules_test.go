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

func TestApplicationService_PatchGroup_ValidatesLikeAFullSave(t *testing.T) {
	f := newAppServiceFixture(t)
	before := storedGroup(uuid.New())
	f.stubGroup(before)
	f.admin.UpdateApplicationGroupMock.Optional().Set(func(ctx context.Context, tenantUUID uuid.UUID, g model.ApplicationGroup) error {
		t.Error("an invalid section must not be stored")
		return nil
	})

	err := f.svc.PatchGroup(context.Background(), port.PatchGroupCommand{
		TenantID: f.tenantID, ID: before.ID, Section: port.GroupSectionRedirects,
		RedirectURIs: []string{"http://insecure.example.com/cb"},
	})

	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr.Fields, "redirect_uris")
}

func TestApplicationService_PatchGroup_SystemGroupsOnlyAcceptSignIn(t *testing.T) {
	ssoID, newSSO := uuid.New(), uuid.New()
	f := newAppServiceFixture(t)
	system := storedGroup(ssoID)
	system.IsSystem = true
	system.GroupName = model.AdminUIGroupName
	f.stubGroup(system)
	f.stubProviders(
		model.IdentityProvider{ID: ssoID, IDPType: model.OpenIDConnectIDPType},
		model.IdentityProvider{ID: newSSO, IDPType: model.OpenIDConnectIDPType},
	)

	t.Run("other sections are refused", func(t *testing.T) {
		err := f.svc.PatchGroup(context.Background(), port.PatchGroupCommand{
			TenantID: f.tenantID, ID: system.ID, Section: port.GroupSectionRedirects, RedirectURIs: []string{"https://evil.example/cb"},
		})
		assert.ErrorIs(t, err, port.ErrSystemManaged)
	})

	t.Run("sign-in is accepted", func(t *testing.T) {
		f.admin.UpdateApplicationGroupMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, g model.ApplicationGroup) error {
			assert.ElementsMatch(t, []uuid.UUID{ssoID, newSSO}, g.AllowedIDPIDs)
			assert.Equal(t, system.RedirectURIs, g.RedirectURIs)
			return nil
		})
		err := f.svc.PatchGroup(context.Background(), port.PatchGroupCommand{
			TenantID: f.tenantID, ID: system.ID, Section: port.GroupSectionSignIn,
			AllowedIDPIDs: []uuid.UUID{ssoID, newSSO}, DefaultIDPID: &ssoID,
		})
		require.NoError(t, err)
	})
}

func TestApplicationService_PatchGroup_UnknownSection(t *testing.T) {
	f := newAppServiceFixture(t)
	group := storedGroup(uuid.New())
	f.stubGroup(group)

	err := f.svc.PatchGroup(context.Background(), port.PatchGroupCommand{TenantID: f.tenantID, ID: group.ID, Section: "bogus"})

	var verr *port.ValidationError
	require.ErrorAs(t, err, &verr)
}
