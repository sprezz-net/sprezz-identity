package service_test

import (
	"context"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (f *appServiceFixture) stubGroup(group model.ApplicationGroup) {
	f.admin.GetApplicationGroupByIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) (*model.ApplicationGroup, error) {
		return &group, nil
	})
}

func (f *appServiceFixture) stubProviders(providers ...model.IdentityProvider) {
	f.storage.GetIdentityProvidersByUUIDsMock.Set(func(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) ([]model.IdentityProvider, error) {
		return providers, nil
	})
}

func TestApplicationService_SystemProfile_IsProtected(t *testing.T) {
	f := newAppServiceFixture(t)
	profileID := uuid.New()

	f.admin.GetApplicationProfileByIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) (*model.ApplicationProfile, error) {
		return &model.ApplicationProfile{ID: profileID, IsSystem: true}, nil
	})

	err := f.svc.UpdateProfile(context.Background(), port.UpdateProfileCommand{TenantID: f.tenantID, ID: profileID})
	assert.ErrorIs(t, err, port.ErrSystemManaged)
}

func TestApplicationService_UpdateProfile_PreservesEnabledState(t *testing.T) {
	f := newAppServiceFixture(t)
	profileID := uuid.New()

	f.admin.GetApplicationProfileByIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) (*model.ApplicationProfile, error) {
		return &model.ApplicationProfile{ID: profileID, IsEnabled: false}, nil
	})
	f.admin.UpdateApplicationProfileMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, p model.ApplicationProfile) error {
		assert.False(t, p.IsEnabled)
		return nil
	})

	err := f.svc.UpdateProfile(context.Background(), port.UpdateProfileCommand{
		TenantID:                f.tenantID,
		ID:                      profileID,
		ProfileName:             "web",
		TokenEndpointAuthMethod: model.AuthMethodClientSecretPost,
		SigningAlgorithm:        model.AlgRS256,
		AccessTokenLifetime:     15 * time.Minute,
		IDTokenLifetime:         15 * time.Minute,
		RefreshTokenLifetime:    24 * time.Hour,
	})
	require.NoError(t, err)
}

func TestApplicationService_LocalAdminGroup_IsFullyLocked(t *testing.T) {
	f := newAppServiceFixture(t)
	groupID := uuid.New()
	f.stubGroup(model.ApplicationGroup{ID: groupID, GroupName: model.LocalAdminUIGroupName, IsSystem: true})

	err := f.svc.UpdateGroup(context.Background(), port.UpdateGroupCommand{
		TenantID:      f.tenantID,
		ID:            groupID,
		AllowedIDPIDs: []uuid.UUID{uuid.New()},
	})
	assert.ErrorIs(t, err, port.ErrSystemManaged)
}

func TestApplicationService_AdminGroup_AllowsOnlyFederatedIDPChanges(t *testing.T) {
	f := newAppServiceFixture(t)
	groupID := uuid.New()
	oldSSO := uuid.New()
	newSSO := uuid.New()

	existing := model.ApplicationGroup{
		ID:            groupID,
		GroupName:     model.AdminUIGroupName,
		IsSystem:      true,
		IsEnabled:     true,
		RedirectURIs:  []string{"https://admin.example/callback"},
		AllowedIDPIDs: []uuid.UUID{oldSSO},
		DefaultIDPID:  &oldSSO,
	}
	f.stubGroup(existing)
	f.stubProviders(
		model.IdentityProvider{ID: oldSSO, IDPType: model.OpenIDConnectIDPType},
		model.IdentityProvider{ID: newSSO, IDPType: model.OpenIDConnectIDPType},
	)

	f.admin.UpdateApplicationGroupMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, g model.ApplicationGroup) error {
		assert.ElementsMatch(t, []uuid.UUID{oldSSO, newSSO}, g.AllowedIDPIDs)
		// Everything other than the sign-in methods keeps its provisioned value.
		assert.Equal(t, existing.GroupName, g.GroupName)
		assert.Equal(t, existing.RedirectURIs, g.RedirectURIs)
		assert.True(t, g.IsSystem)
		return nil
	})

	err := f.svc.UpdateGroup(context.Background(), port.UpdateGroupCommand{
		TenantID:      f.tenantID,
		ID:            groupID,
		GroupName:     "attempted rename",
		RedirectURIs:  []string{"https://evil.example/callback"},
		AllowedIDPIDs: []uuid.UUID{oldSSO, newSSO},
		DefaultIDPID:  &oldSSO,
	})
	require.NoError(t, err)
}

func TestApplicationService_AdminGroup_RejectsLocalAndEmpty(t *testing.T) {
	groupID := uuid.New()
	localID := uuid.New()

	tests := []struct {
		name      string
		allowed   []uuid.UUID
		providers []model.IdentityProvider
	}{
		{
			name:      "local accounts are not allowed",
			allowed:   []uuid.UUID{localID},
			providers: []model.IdentityProvider{{ID: localID, IDPType: model.UsernamePasswordIDPType}},
		},
		{name: "last sign-in method cannot be removed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newAppServiceFixture(t)
			f.stubGroup(model.ApplicationGroup{ID: groupID, GroupName: model.AdminUIGroupName, IsSystem: true})
			if len(tt.providers) > 0 {
				f.stubProviders(tt.providers...)
			}

			err := f.svc.UpdateGroup(context.Background(), port.UpdateGroupCommand{
				TenantID:      f.tenantID,
				ID:            groupID,
				AllowedIDPIDs: tt.allowed,
			})

			var verr *port.ValidationError
			require.ErrorAs(t, err, &verr)
			assert.Contains(t, verr.Fields, "allowed_idps")
		})
	}
}
