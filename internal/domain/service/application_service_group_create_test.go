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

func TestApplicationService_UpdateGroup_KeepsLocalIDPAndEnabledState(t *testing.T) {
	f := newAppServiceFixture(t)
	groupID := uuid.New()
	localID := uuid.New()
	ssoID := uuid.New()

	f.stubGroup(model.ApplicationGroup{ID: groupID, GroupName: "partners", IsEnabled: false})
	f.stubProviders(
		model.IdentityProvider{ID: localID, IDPType: model.UsernamePasswordIDPType},
		model.IdentityProvider{ID: ssoID, IDPType: model.OpenIDConnectIDPType},
	)

	f.admin.UpdateApplicationGroupMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, g model.ApplicationGroup) error {
		assert.Contains(t, g.AllowedIDPIDs, localID, "local login must survive an edit that posts the real local IdP UUID")
		assert.False(t, g.IsEnabled, "a plain edit must not re-enable a disabled group")
		return nil
	})

	err := f.svc.UpdateGroup(context.Background(), port.UpdateGroupCommand{
		TenantID:      f.tenantID,
		ID:            groupID,
		GroupName:     "partners",
		AllowedIDPIDs: []uuid.UUID{localID, ssoID},
		DefaultIDPID:  &localID,
	})
	require.NoError(t, err)
}

func TestApplicationService_CreateGroup_Validation(t *testing.T) {
	knownID := uuid.New()
	otherID := uuid.New()

	tests := []struct {
		name    string
		allowed []uuid.UUID
		def     *uuid.UUID
		field   string
	}{
		{name: "requires at least one provider", field: "allowed_idps"},
		{name: "rejects unknown provider", allowed: []uuid.UUID{knownID, uuid.New()}, field: "allowed_idps"},
		{name: "default must be allowed", allowed: []uuid.UUID{knownID}, def: &otherID, field: "default_idp_id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newAppServiceFixture(t)
			// An empty selection is rejected before any provider lookup happens.
			if len(tt.allowed) > 0 {
				f.stubProviders(model.IdentityProvider{ID: knownID, IDPType: model.OpenIDConnectIDPType})
			}

			err := f.svc.CreateGroup(context.Background(), port.CreateGroupCommand{
				TenantID:      f.tenantID,
				GroupName:     "new-group",
				AllowedIDPIDs: tt.allowed,
				DefaultIDPID:  tt.def,
			})

			var verr *port.ValidationError
			require.ErrorAs(t, err, &verr)
			assert.Contains(t, verr.Fields, tt.field)
		})
	}
}

func TestApplicationService_CreateGroup_NilUUIDDefaultIsDropped(t *testing.T) {
	f := newAppServiceFixture(t)
	knownID := uuid.New()
	nilID := uuid.Nil
	f.stubProviders(model.IdentityProvider{ID: knownID, IDPType: model.OpenIDConnectIDPType})

	f.admin.CreateApplicationGroupMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, g model.ApplicationGroup) error {
		assert.Nil(t, g.DefaultIDPID, "uuid.Nil must never be persisted as a default provider")
		return nil
	})

	err := f.svc.CreateGroup(context.Background(), port.CreateGroupCommand{
		TenantID:      f.tenantID,
		GroupName:     "new-group",
		AllowedIDPIDs: []uuid.UUID{knownID},
		DefaultIDPID:  &nilID,
	})
	require.NoError(t, err)
}

func TestApplicationService_UpdateGroup_NotFound(t *testing.T) {
	f := newAppServiceFixture(t)
	f.admin.GetApplicationGroupByIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) (*model.ApplicationGroup, error) {
		return nil, port.ErrGroupNotFound
	})

	err := f.svc.UpdateGroup(context.Background(), port.UpdateGroupCommand{TenantID: f.tenantID, ID: uuid.New()})
	assert.ErrorIs(t, err, port.ErrGroupNotFound)
}
