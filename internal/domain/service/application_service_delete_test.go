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

func (f *appServiceFixture) stubGroupUsage(apps ...model.ApplicationSummary) {
	f.admin.GetApplicationsByGroupMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, groupID uuid.UUID) ([]model.ApplicationSummary, error) {
		return apps, nil
	})
}

func (f *appServiceFixture) stubProfileUsage(apps ...model.ApplicationSummary) {
	f.admin.GetApplicationsByProfileMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, profileID uuid.UUID) ([]model.ApplicationSummary, error) {
		return apps, nil
	})
}

func TestApplicationService_DeleteGroup(t *testing.T) {
	groupID := uuid.New()

	t.Run("unused group is removed", func(t *testing.T) {
		f := newAppServiceFixture(t)
		f.stubGroup(model.ApplicationGroup{ID: groupID, GroupName: "partners"})
		f.stubGroupUsage()
		f.admin.DeleteApplicationGroupMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) error {
			assert.Equal(t, groupID, id)
			return nil
		})

		require.NoError(t, f.svc.DeleteGroup(context.Background(), f.tenantID, groupID))
	})

	t.Run("group in use is refused", func(t *testing.T) {
		f := newAppServiceFixture(t)
		f.stubGroup(model.ApplicationGroup{ID: groupID, GroupName: "partners"})
		f.stubGroupUsage(model.ApplicationSummary{ClientID: "app-1"}, model.ApplicationSummary{ClientID: "app-2"})
		f.admin.DeleteApplicationGroupMock.Optional().Set(func(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) error {
			t.Error("a group in use must not reach the storage delete")
			return nil
		})

		err := f.svc.DeleteGroup(context.Background(), f.tenantID, groupID)
		assert.ErrorIs(t, err, port.ErrInUse)
		assert.Contains(t, err.Error(), "2 application(s)")
	})

	t.Run("system group is refused", func(t *testing.T) {
		f := newAppServiceFixture(t)
		f.stubGroup(model.ApplicationGroup{ID: groupID, GroupName: model.AdminUIGroupName, IsSystem: true})
		f.admin.GetApplicationsByGroupMock.Optional().Set(func(ctx context.Context, tenantUUID uuid.UUID, groupID uuid.UUID) ([]model.ApplicationSummary, error) {
			return nil, nil
		})
		f.admin.DeleteApplicationGroupMock.Optional().Set(func(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) error {
			t.Error("a system group must never be deleted")
			return nil
		})

		assert.ErrorIs(t, f.svc.DeleteGroup(context.Background(), f.tenantID, groupID), port.ErrSystemManaged)
	})

	t.Run("unknown group", func(t *testing.T) {
		f := newAppServiceFixture(t)
		f.admin.GetApplicationGroupByIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) (*model.ApplicationGroup, error) {
			return nil, port.ErrGroupNotFound
		})

		assert.ErrorIs(t, f.svc.DeleteGroup(context.Background(), f.tenantID, groupID), port.ErrGroupNotFound)
	})

	t.Run("storage reports a concurrent reference", func(t *testing.T) {
		f := newAppServiceFixture(t)
		f.stubGroup(model.ApplicationGroup{ID: groupID, GroupName: "partners"})
		f.stubGroupUsage()
		f.admin.DeleteApplicationGroupMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) error {
			return port.ErrInUse
		})

		assert.ErrorIs(t, f.svc.DeleteGroup(context.Background(), f.tenantID, groupID), port.ErrInUse)
	})
}

func TestApplicationService_DeleteProfile(t *testing.T) {
	profileID := uuid.New()

	stubProfile := func(f *appServiceFixture, p model.ApplicationProfile) {
		f.admin.GetApplicationProfileByIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) (*model.ApplicationProfile, error) {
			return &p, nil
		})
	}

	t.Run("unused profile is removed", func(t *testing.T) {
		f := newAppServiceFixture(t)
		stubProfile(f, model.ApplicationProfile{ID: profileID})
		f.stubProfileUsage()
		f.admin.DeleteApplicationProfileMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) error { return nil })

		require.NoError(t, f.svc.DeleteProfile(context.Background(), f.tenantID, profileID))
	})

	t.Run("profile in use is refused", func(t *testing.T) {
		f := newAppServiceFixture(t)
		stubProfile(f, model.ApplicationProfile{ID: profileID})
		f.stubProfileUsage(model.ApplicationSummary{ClientID: "app-1"})

		assert.ErrorIs(t, f.svc.DeleteProfile(context.Background(), f.tenantID, profileID), port.ErrInUse)
	})

	t.Run("system profile is refused", func(t *testing.T) {
		f := newAppServiceFixture(t)
		stubProfile(f, model.ApplicationProfile{ID: profileID, IsSystem: true})

		assert.ErrorIs(t, f.svc.DeleteProfile(context.Background(), f.tenantID, profileID), port.ErrSystemManaged)
	})
}

func TestApplicationService_ListApplicationsByGroupAndProfile(t *testing.T) {
	f := newAppServiceFixture(t)
	groupID, profileID := uuid.New(), uuid.New()
	want := []model.ApplicationSummary{{ClientID: "app-1", GroupID: groupID, ProfileID: profileID}}

	f.stubGroupUsage(want...)
	f.stubProfileUsage(want...)

	byGroup, err := f.svc.ListApplicationsByGroup(context.Background(), f.tenantID, groupID)
	require.NoError(t, err)
	assert.Equal(t, want, byGroup)

	byProfile, err := f.svc.ListApplicationsByProfile(context.Background(), f.tenantID, profileID)
	require.NoError(t, err)
	assert.Equal(t, want, byProfile)
}

func TestApplicationService_GetApplication(t *testing.T) {
	f := newAppServiceFixture(t)
	f.stubApplication(model.Application{ID: uuid.New(), ClientID: "app-1", ApplicationName: "My App"})

	details, err := f.svc.GetApplication(context.Background(), f.tenantID, "app-1")
	require.NoError(t, err)
	assert.Equal(t, "My App", details.Application.ApplicationName)
	assert.NotNil(t, details.ApplicationProfile)
	assert.NotNil(t, details.ApplicationGroup)
}
