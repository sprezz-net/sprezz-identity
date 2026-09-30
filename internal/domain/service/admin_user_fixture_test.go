package service_test

import (
	"context"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"
	"sprezz-identity/internal/domain/service"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

// errNotFound is what storage reports for a missing user.
var errNotFound = port.ErrUserProfileNotFound

const (
	userTestPartition      = int64(7)
	userTestAdminPartition = int64(9)
)

type userFixture struct {
	svc      *service.AdminUserService
	storage  *portmock.StorageMock
	admin    *portmock.AdminStorageMock
	crypto   *portmock.CryptoMock
	tenantID uuid.UUID
}

func newUserFixture(t *testing.T) *userFixture {
	t.Helper()
	mc := minimock.NewController(t)
	storage, admin, crypto := portmock.NewStorageMock(mc), portmock.NewAdminStorageMock(mc), portmock.NewCryptoMock(mc)
	f := &userFixture{
		svc:      service.NewAdminUserService(storage, admin, crypto, portmock.NewMockClock(time.Now())),
		storage:  storage,
		admin:    admin,
		crypto:   crypto,
		tenantID: uuid.New(),
	}
	storage.GetPartitionsMock.Optional().Return([]model.Partition{
		{ID: userTestPartition, Name: "customers", AliasName: "customers"},
		{ID: userTestAdminPartition, Name: "admins", AliasName: model.AdminPartitionAliasName},
	}, nil)
	return f
}

func (f *userFixture) user(username string, partition int64) model.UserProfile {
	return model.UserProfile{
		ID: uuid.New(), TenantID: f.tenantID, PartitionID: partition, PreferredUsername: username,
		FirstName: "First", LastName: "Last", Name: "First Last", Email: username + "@example.com",
		LifecycleState: model.LifecycleActivated,
	}
}

// stubUsers makes the storage return exactly these users, by ID and as a partition listing.
func (f *userFixture) stubUsers(users ...model.UserProfile) {
	f.storage.GetUserProfileByIDMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, part int64, id uuid.UUID) (*model.UserProfile, error) {
		for _, u := range users {
			if u.ID == id && u.PartitionID == part {
				clone := u
				return &clone, nil
			}
		}
		return nil, errNotFound
	})
	f.admin.GetUserProfilesByTenantMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, part int64) ([]model.UserProfile, error) {
		var out []model.UserProfile
		for _, u := range users {
			if u.PartitionID == part {
				out = append(out, u)
			}
		}
		return out, nil
	})
}

// captureUpdate records the profile written by UpdateUserProfile.
func (f *userFixture) captureUpdate() *model.UserProfile {
	saved := &model.UserProfile{}
	f.admin.UpdateUserProfileMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, part int64, p model.UserProfile) error {
		*saved = p
		return nil
	})
	return saved
}

// noConflicts reports that no other user holds the username or email address.
func (f *userFixture) noConflicts() {
	f.storage.GetUserProfileByPreferredUsernameMock.Optional().Return(nil, errNotFound)
	f.storage.FindProfileByEmailMock.Optional().Return(nil, errNotFound)
}
