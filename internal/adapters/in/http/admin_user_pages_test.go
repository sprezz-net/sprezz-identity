package http

import (
	"context"
	"net/http"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testUserPartition = int64(7)

func testUser(username string) model.UserProfile {
	return model.UserProfile{
		ID: uuid.New(), PartitionID: testUserPartition, PreferredUsername: username, FirstName: "Ann", LastName: "Lee", Name: "Ann Lee",
		Email: username + "@example.com", EmailVerified: true, LifecycleState: model.LifecycleActivated, CreatedAt: time.Now(),
	}
}

func (f *pagesFixture) stubUserPage(u model.UserProfile, detail port.UserDetail) {
	detail.User = u
	f.users.GetUserMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, part int64, id uuid.UUID) (*port.UserDetail, error) {
		if id != u.ID || part != u.PartitionID {
			return nil, port.ErrUserProfileNotFound
		}
		clone := detail
		return &clone, nil
	})
	f.storage.GetPartitionsMock.Optional().Return([]model.Partition{{ID: testUserPartition, Name: "customers", AliasName: "customers"}}, nil)
}

func userPath(u model.UserProfile) string {
	return "/admin/users/7/" + u.ID.String()
}

func TestUserDetail_RendersCardsWithoutAnyPasswordMaterial(t *testing.T) {
	f := newPagesFixture(t)
	u := testUser("ann")
	f.stubUserPage(u, port.UserDetail{HasPassword: true})

	full := f.do(http.MethodGet, userPath(u), nil, nil)
	require.Equal(t, http.StatusOK, full.Code)
	body := full.Body.String()
	assert.Contains(t, body, "<html")
	for _, section := range []string{"profile", "status", "password"} {
		assert.Contains(t, body, `hx-put="`+userPath(u)+`/`+section+`"`)
	}
	assert.Contains(t, body, `id="section-links"`)
	assert.Contains(t, body, `name="new_password"`)
	assert.Regexp(t, `<input[^>]*name="new_password"[^>]*value=""`, body, "the password field is always empty")

	fragment := f.do(http.MethodGet, userPath(u), nil, htmx())
	assert.NotContains(t, fragment.Body.String(), "<html")
}

func TestUserDetail_AddressesUsersByPartitionAndID(t *testing.T) {
	f := newPagesFixture(t)
	u := testUser("ann")
	var gotPartition int64
	var gotID uuid.UUID
	f.storage.GetPartitionsMock.Optional().Return(nil, nil)
	f.users.GetUserMock.Set(func(ctx context.Context, tID uuid.UUID, part int64, id uuid.UUID) (*port.UserDetail, error) {
		gotPartition, gotID = part, id
		return &port.UserDetail{User: u}, nil
	})

	require.Equal(t, http.StatusOK, f.do(http.MethodGet, userPath(u), nil, htmx()).Code)
	assert.Equal(t, testUserPartition, gotPartition, "the partition comes from the path, not from a query string")
	assert.Equal(t, u.ID, gotID, "the user named in the URL is the one loaded")
}

func TestUserDetail_UnknownOrMalformedTarget(t *testing.T) {
	f := newPagesFixture(t)
	f.users.GetUserMock.Optional().Return(nil, port.ErrUserProfileNotFound)

	for _, path := range []string{"/admin/users/7/not-a-uuid", "/admin/users/x/" + uuid.NewString(), "/admin/users/0/" + uuid.NewString(), "/admin/users/7/" + uuid.NewString()} {
		assert.Equal(t, http.StatusNotFound, f.do(http.MethodGet, path, nil, nil).Code, path)
	}
}

func TestUserDetail_LockedAccountOffersUnlock(t *testing.T) {
	f := newPagesFixture(t)
	u := testUser("ann")
	until := time.Now().Add(time.Hour)
	f.stubUserPage(u, port.UserDetail{HasPassword: true, Locked: true, BlockedUntil: &until})

	body := f.do(http.MethodGet, userPath(u), nil, nil).Body.String()
	assert.Contains(t, body, "Unlock now")
	assert.Contains(t, body, `hx-post="`+userPath(u)+`/unlock"`)
}

func TestUserDetail_OwnAccountCannotBeDeletedFromTheUI(t *testing.T) {
	f := newPagesFixture(t)
	u := testUser("me")
	u.ID = f.userID // the signed-in administrator
	f.stubUserPage(u, port.UserDetail{})

	body := f.do(http.MethodGet, userPath(u), nil, nil).Body.String()
	assert.Contains(t, body, "You cannot delete the account you are signed in with")
	assert.NotContains(t, body, `hx-delete="`+userPath(u)+`"`)
}

func TestUserDetail_LinksOfferRemovalOnlyWhenSeveralExist(t *testing.T) {
	f := newPagesFixture(t)
	u := testUser("ann")
	sso, local := uuid.New(), uuid.New()
	links := []port.UserLink{
		{Identity: model.UserIdentity{IdentityProviderID: sso, CoupledAt: time.Now()}, ProviderName: "Corp", ProviderType: model.OpenIDConnectIDPType},
		{Identity: model.UserIdentity{IdentityProviderID: local, CoupledAt: time.Now()}, ProviderName: "Local", ProviderType: model.UsernamePasswordIDPType},
	}
	f.stubUserPage(u, port.UserDetail{Links: links})
	body := f.do(http.MethodGet, userPath(u), nil, nil).Body.String()
	assert.Contains(t, body, `hx-delete="`+userPath(u)+`/identities/`+sso.String()+`"`)

	single := newPagesFixture(t)
	single.stubUserPage(u, port.UserDetail{Links: links[:1]})
	assert.NotContains(t, single.do(http.MethodGet, userPath(u), nil, nil).Body.String(), "/identities/")
}
