package http

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"sprezz-identity/internal/domain/port"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestUserDelete_RequiresTheTypedUsernameAndPassesTheActingAdmin(t *testing.T) {
	f := newPagesFixture(t)
	u := testUser("ann")
	f.stubUserPage(u, port.UserDetail{})
	var got port.DeleteUserCommand
	f.users.DeleteUserMock.Set(func(ctx context.Context, cmd port.DeleteUserCommand) error {
		got = cmd
		v := port.NewValidationError()
		v.Add("confirmation", "type the username exactly to confirm deletion")
		return v
	})

	rec := f.do(http.MethodDelete, userPath(u), url.Values{"confirmation": {"wrong"}}, htmx())

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), "type the username exactly")
	assert.Equal(t, "wrong", got.Confirmation, "the typed text reaches the service, which decides")
	assert.Equal(t, f.userID, got.ActingUserID)
	assert.Equal(t, u.ID, got.ID)
}

func TestUserDelete_ConfirmedDeletionRedirectsToTheList(t *testing.T) {
	f := newPagesFixture(t)
	u := testUser("ann")
	f.stubUserPage(u, port.UserDetail{})
	f.users.DeleteUserMock.Return(nil)

	rec := f.do(http.MethodDelete, userPath(u), url.Values{"confirmation": {"ann"}}, htmx())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("HX-Redirect"), "/admin/users?msg=")
}

func TestUserDelete_GuardErrorsAreShownInTheDangerZone(t *testing.T) {
	for _, guard := range []error{port.ErrOwnAccount, port.ErrLastAdministrator} {
		f := newPagesFixture(t)
		u := testUser("ann")
		f.stubUserPage(u, port.UserDetail{})
		f.users.DeleteUserMock.Return(guard)

		rec := f.do(http.MethodDelete, userPath(u), url.Values{"confirmation": {"ann"}}, htmx())

		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
		assert.Contains(t, rec.Body.String(), guard.Error())
	}
}

func TestUserUnlock_ReloadsThePage(t *testing.T) {
	f := newPagesFixture(t)
	u := testUser("ann")
	f.stubUserPage(u, port.UserDetail{})
	f.users.UnlockUserMock.Expect(minimock.AnyContext, f.tenantID, testUserPartition, u.ID).Return(nil)

	rec := f.do(http.MethodPost, userPath(u)+"/unlock", url.Values{}, htmx())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Account unlocked")
}

func TestUserUnlink_AnswersWithTheRefreshedListOrTheRefusal(t *testing.T) {
	f := newPagesFixture(t)
	u := testUser("ann")
	idp := uuid.New()
	f.stubUserPage(u, port.UserDetail{})
	f.users.UnlinkIdentityMock.Return(port.ErrLastSignInMethod)

	rec := f.do(http.MethodDelete, userPath(u)+"/identities/"+idp.String(), nil, htmx())

	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Contains(t, rec.Body.String(), port.ErrLastSignInMethod.Error())
	assert.Contains(t, rec.Body.String(), `id="section-links"`)
}

func TestUserUnlink_MalformedProvider(t *testing.T) {
	f := newPagesFixture(t)
	u := testUser("ann")
	f.stubUserPage(u, port.UserDetail{})
	assert.Equal(t, http.StatusNotFound, f.do(http.MethodDelete, userPath(u)+"/identities/not-a-uuid", nil, htmx()).Code)
}
