package http

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserSection_ProfileSavesTheNamedUserAndAnswersWithThatCard(t *testing.T) {
	f := newPagesFixture(t)
	u := testUser("ann")
	f.stubUserPage(u, port.UserDetail{})
	var got port.PatchUserCommand
	f.users.PatchUserMock.Set(func(ctx context.Context, cmd port.PatchUserCommand) error {
		got = cmd
		return nil
	})

	rec := f.do(http.MethodPut, userPath(u)+"/profile", url.Values{
		"username": {"ann2"}, "first_name": {"Ann"}, "last_name": {"Lee"}, "email": {"ann2@example.com"},
	}, htmx())

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, u.ID, got.ID, "the save names the user from the URL")
	assert.Equal(t, testUserPartition, got.PartitionID)
	assert.Equal(t, f.userID, got.ActingUserID, "the signed-in administrator is passed to the guards")
	assert.Equal(t, port.UserSectionProfile, got.Section)
	assert.Equal(t, "ann2", got.Username)
	body := rec.Body.String()
	assert.Contains(t, body, `id="section-profile"`)
	assert.NotContains(t, body, `id="section-status"`, "only the saved card is returned")
}

func TestUserSection_StatusParsesTheFlags(t *testing.T) {
	f := newPagesFixture(t)
	u := testUser("ann")
	f.stubUserPage(u, port.UserDetail{})
	var got port.PatchUserCommand
	f.users.PatchUserMock.Set(func(ctx context.Context, cmd port.PatchUserCommand) error {
		got = cmd
		return nil
	})

	f.do(http.MethodPut, userPath(u)+"/status", url.Values{"lifecycle": {"DEACTIVATED"}, "blocked": {"true"}}, htmx())

	assert.Equal(t, model.LifecycleDeactivated, got.Lifecycle)
	assert.True(t, got.Blocked)
	assert.False(t, got.EmailVerified, "an unchecked box means false")
}

func TestUserSection_PasswordIsNeverReturned(t *testing.T) {
	f := newPagesFixture(t)
	u := testUser("ann")
	f.stubUserPage(u, port.UserDetail{HasPassword: true})
	f.users.PatchUserMock.Return(nil)

	rec := f.do(http.MethodPut, userPath(u)+"/password", url.Values{"new_password": {"brand-new-secret"}}, htmx())

	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), "brand-new-secret")
}

func TestUserSection_ServiceErrorsAreSanitized(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		text   string
	}{
		"own account": {port.ErrOwnAccount, http.StatusConflict, port.ErrOwnAccount.Error()},
		"last admin":  {port.ErrLastAdministrator, http.StatusConflict, port.ErrLastAdministrator.Error()},
		"unexpected":  {errors.New("pq: password authentication failed for user sprezz_db"), http.StatusInternalServerError, "an unexpected error occurred"},
		"validation": {func() error {
			v := port.NewValidationError()
			v.Add("lifecycle", "choose a valid account state")
			return v
		}(), http.StatusUnprocessableEntity, "choose a valid account state"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newPagesFixture(t)
			u := testUser("ann")
			f.stubUserPage(u, port.UserDetail{})
			f.users.PatchUserMock.Return(tc.err)

			rec := f.do(http.MethodPut, userPath(u)+"/status", url.Values{"lifecycle": {"ACTIVATED"}}, htmx())

			assert.Equal(t, tc.status, rec.Code)
			assert.Contains(t, rec.Body.String(), tc.text)
			assert.NotContains(t, rec.Body.String(), "sprezz_db")
		})
	}
}

func TestUserSection_UnknownSection(t *testing.T) {
	f := newPagesFixture(t)
	u := testUser("ann")
	f.stubUserPage(u, port.UserDetail{})
	assert.Equal(t, http.StatusNotFound, f.do(http.MethodPut, userPath(u)+"/bogus", url.Values{}, htmx()).Code)
}
