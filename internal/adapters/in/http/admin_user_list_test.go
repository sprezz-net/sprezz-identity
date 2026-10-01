package http

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserList_FiltersAndLinksToRoutedPages(t *testing.T) {
	f := newPagesFixture(t)
	ann, bob, cy := testUser("ann"), testUser("bob"), testUser("cy")
	bob.Blocked = true
	cy.LifecycleState = model.LifecycleRequested
	f.storage.GetPartitionsMock.Optional().Return([]model.Partition{{ID: testUserPartition, Name: "customers"}}, nil)
	f.users.ListUsersMock.Optional().Return([]model.UserProfile{ann, bob, cy}, nil)

	all := f.do(http.MethodGet, "/admin/users", nil, htmx()).Body.String()
	assert.Contains(t, all, `href="`+userPath(ann)+`"`, "rows link to routed pages, not modals")

	assert.NotContains(t, f.do(http.MethodGet, "/admin/users?status=blocked", nil, htmx()).Body.String(), ">ann<")
	assert.Contains(t, f.do(http.MethodGet, "/admin/users?status=blocked", nil, htmx()).Body.String(), ">bob<")
	assert.Contains(t, f.do(http.MethodGet, "/admin/users?status=pending", nil, htmx()).Body.String(), ">cy<")
	assert.NotContains(t, f.do(http.MethodGet, "/admin/users?q=BOB", nil, htmx()).Body.String(), ">ann<", "search ignores case")
	assert.Contains(t, f.do(http.MethodGet, "/admin/users?q=nomatch", nil, htmx()).Body.String(), "No users found")
}

func TestUserList_PassesThePartitionFilterToTheService(t *testing.T) {
	f := newPagesFixture(t)
	var got int64
	f.storage.GetPartitionsMock.Optional().Return(nil, nil)
	f.users.ListUsersMock.Set(func(ctx context.Context, tID uuid.UUID, part int64) ([]model.UserProfile, error) {
		got = part
		return nil, nil
	})

	f.do(http.MethodGet, "/admin/users?partition_id=7", nil, htmx())
	assert.Equal(t, testUserPartition, got)
}

func TestUserNew_AndCreate(t *testing.T) {
	f := newPagesFixture(t)
	f.storage.GetPartitionsMock.Optional().Return([]model.Partition{{ID: testUserPartition, Name: "customers"}}, nil)

	form := f.do(http.MethodGet, "/admin/users/new", nil, htmx()).Body.String()
	assert.Contains(t, form, `name="username"`)
	assert.Contains(t, form, `name="password"`)

	created := testUser("dee")
	f.users.CreateUserMock.Set(func(ctx context.Context, cmd port.CreateUserCommand) (*model.UserProfile, error) {
		assert.Equal(t, "dee", cmd.Username)
		assert.Equal(t, "s3cret-pass", cmd.Password)
		assert.Equal(t, testUserPartition, cmd.PartitionID)
		return &created, nil
	})
	rec := f.do(http.MethodPost, "/admin/users", url.Values{
		"partition_id": {"7"}, "username": {"dee"}, "email": {"dee@example.com"}, "password": {"s3cret-pass"},
	}, htmx())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("HX-Redirect"), userPath(created))
}

func TestUserCreate_ErrorsKeepInputButNeverThePassword(t *testing.T) {
	f := newPagesFixture(t)
	verr := port.NewValidationError()
	verr.Add("username", port.ErrUsernameAlreadyExists.Error())
	f.users.CreateUserMock.Return(nil, verr)
	f.storage.GetPartitionsMock.Optional().Return([]model.Partition{{ID: testUserPartition, Name: "customers"}}, nil)

	rec := f.do(http.MethodPost, "/admin/users", url.Values{
		"partition_id": {"7"}, "username": {"dee"}, "email": {"dee@example.com"}, "password": {"typed-secret-1"},
	}, htmx())

	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, port.ErrUsernameAlreadyExists.Error())
	assert.Contains(t, body, `value="dee"`)
	assert.NotContains(t, body, "typed-secret-1")
}
