package http

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestProfileDelete_NeedsTheTypedName(t *testing.T) {
	f := newPagesFixture(t)
	p := testProfile()
	f.stubProfilePage(p, nil)
	f.apps.DeleteProfileMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, id uuid.UUID) error {
		t.Error("a wrong confirmation must not delete anything")
		return nil
	})

	rec := f.do(http.MethodDelete, "/admin/applications/profiles/"+p.ID.String(), url.Values{"confirmation": {"nope"}}, htmx())

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), "Type the profile name exactly")
}

func TestProfileDelete_SuccessRedirectsToTheList(t *testing.T) {
	f := newPagesFixture(t)
	p := testProfile()
	f.stubProfilePage(p, nil)
	f.apps.DeleteProfileMock.Return(nil)

	rec := f.do(http.MethodDelete, "/admin/applications/profiles/"+p.ID.String(), url.Values{"confirmation": {"web"}}, htmx())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get(model.HeaderHxRedirect), "/admin/applications/profiles?msg=")
}

func TestProfileDelete_InUseIsReportedInTheDangerZone(t *testing.T) {
	f := newPagesFixture(t)
	p := testProfile()
	f.stubProfilePage(p, nil)
	f.apps.DeleteProfileMock.Return(port.ErrInUse)

	rec := f.do(http.MethodDelete, "/admin/applications/profiles/"+p.ID.String(), url.Values{"confirmation": {"web"}}, htmx())

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), "still in use")
}

func TestProfileCreate_RedirectsToTheNewProfile(t *testing.T) {
	f := newPagesFixture(t)
	created := testProfile()
	f.apps.CreateProfileMock.Set(func(ctx context.Context, cmd port.CreateProfileCommand) (*model.ApplicationProfile, error) {
		assert.Equal(t, 15*time.Minute, cmd.AccessTokenLifetime, "new profiles start with secure defaults")
		assert.Equal(t, "web", cmd.ProfileName)
		return &created, nil
	})

	rec := f.do(http.MethodPost, "/admin/applications/profiles", url.Values{
		"profile_name":               {"web"},
		"token_endpoint_auth_method": {"client_secret_post"},
		"signing_algorithm":          {"RS256"},
		"grant_types":                {"authorization_code"},
	}, htmx())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get(model.HeaderHxRedirect), "/admin/applications/profiles/"+created.ID.String())
}

func TestProfileCreate_ValidationErrorsKeepTheFormValues(t *testing.T) {
	f := newPagesFixture(t)
	verr := port.NewValidationError()
	verr.Add("profile_name", "a profile name is required")
	f.apps.CreateProfileMock.Return(nil, verr)

	rec := f.do(http.MethodPost, "/admin/applications/profiles", url.Values{
		"profile_name":               {""},
		"token_endpoint_auth_method": {"none"},
		"signing_algorithm":          {"ES256"},
	}, htmx())

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), "a profile name is required")
	assert.Contains(t, rec.Body.String(), `value="none" selected`, "the chosen authentication method is kept")
}
