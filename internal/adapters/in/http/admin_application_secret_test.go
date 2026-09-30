package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createForm(groupID, profileID uuid.UUID) url.Values {
	return url.Values{
		"application_name": {"Shop"},
		"client_id":        {"shop-1"},
		"group_id":         {groupID.String()},
		"profile_id":       {profileID.String()},
	}
}

func TestApplicationCreate_ConfidentialClientShowsTheSecretOnceInsideTheTransaction(t *testing.T) {
	f := newPagesFixture(t)
	groupID, profileID := uuid.New(), uuid.New()
	f.apps.GetProfileMock.Return(&model.ApplicationProfile{ID: profileID, TokenEndpointAuthMethod: model.AuthMethodClientSecretPost}, nil)
	f.apps.CreateApplicationMock.Set(func(ctx context.Context, cmd port.CreateApplicationCommand) (*model.Application, error) {
		require.NotNil(t, cmd.OnDelivery)
		require.NoError(t, cmd.OnDelivery("s3cr3t-value"))
		return &model.Application{ClientID: cmd.ClientID}, nil
	})

	rec := f.do(http.MethodPost, "/admin/applications", createForm(groupID, profileID), htmx())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "s3cr3t-value")
	assert.Contains(t, rec.Body.String(), "shown only once")
	assert.Empty(t, rec.Header().Get(model.HeaderHxRedirect), "the secret page must not be replaced by a redirect")
}

func TestApplicationCreate_PublicClientRedirectsWithoutASecret(t *testing.T) {
	f := newPagesFixture(t)
	groupID, profileID := uuid.New(), uuid.New()
	f.apps.GetProfileMock.Return(&model.ApplicationProfile{ID: profileID, TokenEndpointAuthMethod: model.AuthMethodNone}, nil)
	f.apps.CreateApplicationMock.Set(func(ctx context.Context, cmd port.CreateApplicationCommand) (*model.Application, error) {
		require.NoError(t, cmd.OnDelivery(""))
		return &model.Application{ClientID: cmd.ClientID}, nil
	})

	rec := f.do(http.MethodPost, "/admin/applications", createForm(groupID, profileID), htmx())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get(model.HeaderHxRedirect), "/admin/applications/shop-1")
	assert.NotContains(t, rec.Body.String(), "shown only once")
}

func TestApplicationCreate_ValidatesTheFormBeforeTouchingTheUseCase(t *testing.T) {
	f := newPagesFixture(t)
	f.apps.GetGroupsMock.Optional().Return(nil, nil)
	f.apps.GetProfilesMock.Optional().Return(nil, nil)
	f.apps.CreateApplicationMock.Optional().Set(func(ctx context.Context, cmd port.CreateApplicationCommand) (*model.Application, error) {
		t.Error("an invalid form must not create anything")
		return nil, nil
	})

	rec := f.do(http.MethodPost, "/admin/applications", url.Values{
		"application_name": {""},
		"client_id":        {"has spaces!"},
		"group_id":         {""},
		"profile_id":       {"x"},
	}, htmx())

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "an application name is required")
	assert.Contains(t, body, "use letters, digits and - _ . ~ only")
	assert.Contains(t, body, "choose a group")
	assert.Contains(t, body, "choose a profile")
}

func TestApplicationCreate_DuplicateClientIDIsAFieldError(t *testing.T) {
	f := newPagesFixture(t)
	groupID, profileID := uuid.New(), uuid.New()
	f.apps.GetProfileMock.Return(&model.ApplicationProfile{ID: profileID, TokenEndpointAuthMethod: model.AuthMethodNone}, nil)
	f.apps.GetGroupsMock.Optional().Return(nil, nil)
	f.apps.GetProfilesMock.Optional().Return(nil, nil)
	f.apps.CreateApplicationMock.Return(nil, fmt.Errorf("storage: application client_id already exists: %w", port.ErrApplicationNotFound))

	rec := f.do(http.MethodPost, "/admin/applications", createForm(groupID, profileID), htmx())

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), "this client ID is already taken")
}

func TestApplicationCreate_UnexpectedFailuresAreSanitized(t *testing.T) {
	f := newPagesFixture(t)
	groupID, profileID := uuid.New(), uuid.New()
	f.apps.GetProfileMock.Return(&model.ApplicationProfile{ID: profileID, TokenEndpointAuthMethod: model.AuthMethodNone}, nil)
	f.apps.CreateApplicationMock.Return(nil, errors.New("pq: password authentication failed for user admin"))

	rec := f.do(http.MethodPost, "/admin/applications", createForm(groupID, profileID), htmx())

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "password authentication")
}

func TestApplicationResetSecret_ShowsTheNewSecretOnce(t *testing.T) {
	f := newPagesFixture(t)
	f.apps.ResetApplicationSecretMock.Set(func(ctx context.Context, cmd port.ResetApplicationSecretCommand) error {
		assert.Equal(t, "shop", cmd.ClientID)
		return cmd.OnDelivery("fresh-secret")
	})

	rec := f.do(http.MethodPost, "/admin/applications/shop/reset-secret", url.Values{}, htmx())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "fresh-secret")
}

func TestApplicationResetSecret_SystemApplicationIsForbidden(t *testing.T) {
	f := newPagesFixture(t)
	f.apps.ResetApplicationSecretMock.Return(port.ErrSystemManaged)

	rec := f.do(http.MethodPost, "/admin/applications/admin_ui/reset-secret", url.Values{}, htmx())

	assert.Equal(t, http.StatusForbidden, rec.Code)
}
