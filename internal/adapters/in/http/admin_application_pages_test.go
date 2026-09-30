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

func testApplication(groupID, profileID uuid.UUID) model.ApplicationDetailsProps {
	return model.ApplicationDetailsProps{
		Application: &model.Application{
			ID: uuid.New(), ClientID: "shop", ApplicationName: "Shop", IsEnabled: true, GroupID: groupID, ProfileID: profileID,
		},
		ApplicationProfile: &model.ApplicationProfile{ID: profileID, ProfileName: "web", TokenEndpointAuthMethod: model.AuthMethodClientSecretPost},
		ApplicationGroup:   &model.ApplicationGroup{ID: groupID, GroupName: "partners"},
	}
}

func (f *pagesFixture) stubApplicationPage(d model.ApplicationDetailsProps) {
	f.apps.GetApplicationMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, clientID string) (*model.ApplicationDetailsProps, error) {
		clone := d
		app := *d.Application
		clone.Application = &app
		return &clone, nil
	})
	f.apps.GetProfilesMock.Optional().Set(func(ctx context.Context, tID uuid.UUID) ([]model.ApplicationProfile, error) {
		return []model.ApplicationProfile{*d.ApplicationProfile}, nil
	})
	f.apps.GetGroupsMock.Optional().Set(func(ctx context.Context, tID uuid.UUID) ([]model.ApplicationGroup, error) {
		return []model.ApplicationGroup{*d.ApplicationGroup}, nil
	})
}

func TestApplicationRoutes_StaticPathsAreNotSwallowedByTheClientIDRoute(t *testing.T) {
	f := newPagesFixture(t)
	f.stubDashboard(0, nil, nil)
	f.apps.GetGroupsMock.Optional().Return(nil, nil)
	f.apps.GetProfilesMock.Optional().Return(nil, nil)
	f.idps.GetPartitionsWithProvidersMock.Optional().Return(nil, nil)

	for _, path := range []string{"/admin/applications/new", "/admin/applications/groups", "/admin/applications/profiles", "/admin/applications/groups/new", "/admin/applications/profiles/new"} {
		rec := f.do(http.MethodGet, path, nil, htmx())
		assert.Equal(t, http.StatusOK, rec.Code, path)
	}
}

func TestApplicationDetail_ShowsCardsAndLinksToGroupAndProfile(t *testing.T) {
	f := newPagesFixture(t)
	groupID, profileID := uuid.New(), uuid.New()
	f.stubApplicationPage(testApplication(groupID, profileID))

	body := f.do(http.MethodGet, "/admin/applications/shop", nil, nil).Body.String()

	assert.Contains(t, body, `id="section-general"`)
	assert.Contains(t, body, `id="section-policy"`)
	assert.Contains(t, body, `id="section-credentials"`)
	assert.Contains(t, body, "/admin/applications/groups/"+groupID.String())
	assert.Contains(t, body, "/admin/applications/profiles/"+profileID.String())
}

func TestApplicationDetail_SystemApplicationHasNoDestructiveControls(t *testing.T) {
	f := newPagesFixture(t)
	d := testApplication(uuid.New(), uuid.New())
	d.Application.IsSystem = true
	f.stubApplicationPage(d)

	body := f.do(http.MethodGet, "/admin/applications/shop", nil, nil).Body.String()

	assert.Contains(t, body, "Managed by Sprezz")
	assert.NotContains(t, body, "Danger zone")
	assert.NotContains(t, body, "Reset secret")
	assert.Contains(t, body, "<fieldset disabled", "the cards render read-only")
}

func TestApplicationSection_GeneralKeepsTheEnabledFlagExplicit(t *testing.T) {
	f := newPagesFixture(t)
	f.stubApplicationPage(testApplication(uuid.New(), uuid.New()))

	var got port.UpdateApplicationCommand
	f.apps.UpdateApplicationMock.Set(func(ctx context.Context, cmd port.UpdateApplicationCommand) error {
		got = cmd
		return nil
	})

	// An unchecked checkbox is simply absent from the form, which means "disabled".
	rec := f.do(http.MethodPut, "/admin/applications/shop/general", url.Values{"application_name": {"  Renamed "}}, htmx())

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "Renamed", got.ApplicationName)
	require.NotNil(t, got.IsEnabled)
	assert.False(t, *got.IsEnabled)
}

func TestApplicationSection_PolicyRequiresBothChoices(t *testing.T) {
	f := newPagesFixture(t)
	f.stubApplicationPage(testApplication(uuid.New(), uuid.New()))
	f.apps.UpdateApplicationMock.Optional().Set(func(ctx context.Context, cmd port.UpdateApplicationCommand) error {
		t.Error("an unparseable group must not reach the use case")
		return nil
	})

	rec := f.do(http.MethodPut, "/admin/applications/shop/policy", url.Values{"group_id": {"nonsense"}, "profile_id": {uuid.NewString()}}, htmx())

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), "choose a group")
}

func TestApplicationSection_UnknownSection(t *testing.T) {
	f := newPagesFixture(t)
	assert.Equal(t, http.StatusNotFound, f.do(http.MethodPut, "/admin/applications/shop/credentials", url.Values{}, nil).Code)
}
