package http

import (
	"context"
	"net/http"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func testGroup() model.ApplicationGroup {
	ssoID := uuid.New()
	return model.ApplicationGroup{
		ID:            uuid.New(),
		GroupName:     "partners",
		IsEnabled:     true,
		RedirectURI:   "https://a.example.com/cb",
		RedirectURIs:  []string{"https://a.example.com/cb"},
		AllowedScopes: []string{"openid"},
		DefaultScopes: []string{"openid"},
		AllowedIDPIDs: []uuid.UUID{ssoID},
	}
}

func (f *pagesFixture) stubGroupPage(g model.ApplicationGroup, used []model.ApplicationSummary) {
	f.apps.GetGroupMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, id uuid.UUID) (*model.ApplicationGroup, error) {
		clone := g
		return &clone, nil
	})
	f.apps.ListApplicationsByGroupMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, id uuid.UUID) ([]model.ApplicationSummary, error) {
		return used, nil
	})
	f.idps.GetPartitionsWithProvidersMock.Optional().Set(func(ctx context.Context, tID uuid.UUID) ([]model.PartitionWithProviders, error) {
		return []model.PartitionWithProviders{{PartitionID: 1, PartitionName: "default", Providers: []model.IdentityProvider{
			{ID: g.AllowedIDPIDs[0], IDPType: model.OpenIDConnectIDPType, Alias: "corp-sso", Enabled: true},
		}}}, nil
	})
}

func TestGroupDetail_FullPageAndFragment(t *testing.T) {
	f := newPagesFixture(t)
	g := testGroup()
	f.stubGroupPage(g, nil)
	path := "/admin/applications/groups/" + g.ID.String()

	full := f.do(http.MethodGet, path, nil, nil)
	assert.Equal(t, http.StatusOK, full.Code)
	assert.Contains(t, full.Body.String(), "<html", "a direct visit gets the whole document")
	assert.Contains(t, full.Body.String(), `id="section-redirects"`)
	assert.Contains(t, full.Body.String(), `hx-put="`+path+`/redirects"`)

	fragment := f.do(http.MethodGet, path, nil, htmx())
	assert.Equal(t, http.StatusOK, fragment.Code)
	assert.NotContains(t, fragment.Body.String(), "<html", "an htmx navigation only swaps the main area")
	assert.Contains(t, fragment.Body.String(), "partners")
}

func TestGroupDetail_CachingHeaders(t *testing.T) {
	f := newPagesFixture(t)
	g := testGroup()
	f.stubGroupPage(g, nil)

	rec := f.do(http.MethodGet, "/admin/applications/groups/"+g.ID.String(), nil, htmx())
	assert.Contains(t, rec.Header().Values("Vary"), "HX-Request", "caches must keep the two representations apart")
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

func TestGroupDetail_UnknownOrMalformedID(t *testing.T) {
	f := newPagesFixture(t)
	f.apps.GetGroupMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, id uuid.UUID) (*model.ApplicationGroup, error) {
		return nil, port.ErrGroupNotFound
	})

	assert.Equal(t, http.StatusNotFound, f.do(http.MethodGet, "/admin/applications/groups/not-a-uuid", nil, nil).Code)
	assert.Equal(t, http.StatusNotFound, f.do(http.MethodGet, "/admin/applications/groups/"+uuid.NewString(), nil, nil).Code)
}

func TestGroupDetail_SystemGroupIsReadOnly(t *testing.T) {
	f := newPagesFixture(t)
	g := testGroup()
	g.IsSystem = true
	g.GroupName = model.LocalAdminUIGroupName
	f.stubGroupPage(g, nil)

	body := f.do(http.MethodGet, "/admin/applications/groups/"+g.ID.String(), nil, nil).Body.String()

	assert.Contains(t, body, "Managed by Sprezz")
	assert.NotContains(t, body, `id="section-redirects"`, "no editable cards for a locked system group")
	assert.NotContains(t, body, "Danger zone")
}
