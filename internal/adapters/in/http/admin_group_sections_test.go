package http

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"sprezz-identity/internal/domain/port"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGroupSection_SaveRerendersOnlyThatCard(t *testing.T) {
	f := newPagesFixture(t)
	g := testGroup()
	f.stubGroupPage(g, nil)

	var got port.PatchGroupCommand
	f.apps.PatchGroupMock.Set(func(ctx context.Context, cmd port.PatchGroupCommand) error {
		got = cmd
		return nil
	})

	rec := f.do(http.MethodPut, "/admin/applications/groups/"+g.ID.String()+"/redirects", url.Values{
		"redirect_uris":        {"https://b.example.com/cb", " https://c.example.com/cb "},
		"default_redirect_uri": {"https://c.example.com/cb"},
	}, htmx())

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, port.GroupSectionRedirects, got.Section)
	assert.Equal(t, []string{"https://b.example.com/cb", "https://c.example.com/cb"}, got.RedirectURIs)
	assert.Equal(t, "https://c.example.com/cb", got.DefaultRedirectURI)
	assert.Equal(t, g.ID, got.ID)
	assert.Equal(t, f.tenantID, got.TenantID)
	assert.Contains(t, rec.Body.String(), `id="section-redirects"`)
	assert.NotContains(t, rec.Body.String(), `id="section-scopes"`, "other cards are untouched")
	assert.Contains(t, rec.Body.String(), "Saved")
}

func TestGroupSection_ValidationErrorKeepsTypedValues(t *testing.T) {
	f := newPagesFixture(t)
	g := testGroup()
	f.stubGroupPage(g, nil)

	verr := port.NewValidationError()
	verr.Add("redirect_uris", "http://bad.example.com/cb: plain http is only allowed for localhost")
	f.apps.PatchGroupMock.Return(verr)

	rec := f.do(http.MethodPut, "/admin/applications/groups/"+g.ID.String()+"/redirects", url.Values{
		"redirect_uris": {"http://bad.example.com/cb"},
	}, htmx())

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, "true", rec.Header().Get(headerAdminFragment), "the admin script must swap this response in")
	assert.Contains(t, rec.Body.String(), "plain http is only allowed")
	assert.Contains(t, rec.Body.String(), "http://bad.example.com/cb", "the rejected value stays in the form")
}

func TestGroupSection_UnknownSectionAndBadUUIDs(t *testing.T) {
	f := newPagesFixture(t)
	g := testGroup()
	f.stubGroupPage(g, nil)

	assert.Equal(t, http.StatusNotFound, f.do(http.MethodPut, "/admin/applications/groups/"+g.ID.String()+"/bogus", url.Values{}, nil).Code)

	f.apps.PatchGroupMock.Optional().Set(func(ctx context.Context, cmd port.PatchGroupCommand) error {
		t.Error("a malformed identifier must be rejected before the use case runs")
		return nil
	})
	rec := f.do(http.MethodPut, "/admin/applications/groups/"+g.ID.String()+"/signin", url.Values{"allowed_idps": {"not-a-uuid"}}, htmx())
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestGroupSection_SystemGroupRefusalIsForbidden(t *testing.T) {
	f := newPagesFixture(t)
	g := testGroup()
	f.stubGroupPage(g, nil)
	f.apps.PatchGroupMock.Return(port.ErrSystemManaged)

	rec := f.do(http.MethodPut, "/admin/applications/groups/"+g.ID.String()+"/general", url.Values{"group_name": {"x"}}, htmx())

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "managed by the system")
}
