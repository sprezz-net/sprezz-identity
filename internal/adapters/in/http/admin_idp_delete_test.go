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
)

func TestIDPDelete_RequiresTheTypedAlias(t *testing.T) {
	f := newPagesFixture(t)
	p := testIDP()
	f.stubIDPPage(p, model.IdentityProviderUsage{LinkedUsers: 2})
	f.idps.DeleteIdentityProviderMock.Optional().Set(func(ctx context.Context, tID, id uuid.UUID) error {
		t.Error("deleting without the typed alias must not reach the service")
		return nil
	})

	rec := f.do(http.MethodDelete, "/admin/idps/"+p.ID.String(), url.Values{"confirmation": {"wrong"}}, htmx())

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), "Type the provider alias exactly")
}

func TestIDPDelete_ConfirmedDeletionRedirectsToTheList(t *testing.T) {
	f := newPagesFixture(t)
	p := testIDP()
	f.stubIDPPage(p, model.IdentityProviderUsage{})
	f.idps.DeleteIdentityProviderMock.Return(nil)

	rec := f.do(http.MethodDelete, "/admin/idps/"+p.ID.String(), url.Values{"confirmation": {p.Alias}}, htmx())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("HX-Redirect"), "/admin/idps?msg=")
}

func TestIDPDelete_RefusedWhenInUse(t *testing.T) {
	f := newPagesFixture(t)
	p := testIDP()
	f.stubIDPPage(p, model.IdentityProviderUsage{})
	f.idps.DeleteIdentityProviderMock.Return(port.ErrInUse)

	rec := f.do(http.MethodDelete, "/admin/idps/"+p.ID.String(), url.Values{"confirmation": {p.Alias}}, htmx())

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), port.ErrInUse.Error())
}

func TestIDPDetail_DangerZoneWarnsAboutLinkedUsersAndBlocksWhenAllowedByGroups(t *testing.T) {
	f := newPagesFixture(t)
	p := testIDP()

	f.stubIDPPage(p, model.IdentityProviderUsage{LinkedUsers: 9})
	body := f.do(http.MethodGet, "/admin/idps/"+p.ID.String(), nil, nil).Body.String()
	assert.Contains(t, body, "9 user(s) have signed in with it")
	assert.Contains(t, body, `hx-delete="/admin/idps/`+p.ID.String()+`"`)

	blocked := newPagesFixture(t)
	blocked.stubIDPPage(p, model.IdentityProviderUsage{GroupNames: []string{"Staff"}})
	body = blocked.do(http.MethodGet, "/admin/idps/"+p.ID.String(), nil, nil).Body.String()
	assert.Contains(t, body, "allowed by 1 group(s): Staff")
	assert.NotContains(t, body, `hx-delete=`)
}
