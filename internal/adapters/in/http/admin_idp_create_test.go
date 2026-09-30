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

func TestIDPNew_TypePickerThenForm(t *testing.T) {
	f := newPagesFixture(t)
	f.storage.GetPartitionsMock.Optional().Return([]model.Partition{{ID: 1, Name: "default"}}, nil)

	picker := f.do(http.MethodGet, "/admin/idps/new", nil, htmx()).Body.String()
	assert.Contains(t, picker, "/admin/idps/new?type=oidc")
	assert.NotContains(t, picker, `name="alias"`)

	form := f.do(http.MethodGet, "/admin/idps/new?type=oidc", nil, htmx()).Body.String()
	assert.Contains(t, form, `name="discovery_endpoint"`)
	assert.Contains(t, form, `name="alias"`)

	local := f.do(http.MethodGet, "/admin/idps/new?type=username-password", nil, htmx()).Body.String()
	assert.NotContains(t, local, `name="discovery_endpoint"`)

	bogus := f.do(http.MethodGet, "/admin/idps/new?type=evil", nil, htmx()).Body.String()
	assert.Contains(t, bogus, "/admin/idps/new?type=oidc", "an unknown type falls back to the picker")
}

func TestIDPCreate_RedirectsToTheNewProviderPage(t *testing.T) {
	f := newPagesFixture(t)
	newID := uuid.New()
	f.idps.CreateIdentityProviderMock.Set(func(ctx context.Context, tID uuid.UUID, p model.IdentityProvider) (*model.IdentityProvider, error) {
		assert.Equal(t, "corp", p.Alias)
		assert.Equal(t, idpSecret, p.Config.ClientSecret)
		p.ID = newID
		return &p, nil
	})

	rec := f.do(http.MethodPost, "/admin/idps", url.Values{
		"idp_type": {"oidc"}, "name": {"Corp"}, "alias": {"corp"}, "partition_id": {"1"},
		"discovery_endpoint": {"https://idp.example.com/.well-known/openid-configuration"}, "client_id": {"sprezz"}, "client_secret": {idpSecret},
	}, htmx())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("HX-Redirect"), "/admin/idps/"+newID.String())
}

func TestIDPCreate_ValidationErrorsKeepInputButNeverTheSecret(t *testing.T) {
	f := newPagesFixture(t)
	verr := port.NewValidationError()
	verr.Add("alias", "this partition already has a provider with that alias")
	f.idps.CreateIdentityProviderMock.Return(nil, verr)
	f.storage.GetPartitionsMock.Optional().Return([]model.Partition{{ID: 1, Name: "default"}}, nil)

	rec := f.do(http.MethodPost, "/admin/idps", url.Values{
		"idp_type": {"oidc"}, "name": {"Corp"}, "alias": {"corp"}, "partition_id": {"1"}, "client_secret": {idpSecret},
	}, htmx())

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "already has a provider with that alias")
	assert.Contains(t, body, `value="Corp"`)
	assert.NotContains(t, body, idpSecret)
}
