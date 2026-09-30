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

func TestIDPSection_SavesOnlyThePostedSectionAndAnswersWithThatCard(t *testing.T) {
	f := newPagesFixture(t)
	p := testIDP()
	f.stubIDPPage(p, model.IdentityProviderUsage{})
	var got port.PatchIdentityProviderCommand
	f.idps.PatchIdentityProviderMock.Set(func(ctx context.Context, cmd port.PatchIdentityProviderCommand) error {
		got = cmd
		return nil
	})

	rec := f.do(http.MethodPut, "/admin/idps/"+p.ID.String()+"/behavior", url.Values{
		"scopes": {"openid  profile email"}, "domain_aliases": {"a.example.com\n\n b.example.com \n"},
		"user_identifier_claim": {"email"}, "auto_provision_user": {"true"},
	}, htmx())

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, port.IDPSectionBehavior, got.Section)
	assert.Equal(t, p.ID, got.ID)
	assert.Equal(t, []string{"openid", "profile", "email"}, got.Scopes)
	assert.Equal(t, []string{"a.example.com", "b.example.com"}, got.DomainAliases)
	assert.True(t, got.AutoProvisionUser)
	assert.False(t, got.AutoVerifyEmail, "an unchecked box means false")
	body := rec.Body.String()
	assert.Contains(t, body, `id="section-behavior"`)
	assert.NotContains(t, body, `id="section-general"`, "only the saved card is returned")
	assert.NotContains(t, body, idpSecret)
}

func TestIDPSection_CredentialsPostsTheSecretButNeverReturnsIt(t *testing.T) {
	f := newPagesFixture(t)
	p := testIDP()
	f.stubIDPPage(p, model.IdentityProviderUsage{})
	var got port.PatchIdentityProviderCommand
	f.idps.PatchIdentityProviderMock.Set(func(ctx context.Context, cmd port.PatchIdentityProviderCommand) error {
		got = cmd
		return nil
	})

	rec := f.do(http.MethodPut, "/admin/idps/"+p.ID.String()+"/credentials", url.Values{"client_id": {"sprezz"}, "client_secret": {""}}, htmx())

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, got.ClientSecret, "an empty field means keep the stored secret")
	assert.NotContains(t, rec.Body.String(), idpSecret)
}

func TestIDPSection_AssuranceParsesTheMappings(t *testing.T) {
	f := newPagesFixture(t)
	p := testIDP()
	f.stubIDPPage(p, model.IdentityProviderUsage{})
	var got port.PatchIdentityProviderCommand
	f.idps.PatchIdentityProviderMock.Set(func(ctx context.Context, cmd port.PatchIdentityProviderCommand) error {
		got = cmd
		return nil
	})

	rec := f.do(http.MethodPut, "/admin/idps/"+p.ID.String()+"/assurance", url.Values{
		"aal": {"2"}, "ial": {"1"}, "acr_value": {"gold", "silver"},
		"acr_aal:gold": {"3"}, "acr_ial:gold": {"2"}, "acr_aal:silver": {"0"}, "acr_ial:silver": {"0"},
		"amr_to_aal": {"otp=2\nhwk = 3"},
	}, htmx())

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 2, got.AAL)
	assert.Equal(t, map[string]model.AcrTuple{"gold": {AAL: 3, IAL: 2}}, got.AcrToTuple, "unmapped values are omitted")
	assert.Equal(t, map[string]int{"otp": 2, "hwk": 3}, got.AmrToAAL)
}

func TestIDPSection_MalformedInputIsReportedWithoutCallingTheService(t *testing.T) {
	f := newPagesFixture(t)
	p := testIDP()
	f.stubIDPPage(p, model.IdentityProviderUsage{})
	f.idps.PatchIdentityProviderMock.Optional().Set(func(ctx context.Context, cmd port.PatchIdentityProviderCommand) error {
		t.Error("the service must not be called with a malformed form")
		return nil
	})

	rec := f.do(http.MethodPut, "/admin/idps/"+p.ID.String()+"/assurance", url.Values{"aal": {"high"}, "ial": {"1"}, "amr_to_aal": {"otp"}}, htmx())

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), "enter a whole number")
	assert.Contains(t, rec.Body.String(), "name=level")
}

func TestIDPSection_ServiceErrorsAreSanitized(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		text   string
	}{
		"validation": {func() error { v := port.NewValidationError(); v.Add("client_id", "a client ID is required"); return v }(), http.StatusUnprocessableEntity, "a client ID is required"},
		"system":     {port.ErrSystemManaged, http.StatusForbidden, port.ErrSystemManaged.Error()},
		"unexpected": {errors.New("pq: password authentication failed for user sprezz_db"), http.StatusInternalServerError, "an unexpected error occurred"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newPagesFixture(t)
			p := testIDP()
			f.stubIDPPage(p, model.IdentityProviderUsage{})
			f.idps.PatchIdentityProviderMock.Return(tc.err)

			rec := f.do(http.MethodPut, "/admin/idps/"+p.ID.String()+"/credentials", url.Values{"client_id": {""}}, htmx())

			assert.Equal(t, tc.status, rec.Code)
			assert.Contains(t, rec.Body.String(), tc.text)
			assert.NotContains(t, rec.Body.String(), "sprezz_db", "internal error text never reaches the browser")
		})
	}
}

func TestIDPSection_UnknownSection(t *testing.T) {
	f := newPagesFixture(t)
	p := testIDP()
	f.stubIDPPage(p, model.IdentityProviderUsage{})

	assert.Equal(t, http.StatusNotFound, f.do(http.MethodPut, "/admin/idps/"+p.ID.String()+"/bogus", url.Values{}, htmx()).Code)
}
