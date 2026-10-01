package service_test

import (
	"context"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The old settings handler rebuilt the lists from the form and reused the rest, so what a card did not show had to
// survive by luck. Every section must leave everything outside it exactly as it was.
func TestPatchTenant_EverySectionKeepsWhatItDoesNotShow(t *testing.T) {
	sections := []port.PatchTenantCommand{
		{Section: port.TenantSectionGeneral, Name: "Acme Corp", Domain: "acme.example.com"},
		{Section: port.TenantSectionRedirects, RedirectWhitelist: []string{"https://acme.example.com/cb", "https://acme.example.com/cb2"}, DefaultRedirectURI: "https://acme.example.com/cb2"},
		{Section: port.TenantSectionScopes, PredefinedScopes: []string{"openid", "email"}, PredefinedAudiences: []string{}},
	}
	for _, cmd := range sections {
		t.Run(string(cmd.Section), func(t *testing.T) {
			f := newTenantFixture(t)
			f.storage.ResolveTenantByDomainMock.Optional().Return(&f.acme, nil)
			saved := f.captureSave()

			cmd.TenantID, cmd.ActingTenant = f.acme.ID, f.acme.ID
			require.NoError(t, f.svc.PatchTenant(context.Background(), cmd))

			assert.Equal(t, 2, saved.Config.DefaultAAL, "assurance level")
			assert.True(t, saved.Config.ACREssential)
			assert.Equal(t, "sealed", saved.Config.EncryptedAdminSecret, "secrets are never dropped")
			assert.Equal(t, map[string]model.Levels{"gold": {AAL: 3}}, saved.Config.ACRToLevels)
			assert.True(t, saved.Config.AllowSignup, "registration mode")
			assert.Equal(t, f.acme.ID, saved.ID)
			assert.False(t, saved.IsSystem)
		})
	}
}

func TestPatchTenant_SectionFieldsLandWhereExpected(t *testing.T) {
	f := newTenantFixture(t)
	f.storage.ResolveTenantByDomainMock.Optional().Return(nil, port.ErrTenantNotFound)
	saved := f.captureSave()

	require.NoError(t, f.svc.PatchTenant(context.Background(), port.PatchTenantCommand{
		TenantID: f.acme.ID, ActingTenant: f.acme.ID, Section: port.TenantSectionGeneral, Name: "  Acme Corp ", Domain: " ACME2.Example.com ",
	}))
	assert.Equal(t, "Acme Corp", saved.Name)
	assert.Equal(t, "acme2.example.com", saved.Domain)
	assert.Equal(t, []string{"openid", "profile"}, saved.Config.PredefinedScopes, "other sections are untouched")

	require.NoError(t, f.svc.PatchTenant(context.Background(), port.PatchTenantCommand{
		TenantID: f.acme.ID, ActingTenant: f.acme.ID, Section: port.TenantSectionScopes,
		PredefinedScopes: []string{" openid ", "email", "email"}, PredefinedAudiences: []string{"https://api.example.com"},
	}))
	assert.Equal(t, []string{"openid", "email"}, saved.Config.PredefinedScopes, "trimmed and de-duplicated")
	assert.Equal(t, "Acme", saved.Name, "the name section is untouched")
}

func TestPatchTenant_Validation(t *testing.T) {
	cases := map[string]struct {
		cmd   port.PatchTenantCommand
		field string
	}{
		"empty name":            {port.PatchTenantCommand{Section: port.TenantSectionGeneral, Domain: "acme.example.com"}, "name"},
		"domain with a scheme":  {port.PatchTenantCommand{Section: port.TenantSectionGeneral, Name: "A", Domain: "https://acme.example.com"}, "domain"},
		"scopes without openid": {port.PatchTenantCommand{Section: port.TenantSectionScopes, PredefinedScopes: []string{"email"}}, "predefined_scopes"},
		"relative audience":     {port.PatchTenantCommand{Section: port.TenantSectionScopes, PredefinedScopes: []string{"openid"}, PredefinedAudiences: []string{"api"}}, "predefined_audiences"},
		"wildcard redirect":     {port.PatchTenantCommand{Section: port.TenantSectionRedirects, RedirectWhitelist: []string{"https://*.example.com/cb"}}, "redirect_whitelist"},
		"plain http redirect":   {port.PatchTenantCommand{Section: port.TenantSectionRedirects, RedirectWhitelist: []string{"http://example.com/cb"}}, "redirect_whitelist"},
		"default outside list": {port.PatchTenantCommand{Section: port.TenantSectionRedirects, RedirectWhitelist: []string{"https://acme.example.com/cb"},
			DefaultRedirectURI: "https://other.example.com/cb"}, "default_redirect_uri"},
		"unknown section": {port.PatchTenantCommand{Section: "bogus"}, "section"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newTenantFixture(t)
			f.forbidSave(t)
			tc.cmd.TenantID, tc.cmd.ActingTenant = f.acme.ID, f.acme.ID

			var verr *port.ValidationError
			require.ErrorAs(t, f.svc.PatchTenant(context.Background(), tc.cmd), &verr)
			assert.Contains(t, verr.Fields, tc.field)
		})
	}
}
