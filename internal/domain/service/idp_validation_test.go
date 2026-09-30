package service

import (
	"testing"

	"sprezz-identity/internal/domain/model"

	"github.com/stretchr/testify/assert"
)

func validOIDC() model.IdentityProvider {
	return model.IdentityProvider{
		Name: "Corp SSO", Alias: "corp", IDPType: model.OpenIDConnectIDPType, PartitionID: 1,
		Issuer: "https://idp.example.com",
		Config: model.IdentityProviderConfig{
			DiscoveryEndpoint: "https://idp.example.com/.well-known/openid-configuration",
			ClientID:          "sprezz", ClientSecret: "s3cret", AuthenticationMethod: "client_secret_basic",
			Scopes: []string{"openid", "email"}, AAL: 1, IAL: 1,
		},
	}
}

func validLocal() model.IdentityProvider {
	return model.IdentityProvider{
		Name: "Local", Alias: "username-password", IDPType: model.UsernamePasswordIDPType, PartitionID: 1,
		Config: model.IdentityProviderConfig{UsernameField: "email", MaxFailedVerificationCount: 5, PasswordBlockedTime: 900, AAL: 1, IAL: 1},
	}
}

func TestValidateIdentityProvider_ValidProvidersPass(t *testing.T) {
	assert.False(t, validateIdentityProvider(validOIDC()).HasErrors())
	assert.False(t, validateIdentityProvider(validLocal()).HasErrors())
}

func TestValidateIdentityProvider_OIDCRules(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.IdentityProvider)
		field  string
	}{
		{"missing name", func(p *model.IdentityProvider) { p.Name = "  " }, "name"},
		{"discovery over plain http", func(p *model.IdentityProvider) { p.Config.DiscoveryEndpoint = "http://idp.example.com/x" }, "discovery_endpoint"},
		{"discovery with credentials", func(p *model.IdentityProvider) { p.Config.DiscoveryEndpoint = "https://u:p@idp.example.com/x" }, "discovery_endpoint"},
		{"discovery not absolute", func(p *model.IdentityProvider) { p.Config.DiscoveryEndpoint = "idp.example.com" }, "discovery_endpoint"},
		{"issuer missing", func(p *model.IdentityProvider) { p.Issuer = "" }, "issuer"},
		{"issuer with fragment", func(p *model.IdentityProvider) { p.Issuer = "https://idp.example.com#x" }, "issuer"},
		{"client id missing", func(p *model.IdentityProvider) { p.Config.ClientID = "" }, "client_id"},
		{"secret missing for confidential client", func(p *model.IdentityProvider) { p.Config.ClientSecret = "" }, "client_secret"},
		{"unknown auth method", func(p *model.IdentityProvider) { p.Config.AuthenticationMethod = "magic" }, "authentication_method"},
		{"openid scope missing", func(p *model.IdentityProvider) { p.Config.Scopes = []string{"email"} }, "scopes"},
		{"bad domain alias", func(p *model.IdentityProvider) { p.Config.DomainAliases = []string{"user@example.com"} }, "domain_aliases"},
		{"aal out of range", func(p *model.IdentityProvider) { p.Config.AAL = 9 }, "aal"},
		{"ial out of range", func(p *model.IdentityProvider) { p.Config.IAL = 5 }, "ial"},
		{"acr tuple out of range", func(p *model.IdentityProvider) { p.Config.AcrToTuple = map[string]model.AcrTuple{"gold": {AAL: 7}} }, "acr_to_tuple"},
		{"empty acr", func(p *model.IdentityProvider) { p.Config.AcrToTuple = map[string]model.AcrTuple{" ": {AAL: 1}} }, "acr_to_tuple"},
		{"amr level out of range", func(p *model.IdentityProvider) { p.Config.AmrToAAL = map[string]int{"otp": 0} }, "amr_to_aal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validOIDC()
			tt.mutate(&p)
			assert.Contains(t, validateIdentityProvider(p).Fields, tt.field)
		})
	}
}

func TestValidateIdentityProvider_PublicClientNeedsNoSecret(t *testing.T) {
	p := validOIDC()
	p.Config.AuthenticationMethod, p.Config.ClientSecret = "none", ""
	assert.False(t, validateIdentityProvider(p).HasErrors())
}

func TestValidateIdentityProvider_DynamicRegistrationNeedsNoCredentials(t *testing.T) {
	p := validOIDC()
	p.Config.ClientID, p.Config.ClientSecret = "", ""
	p.Config.DCRMode = model.DCRModeSoftwareStatement
	assert.False(t, validateIdentityProvider(p).HasErrors(), "credentials are obtained on demand")
}

func TestValidateIdentityProvider_LocalRules(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.IdentityProvider)
		field  string
	}{
		{"unknown login field", func(p *model.IdentityProvider) { p.Config.UsernameField = "phone" }, "username_field"},
		{"too few attempts", func(p *model.IdentityProvider) { p.Config.MaxFailedVerificationCount = 1 }, "max_failed_verification_count"},
		{"too many attempts", func(p *model.IdentityProvider) { p.Config.MaxFailedVerificationCount = 500 }, "max_failed_verification_count"},
		{"lockout too short", func(p *model.IdentityProvider) { p.Config.PasswordBlockedTime = 5 }, "password_blocked_time"},
		{"lockout too long", func(p *model.IdentityProvider) { p.Config.PasswordBlockedTime = 999999 }, "password_blocked_time"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validLocal()
			tt.mutate(&p)
			assert.Contains(t, validateIdentityProvider(p).Fields, tt.field)
		})
	}
}

func TestValidateNewIdentityProvider_AliasAndPartition(t *testing.T) {
	for _, alias := range []string{"", "Has Space", "UPPER", "-lead", "a/b", "x@y"} {
		p := validOIDC()
		p.Alias = alias
		assert.Contains(t, validateNewIdentityProvider(p).Fields, "alias", "alias %q", alias)
	}
	for _, alias := range []string{"corp", "corp-2", "sso_1", "a"} {
		p := validOIDC()
		p.Alias = alias
		assert.NotContains(t, validateNewIdentityProvider(p).Fields, "alias", "alias %q", alias)
	}

	p := validOIDC()
	p.PartitionID = 0
	assert.Contains(t, validateNewIdentityProvider(p).Fields, "partition_id")
}

func TestCheckHTTPSURL_LoopbackMayUsePlainHTTP(t *testing.T) {
	assert.Empty(t, checkHTTPSURL("http://localhost:8100/.well-known/openid-configuration"))
	assert.Empty(t, checkHTTPSURL("http://127.0.0.1:9000/x"))
	assert.NotEmpty(t, checkHTTPSURL("http://localhost.evil.example/x"))
	assert.NotEmpty(t, checkHTTPSURL("ftp://idp.example.com"))
}
