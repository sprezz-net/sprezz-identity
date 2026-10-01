package service

import (
	"strings"
	"testing"

	"sprezz-identity/internal/domain/port"

	"github.com/stretchr/testify/assert"
)

func domainErr(domain string) string {
	verr := port.NewValidationError()
	validateDomain(domain, verr)
	return verr.Fields["domain"]
}

func TestValidateDomain_Accepts(t *testing.T) {
	for _, d := range []string{"id.example.com", "a-b.example.co.uk", "localhost", "localhost:8100", "127.0.0.1:9000", "id.example.com:8443", "xn--bcher-kva.example"} {
		assert.Empty(t, domainErr(d), d)
	}
}

func TestValidateDomain_Refuses(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"scheme":           "https://id.example.com",
		"path":             "id.example.com/login",
		"credentials":      "user@id.example.com",
		"space":            "id example.com",
		"query":            "id.example.com?x=1",
		"single label":     "intranet",
		"leading hyphen":   "-id.example.com",
		"trailing hyphen":  "id-.example.com",
		"underscore":       "i_d.example.com",
		"empty label":      "id..example.com",
		"port zero":        "id.example.com:0",
		"port too large":   "id.example.com:70000",
		"port not numeric": "id.example.com:http",
		"too long":         strings.Repeat("a", 250) + ".com",
		"label too long":   strings.Repeat("a", 64) + ".example.com",
	}
	for name, domain := range cases {
		t.Run(name, func(t *testing.T) {
			assert.NotEmpty(t, domainErr(domain), domain)
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	assert.Equal(t, "id.example.com", normalizeDomain("  ID.Example.COM "))
}

func TestValidateTenantScopes(t *testing.T) {
	check := func(scopes ...string) *port.ValidationError {
		verr := port.NewValidationError()
		validateTenantScopes(scopes, verr)
		return verr
	}
	assert.False(t, check("openid", "profile", "read:orders").HasErrors())
	assert.Contains(t, check("profile").Fields, "predefined_scopes", "openid is mandatory")
	assert.Contains(t, check("openid", "has space").Fields, "predefined_scopes")
	assert.Contains(t, check("openid", `quo"te`).Fields, "predefined_scopes")
	assert.Contains(t, check(append([]string{"openid"}, make([]string, 100)...)...).Fields, "predefined_scopes", "too many")
}

func TestValidateTenantAudiences(t *testing.T) {
	check := func(auds ...string) *port.ValidationError {
		verr := port.NewValidationError()
		validateTenantAudiences(auds, verr)
		return verr
	}
	assert.False(t, check().HasErrors(), "an empty list is fine")
	assert.False(t, check("https://api.example.com", "https://billing.example.com/v2").HasErrors())
	assert.Contains(t, check("api.example.com").Fields, "predefined_audiences", "must be absolute")
	assert.Contains(t, check("https://api.example.com/#frag").Fields, "predefined_audiences")
	assert.Contains(t, check("https://*.example.com").Fields, "predefined_audiences")
}

func TestValidateTenantName(t *testing.T) {
	verr := port.NewValidationError()
	validateTenantName("", verr)
	assert.Contains(t, verr.Fields, "name")

	verr = port.NewValidationError()
	validateTenantName(strings.Repeat("x", 101), verr)
	assert.Contains(t, verr.Fields, "name")

	verr = port.NewValidationError()
	validateTenantName("Acme", verr)
	assert.False(t, verr.HasErrors())
}
