package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckURI(t *testing.T) {
	tests := []struct {
		name          string
		uri           string
		allowPrivate  bool
		wantViolation bool
	}{
		{name: "https", uri: "https://app.example.com/callback"},
		{name: "https with port and query", uri: "https://app.example.com:8443/cb?x=1"},
		{name: "http localhost", uri: "http://localhost:3000/cb"},
		{name: "http loopback ip", uri: "http://127.0.0.1:8080/cb"},
		{name: "http ipv6 loopback", uri: "http://[::1]:8080/cb"},
		{name: "http remote host", uri: "http://app.example.com/cb", wantViolation: true},
		{name: "http lookalike of localhost", uri: "http://localhost.evil.example/cb", wantViolation: true},
		{name: "relative", uri: "/callback", wantViolation: true},
		{name: "no scheme", uri: "app.example.com/callback", wantViolation: true},
		{name: "fragment", uri: "https://app.example.com/cb#frag", wantViolation: true},
		{name: "empty fragment marker", uri: "https://app.example.com/cb#", wantViolation: true},
		{name: "wildcard", uri: "https://*.example.com/cb", wantViolation: true},
		{name: "path traversal", uri: "https://app.example.com/a/../cb", wantViolation: true},
		{name: "https without host", uri: "https:///cb", wantViolation: true},
		{name: "javascript scheme", uri: "javascript:alert(1)", wantViolation: true},
		{name: "data scheme", uri: "data:text/html,x", wantViolation: true},
		{name: "private scheme for native app", uri: "com.example.app:/oauth2redirect", allowPrivate: true},
		{name: "private scheme not allowed here", uri: "com.example.app:/oauth2redirect", wantViolation: true},
		{name: "private scheme without reverse domain", uri: "myapp:/cb", allowPrivate: true, wantViolation: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := checkURI(tt.uri, tt.allowPrivate)
			if tt.wantViolation {
				assert.NotEmpty(t, msg)
			} else {
				assert.Empty(t, msg)
			}
		})
	}
}

func TestNormalizeGroupContent_CleansAndDeduplicates(t *testing.T) {
	out, verr := normalizeGroupContent(groupContentInput{
		redirectURIs:     []string{" https://a.example.com/cb ", "https://a.example.com/cb", "", "https://b.example.com/cb"},
		allowedScopes:    []string{"openid", "openid", "email"},
		allowedAudiences: nil,
	})

	require.False(t, verr.HasErrors(), verr.Error())
	assert.Equal(t, []string{"https://a.example.com/cb", "https://b.example.com/cb"}, out.redirectURIs)
	assert.Equal(t, []string{"openid", "email"}, out.allowedScopes)
	assert.NotNil(t, out.allowedAudiences, "slices must never be nil")
	assert.NotNil(t, out.defaultScopes)
	assert.NotNil(t, out.postLogoutRedirectURIs)
}

func TestNormalizeGroupContent_DefaultRedirect(t *testing.T) {
	whitelist := []string{"https://a.example.com/cb", "https://b.example.com/cb"}

	t.Run("falls back to the first entry", func(t *testing.T) {
		out, verr := normalizeGroupContent(groupContentInput{redirectURIs: whitelist})
		require.False(t, verr.HasErrors())
		assert.Equal(t, "https://a.example.com/cb", out.defaultRedirectURI)
	})

	t.Run("explicit default that is whitelisted", func(t *testing.T) {
		out, verr := normalizeGroupContent(groupContentInput{redirectURIs: whitelist, defaultRedirectURI: "https://b.example.com/cb"})
		require.False(t, verr.HasErrors())
		assert.Equal(t, "https://b.example.com/cb", out.defaultRedirectURI)
	})

	t.Run("default outside the whitelist is rejected", func(t *testing.T) {
		_, verr := normalizeGroupContent(groupContentInput{redirectURIs: whitelist, defaultRedirectURI: "https://evil.example/cb"})
		assert.Contains(t, verr.Fields, "default_redirect_uri")
	})

	t.Run("no redirect URIs yields no default", func(t *testing.T) {
		out, verr := normalizeGroupContent(groupContentInput{})
		require.False(t, verr.HasErrors())
		assert.Empty(t, out.defaultRedirectURI)
	})
}

func TestNormalizeGroupContent_Validation(t *testing.T) {
	tests := []struct {
		name  string
		in    groupContentInput
		field string
	}{
		{name: "insecure redirect", in: groupContentInput{redirectURIs: []string{"http://app.example.com/cb"}}, field: "redirect_uris"},
		{name: "wildcard redirect", in: groupContentInput{redirectURIs: []string{"https://*.example.com/cb"}}, field: "redirect_uris"},
		{name: "bad post logout", in: groupContentInput{postLogoutRedirectURIs: []string{"not a uri"}}, field: "post_logout_redirect_uris"},
		{name: "private scheme not valid for logout", in: groupContentInput{postLogoutRedirectURIs: []string{"com.example.app:/bye"}}, field: "post_logout_redirect_uris"},
		{name: "bad front channel", in: groupContentInput{frontChannelLogoutURI: "javascript:alert(1)"}, field: "front_channel_logout_uri"},
		{name: "bad back channel", in: groupContentInput{backChannelLogoutURI: "ftp://x.example.com"}, field: "back_channel_logout_uri"},
		{name: "default scope not allowed", in: groupContentInput{allowedScopes: []string{"openid"}, defaultScopes: []string{"email"}}, field: "default_scopes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, verr := normalizeGroupContent(tt.in)
			assert.Contains(t, verr.Fields, tt.field)
		})
	}
}

func TestNormalizeGroupContent_AcceptsNativeAppRedirect(t *testing.T) {
	_, verr := normalizeGroupContent(groupContentInput{redirectURIs: []string{"com.example.app:/oauth2redirect"}})
	assert.False(t, verr.HasErrors(), "RFC 8252 private-use schemes are valid redirect URIs")
}
