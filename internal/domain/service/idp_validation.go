package service

import (
	"net/url"
	"regexp"
	"slices"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

const (
	minLockoutAttempts = 3
	maxLockoutAttempts = 20
	minLockoutSeconds  = 60
	maxLockoutSeconds  = 24 * 60 * 60
)

// aliasPattern keeps aliases usable as an idp_hint query value and as a cookie-safe label.
var aliasPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

var validAuthMethods = []string{"client_secret_basic", "client_secret_post", "none"}

// validateIdentityProvider checks a complete provider and returns every problem keyed by form field name.
func validateIdentityProvider(p model.IdentityProvider) *port.ValidationError {
	verr := port.NewValidationError()

	if strings.TrimSpace(p.Name) == "" {
		verr.Add("name", "a display name is required")
	} else if len(strings.TrimSpace(p.Name)) > 100 {
		verr.Add("name", "the display name must be at most 100 characters")
	}

	switch p.IDPType {
	case model.UsernamePasswordIDPType:
		validateLocalConfig(p.Config, verr)
	case model.OpenIDConnectIDPType:
		validateOIDCConfig(p, verr)
	default:
		verr.Add("idp_type", "choose a supported provider type")
	}

	validateAssurance(p.Config, verr)
	return verr
}

// validateNewIdentityProvider adds the rules that only apply when a provider is created.
func validateNewIdentityProvider(p model.IdentityProvider) *port.ValidationError {
	verr := validateIdentityProvider(p)
	if !aliasPattern.MatchString(p.Alias) {
		verr.Add("alias", "use lowercase letters, digits, - and _ (at most 63 characters)")
	}
	if p.PartitionID == 0 {
		verr.Add("partition_id", "choose a partition")
	}
	return verr
}

func validateLocalConfig(c model.IdentityProviderConfig, verr *port.ValidationError) {
	if c.UsernameField != "preferredUsername" && c.UsernameField != "email" {
		verr.Add("username_field", "sign-in must use the username or the email address")
	}
	if c.MaxFailedVerificationCount < minLockoutAttempts || c.MaxFailedVerificationCount > maxLockoutAttempts {
		verr.Add("max_failed_verification_count", "allow between 3 and 20 failed attempts")
	}
	if c.PasswordBlockedTime < minLockoutSeconds || c.PasswordBlockedTime > maxLockoutSeconds {
		verr.Add("password_blocked_time", "lock out for between 1 minute and 24 hours")
	}
}

func validateOIDCConfig(p model.IdentityProvider, verr *port.ValidationError) {
	c := p.Config

	if msg := checkHTTPSURL(c.DiscoveryEndpoint); msg != "" {
		verr.Add("discovery_endpoint", msg)
	}
	if strings.TrimSpace(p.Issuer) == "" {
		verr.Add("issuer", "fetch the provider metadata so the issuer can be confirmed")
	} else if msg := checkHTTPSURL(p.Issuer); msg != "" {
		verr.Add("issuer", msg)
	}
	// A provider that registers itself through Dynamic Client Registration gets its credentials on demand, so they
	// are only required when registration is off.
	if !usesDynamicRegistration(c) {
		if strings.TrimSpace(c.ClientID) == "" {
			verr.Add("client_id", "a client ID is required")
		}
		if c.AuthenticationMethod != "none" && strings.TrimSpace(c.ClientSecret) == "" {
			verr.Add("client_secret", "a client secret is required unless the provider uses a public client")
		}
	}
	if c.AuthenticationMethod != "" && !slices.Contains(validAuthMethods, c.AuthenticationMethod) {
		verr.Add("authentication_method", "choose a supported client authentication method")
	}
	if len(c.Scopes) > 0 && !slices.Contains(c.Scopes, "openid") {
		verr.Add("scopes", "the openid scope is required")
	}
	for _, alias := range c.DomainAliases {
		if strings.ContainsAny(alias, " /@") || !strings.Contains(alias, ".") {
			verr.Add("domain_aliases", alias+" is not a valid domain")
			break
		}
	}
}

func validateAssurance(c model.IdentityProviderConfig, verr *port.ValidationError) {
	if c.AAL != 0 && (c.AAL < 1 || c.AAL > 4) {
		verr.Add("aal", "the authenticator assurance level must be between 1 and 4")
	}
	if c.IAL != 0 && (c.IAL < 1 || c.IAL > 4) {
		verr.Add("ial", "the identity assurance level must be between 1 and 4")
	}
	for acr, tuple := range c.AcrToTuple {
		if strings.TrimSpace(acr) == "" {
			verr.Add("acr_to_tuple", "an ACR value cannot be empty")
			break
		}
		if tuple.AAL < 0 || tuple.AAL > 4 || tuple.IAL < 0 || tuple.IAL > 4 {
			verr.Add("acr_to_tuple", "levels for "+acr+" must be between 0 and 4")
			break
		}
	}
	for factor, level := range c.AmrToAAL {
		if strings.TrimSpace(factor) == "" || level < 1 || level > 4 {
			verr.Add("amr_to_aal", "each authentication method needs a name and a level between 1 and 4")
			break
		}
	}
}

// checkHTTPSURL requires an absolute https URL without fragment or credentials. Plain http is allowed only for
// loopback hosts so local development providers keep working.
func checkHTTPSURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "a URL is required"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "enter an absolute URL"
	}
	if u.User != nil {
		return "the URL must not contain credentials"
	}
	if u.Fragment != "" {
		return "the URL must not contain a fragment"
	}
	switch u.Scheme {
	case "https":
		return ""
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return ""
		}
		return "plain http is only allowed for localhost"
	default:
		return "the URL must use https"
	}
}

// usesDynamicRegistration reports whether the provider obtains its client credentials through RFC 7591 registration.
func usesDynamicRegistration(c model.IdentityProviderConfig) bool {
	return c.DCRMode != "" && c.DCRMode != model.DCRModeOff
}
