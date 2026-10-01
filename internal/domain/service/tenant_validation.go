package service

import (
	"net"
	"regexp"
	"slices"
	"strings"

	"sprezz-identity/internal/domain/port"
)

const (
	maxTenantNameLength   = 100
	maxDomainLength       = 253
	maxScopesPerTenant    = 100
	maxAudiencesPerTenant = 100
)

// domainLabel is one DNS label: letters, digits and inner hyphens.
var domainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// scopeToken follows RFC 6749: printable ASCII without space, quote or backslash.
var scopeToken = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+$`)

// mandatoryScope is required by OpenID Connect, so a tenant can never stop offering it.
const mandatoryScope = "openid"

// normalizeDomain lower-cases and trims a host name, optionally followed by a port.
func normalizeDomain(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// validateDomain checks a canonical host name with an optional port. Schemes, paths and credentials are refused,
// because the value is used as the host of every URL the tenant issues.
func validateDomain(domain string, verr *port.ValidationError) {
	switch {
	case domain == "":
		verr.Add("domain", "a domain is required")
		return
	case len(domain) > maxDomainLength:
		verr.Add("domain", "the domain must be at most 253 characters")
		return
	case strings.ContainsAny(domain, "/@ ?#\\"):
		verr.Add("domain", "enter only a host name, without scheme, path or credentials")
		return
	}

	host, portPart, hasPort := strings.Cut(domain, ":")
	if hasPort && !validPort(portPart) {
		verr.Add("domain", "the port must be a number between 1 and 65535")
		return
	}
	if host == "localhost" || net.ParseIP(host) != nil {
		return
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		verr.Add("domain", "enter a fully qualified domain name, for example id.example.com")
		return
	}
	for _, label := range labels {
		if !domainLabel.MatchString(label) {
			verr.Add("domain", "the domain contains characters that are not allowed")
			return
		}
	}
}

func validPort(p string) bool {
	if p == "" || len(p) > 5 {
		return false
	}
	n := 0
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= 1 && n <= 65535
}

func validateTenantName(name string, verr *port.ValidationError) {
	switch {
	case name == "":
		verr.Add("name", "a name is required")
	case len(name) > maxTenantNameLength:
		verr.Add("name", "the name must be at most 100 characters")
	}
}

// validateTenantScopes keeps the scope list well formed. The openid scope is mandatory.
func validateTenantScopes(scopes []string, verr *port.ValidationError) {
	if len(scopes) > maxScopesPerTenant {
		verr.Add("predefined_scopes", "at most 100 scopes are allowed")
		return
	}
	for _, scope := range scopes {
		if !scopeToken.MatchString(scope) {
			verr.Add("predefined_scopes", scope+" is not a valid scope name")
			return
		}
	}
	if !slices.Contains(scopes, mandatoryScope) {
		verr.Add("predefined_scopes", "the openid scope is required")
	}
}

// validateTenantAudiences requires every audience to be an absolute URI without a fragment.
func validateTenantAudiences(audiences []string, verr *port.ValidationError) {
	if len(audiences) > maxAudiencesPerTenant {
		verr.Add("predefined_audiences", "at most 100 audiences are allowed")
		return
	}
	for _, aud := range audiences {
		if msg := checkAudience(aud); msg != "" {
			verr.Add("predefined_audiences", aud+": "+msg)
			return
		}
	}
}

func checkAudience(aud string) string {
	if strings.Contains(aud, "#") {
		return "must not contain a fragment"
	}
	if strings.ContainsAny(aud, "*") {
		return "wildcards are not allowed"
	}
	if msg := checkURI(aud, true); msg != "" {
		return msg
	}
	return ""
}
