package service

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"sprezz-identity/internal/domain/port"
)

// groupContent is the validated, normalized routing content shared by group create and update.
type groupContent struct {
	redirectURIs           []string
	defaultRedirectURI     string
	postLogoutRedirectURIs []string
	frontChannelLogoutURI  string
	backChannelLogoutURI   string
	allowedScopes          []string
	defaultScopes          []string
	allowedAudiences       []string
}

// groupContentInput carries the raw values of a group command.
type groupContentInput struct {
	redirectURIs           []string
	defaultRedirectURI     string
	postLogoutRedirectURIs []string
	frontChannelLogoutURI  string
	backChannelLogoutURI   string
	allowedScopes          []string
	defaultScopes          []string
	allowedAudiences       []string
}

// normalizeGroupContent validates and normalizes the routing content of a group. Every violation is collected
// into the returned ValidationError so the admin form can show all problems at once. Slices are never nil.
func normalizeGroupContent(in groupContentInput) (groupContent, *port.ValidationError) {
	verr := port.NewValidationError()

	out := groupContent{
		redirectURIs:           validateURIList(in.redirectURIs, "redirect_uris", true, verr),
		postLogoutRedirectURIs: validateURIList(in.postLogoutRedirectURIs, "post_logout_redirect_uris", false, verr),
		frontChannelLogoutURI:  validateOptionalURI(in.frontChannelLogoutURI, "front_channel_logout_uri", verr),
		backChannelLogoutURI:   validateOptionalURI(in.backChannelLogoutURI, "back_channel_logout_uri", verr),
		allowedScopes:          cleanUnique(in.allowedScopes),
		defaultScopes:          cleanUnique(in.defaultScopes),
		allowedAudiences:       cleanUnique(in.allowedAudiences),
	}

	out.defaultRedirectURI = resolveDefaultRedirect(in.defaultRedirectURI, out.redirectURIs, verr)
	out.defaultScopes = resolveDefaultScopes(out.allowedScopes, out.defaultScopes, verr)

	return out, verr
}

// resolveDefaultRedirect falls back to the first whitelisted URI and insists that an explicit default is whitelisted.
func resolveDefaultRedirect(requested string, whitelist []string, verr *port.ValidationError) string {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		if len(whitelist) > 0 {
			return whitelist[0]
		}
		return ""
	}
	if !slices.Contains(whitelist, requested) {
		verr.Add("default_redirect_uri", "the default redirect URI must be one of the allowed redirect URIs")
	}
	return requested
}

// resolveDefaultScopes keeps the default scopes a subset of the allowed scopes, which the database also enforces.
func resolveDefaultScopes(allowed, defaults []string, verr *port.ValidationError) []string {
	if len(defaults) == 0 {
		return []string{}
	}
	for _, scope := range defaults {
		if !slices.Contains(allowed, scope) {
			verr.Add("default_scopes", fmt.Sprintf("default scope %q must also be an allowed scope", scope))
			break
		}
	}
	return defaults
}

// validateURIList validates every entry, drops duplicates and blanks, and reports the first problem per field.
func validateURIList(values []string, field string, allowPrivateScheme bool, verr *port.ValidationError) []string {
	cleaned := cleanUnique(values)
	for _, raw := range cleaned {
		if msg := checkURI(raw, allowPrivateScheme); msg != "" {
			verr.Add(field, fmt.Sprintf("%s: %s", raw, msg))
			break
		}
	}
	return cleaned
}

func validateOptionalURI(raw, field string, verr *port.ValidationError) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if msg := checkURI(raw, false); msg != "" {
		verr.Add(field, msg)
	}
	return raw
}

// checkURI returns a description of what is wrong with the URI, or an empty string when it is acceptable.
// Redirect URIs must be exact values: wildcards, fragments and path traversal are never allowed.
func checkURI(raw string, allowPrivateScheme bool) string {
	if strings.ContainsAny(raw, "*") {
		return "wildcards are not allowed"
	}
	if strings.Contains(raw, "..") {
		return "path traversal is not allowed"
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		return "must be an absolute URI"
	}
	if parsed.Fragment != "" || strings.Contains(raw, "#") {
		return "must not contain a fragment"
	}

	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return requireHost(parsed)
	case "http":
		if msg := requireHost(parsed); msg != "" {
			return msg
		}
		if !isLoopbackHost(parsed.Hostname()) {
			return "plain http is only allowed for localhost"
		}
		return ""
	default:
		// RFC 8252 private-use schemes for native apps use a reverse-domain name, so they always contain a dot.
		if allowPrivateScheme && strings.Contains(parsed.Scheme, ".") {
			return ""
		}
		return "scheme must be https"
	}
}

func requireHost(parsed *url.URL) string {
	if parsed.Hostname() == "" {
		return "must include a host"
	}
	return ""
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// cleanUnique trims entries, drops blanks and duplicates, and keeps the original order. The result is never nil.
func cleanUnique(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
