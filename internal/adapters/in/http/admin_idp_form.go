package http

import (
	"net/http"
	"strconv"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

// idpSections maps the URL segment of a section to its domain section.
var idpSections = map[string]port.IdentityProviderSection{
	"general":      port.IDPSectionGeneral,
	"connection":   port.IDPSectionConnection,
	"credentials":  port.IDPSectionCredentials,
	"behavior":     port.IDPSectionBehavior,
	"assurance":    port.IDPSectionAssurance,
	"local-policy": port.IDPSectionLocalPolicy,
}

// idpPatchFromForm reads only the fields of one section from a submitted form. Malformed numbers are reported
// against their field instead of being replaced by zero.
func idpPatchFromForm(r *http.Request, section port.IdentityProviderSection, errs map[string]string) port.PatchIdentityProviderCommand {
	cmd := port.PatchIdentityProviderCommand{Section: section}
	switch section {
	case port.IDPSectionGeneral:
		cmd.Name, cmd.Enabled = strings.TrimSpace(r.FormValue("name")), r.FormValue("enabled") == "true"
	case port.IDPSectionConnection:
		cmd.DiscoveryEndpoint = r.FormValue("discovery_endpoint")
		cmd.AuthenticationMethod = r.FormValue("authentication_method")
		cmd.PkceEnabled, cmd.ParEnabled, cmd.SLOEnabled = r.FormValue("pkce_enabled") == "true", r.FormValue("par_enabled") == "true", r.FormValue("slo_enabled") == "true"
	case port.IDPSectionCredentials:
		cmd.ClientID, cmd.ClientSecret = r.FormValue("client_id"), r.FormValue("client_secret")
	case port.IDPSectionBehavior:
		cmd.Scopes = strings.Fields(r.FormValue("scopes"))
		cmd.UserIdentifierClaim = r.FormValue("user_identifier_claim")
		cmd.DomainAliases = splitLines(r.FormValue("domain_aliases"))
		cmd.AutoProvisionUser, cmd.AutoVerifyEmail = r.FormValue("auto_provision_user") == "true", r.FormValue("auto_verify_email") == "true"
	case port.IDPSectionAssurance:
		readAssurance(r, &cmd, errs)
	case port.IDPSectionLocalPolicy:
		cmd.UsernameField = r.FormValue("username_field")
		cmd.MaxFailedVerificationCount = intField(r, "max_failed_verification_count", errs)
		cmd.PasswordBlockedTime = intField(r, "password_blocked_time", errs)
		cmd.AllowDecoupling = r.FormValue("allow_decoupling") == "true"
	}
	return cmd
}

func readAssurance(r *http.Request, cmd *port.PatchIdentityProviderCommand, errs map[string]string) {
	cmd.AAL, cmd.IAL = intField(r, "aal", errs), intField(r, "ial", errs)
	cmd.AcrToTuple = map[string]model.AcrTuple{}
	for _, acr := range r.Form["acr_value"] {
		aal, ial := intField(r, "acr_aal:"+acr, errs), intField(r, "acr_ial:"+acr, errs)
		if aal != 0 || ial != 0 {
			cmd.AcrToTuple[acr] = model.AcrTuple{AAL: aal, IAL: ial}
		}
	}
	cmd.AmrToAAL = parseAmrLines(r.FormValue("amr_to_aal"), errs)
}

// parseAmrLines reads name=level lines; a line that is not of that form is reported.
func parseAmrLines(raw string, errs map[string]string) map[string]int {
	out := map[string]int{}
	for _, line := range splitLines(raw) {
		name, level, ok := strings.Cut(line, "=")
		n, err := strconv.Atoi(strings.TrimSpace(level))
		if !ok || err != nil || strings.TrimSpace(name) == "" {
			errs["amr_to_aal"] = "write each method as name=level, for example otp=2"
			return out
		}
		out[strings.TrimSpace(name)] = n
	}
	return out
}

// intField parses a whole-number field. An empty value is zero, so the domain validation decides whether that is
// acceptable; text that is not a number is an error.
func intField(r *http.Request, name string, errs map[string]string) int {
	raw := strings.TrimSpace(r.FormValue(name))
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		errs[strings.SplitN(name, ":", 2)[0]] = "enter a whole number"
		return 0
	}
	return n
}

// splitLines returns the non-empty trimmed lines of a textarea value.
func splitLines(raw string) []string {
	out := []string{}
	for _, line := range strings.Split(raw, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
