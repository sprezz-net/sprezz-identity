package admin

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

// IDPRow is one line of the provider list.
type IDPRow struct {
	Provider      model.IdentityProvider
	Usage         model.IdentityProviderUsage
	PartitionName string
}

// IDPListProps is everything the provider list renders. Filters are applied on the server.
type IDPListProps struct {
	ActiveTenant model.Tenant
	Rows         []IDPRow
	Partitions   []model.Partition
	Msg          string
	Query        string
	Type         string
	Status       string
	PartitionID  int64
}

// IDPPageProps is everything the provider detail page renders.
type IDPPageProps struct {
	ActiveTenant  model.Tenant
	Provider      *model.IdentityProvider
	Usage         model.IdentityProviderUsage
	PartitionName string
	Msg           string
	Sections      map[string]SectionResult
}

// Section returns the result for a section, or the zero value when it was not just saved.
func (p IDPPageProps) Section(name string) SectionResult {
	return p.Sections[name]
}

// IDPNewProps drives the add flow: a type picker first, then a short form for the chosen type.
type IDPNewProps struct {
	ActiveTenant model.Tenant
	Partitions   []model.Partition
	Type         string
	Errors       map[string]string
	Error        string
	Values       map[string]string
}

// V returns the value the admin typed before a validation error.
func (p IDPNewProps) V(name string) string {
	return p.Values[name]
}

func idpsBase() string {
	return port.RouteAdmin + port.RouteAdminIdentityProviders
}

func idpURL(id string) string {
	return idpsBase() + "/" + id
}

func idpSectionAction(id, section string) string {
	return idpURL(id) + "/" + section
}

func idpTypeLabel(idpType string) string {
	if idpType == model.UsernamePasswordIDPType {
		return "Local accounts"
	}
	return "OpenID Connect"
}

// discoveryMeta returns the stored provider metadata snapshot, or nil when there is none.
func discoveryMeta(p *model.IdentityProvider) *model.OIDCDiscoveryMetadata {
	if p == nil || p.Config.DiscoveryResult == "" {
		return nil
	}
	var meta model.OIDCDiscoveryMetadata
	if err := json.Unmarshal([]byte(p.Config.DiscoveryResult), &meta); err != nil {
		return nil
	}
	return &meta
}

func joinList(values []string) string {
	return strings.Join(values, ", ")
}

func joinLines(values []string) string {
	return strings.Join(values, "\n")
}

func levelText(n int) string {
	return strconv.Itoa(n)
}

func formatTime(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04 MST")
}

// acrChoices lists every ACR value the admin can map: the ones already mapped or requested, plus those the
// provider advertises.
func acrChoices(p *model.IdentityProvider) []string {
	seen := map[string]bool{}
	for k := range p.Config.AcrToTuple {
		seen[k] = true
	}
	for _, v := range p.Config.ACRValues {
		seen[v] = true
	}
	if meta := discoveryMeta(p); meta != nil {
		for _, v := range meta.ACRValuesSupported {
			seen[v] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func amrNames(p *model.IdentityProvider) []string {
	out := make([]string, 0, len(p.Config.AmrToAAL))
	for k := range p.Config.AmrToAAL {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func containsString(list []string, target string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

func IDPDeleteProps(props IDPPageProps) ConfirmDeleteProps {
	p := ConfirmDeleteProps{
		Action:   idpURL(props.Provider.ID.String()),
		Expected: props.Provider.Alias,
		Noun:     "provider",
		Warning:  "Deleting a provider cannot be undone.",
	}
	if n := props.Usage.LinkedUsers; n > 0 {
		p.Warning += " " + itoa(n) + " user(s) have signed in with it and will lose that sign-in method."
	}
	if n := len(props.Usage.GroupNames); n > 0 {
		p.Blocked = "This provider is allowed by " + itoa(n) + " group(s): " + strings.Join(props.Usage.GroupNames, ", ") + ". Remove it from their sign-in methods first."
	}
	return p
}

func joinSpaces(values []string) string {
	return strings.Join(values, " ")
}

// amrLines renders the authentication method mapping as one name=level line each.
func amrLines(p *model.IdentityProvider) string {
	lines := make([]string, 0, len(p.Config.AmrToAAL))
	for _, name := range amrNames(p) {
		lines = append(lines, name+"="+strconv.Itoa(p.Config.AmrToAAL[name]))
	}
	return strings.Join(lines, "\n")
}
