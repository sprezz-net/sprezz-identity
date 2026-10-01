package admin

import (
	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

// TenantListProps is everything the tenant list renders. Filtering is applied on the server.
type TenantListProps struct {
	ActiveTenant model.Tenant
	Rows         []port.TenantDetail
	Msg          string
	Query        string
	Status       string
	// CanManageAll is true for the administrative tenant, which may add and delete tenants.
	CanManageAll bool
}

// TenantPageProps is everything the tenant detail page renders.
type TenantPageProps struct {
	ActiveTenant model.Tenant
	Detail       *port.TenantDetail
	CanManageAll bool
	Msg          string
	Sections     map[string]SectionResult
}

// Section returns the result for a section, or the zero value when it was not just saved.
func (p TenantPageProps) Section(name string) SectionResult {
	return p.Sections[name]
}

// CanDeactivate reports whether the status card is offered: only the administrative tenant may switch tenants on
// and off, and never itself or another system tenant.
func (p TenantPageProps) CanDeactivate() bool {
	return p.CanManageAll && !p.Detail.Tenant.IsSystem && !p.IsOwn()
}

// IsOwn reports whether the page shows the tenant the administrator is signed in to.
func (p TenantPageProps) IsOwn() bool {
	return p.Detail.Tenant.ID == p.ActiveTenant.ID
}

func tenantsBase() string {
	return port.RouteAdmin + port.RouteAdminTenants
}

func tenantURL(id string) string {
	return tenantsBase() + "/" + id
}

func tenantSectionAction(id, section string) string {
	return tenantURL(id) + "/" + section
}

// TenantNewProps drives the add form.
type TenantNewProps struct {
	ActiveTenant model.Tenant
	Errors       map[string]string
	Error        string
	Values       map[string]string
}

// V returns the value typed before a validation error.
func (p TenantNewProps) V(name string) string {
	return p.Values[name]
}

// TenantDeleteProps builds the danger zone of a tenant, including what the deletion would remove.
func TenantDeleteProps(props TenantPageProps) ConfirmDeleteProps {
	u := props.Detail.Usage
	p := ConfirmDeleteProps{
		Action:   tenantURL(props.Detail.Tenant.ID.String()),
		Expected: props.Detail.Tenant.Domain,
		Noun:     "tenant",
		Warning: "Deleting this tenant permanently removes " + itoa(u.Users) + " user(s), " + itoa(u.Applications) + " application(s), " +
			itoa(u.Groups) + " group(s), " + itoa(u.Profiles) + " profile(s), " + itoa(u.Providers) + " identity provider(s) and " +
			itoa(u.Partitions) + " partition(s), together with its keys, sessions and audit trail. It cannot be undone.",
	}
	if props.IsOwn() {
		p.Blocked = "You are signed in to this tenant, so it cannot be deleted from here."
	}
	return p
}
