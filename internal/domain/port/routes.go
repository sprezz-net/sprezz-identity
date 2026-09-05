package port

// Shared operational route paths that the core domain logic must be aware of
// to calculate matching tenant whitelists, landing zones, or validation bounds.
const (
	RouteAdmin              = "/admin"
	RouteAdminDashboard     = RouteAdmin + "/dashboard"
	RouteFederationCallback = "/oauth/federation/callback"
)
