package port

// Shared operational route paths that the core domain logic must be aware of
// to calculate matching tenant whitelists, landing zones, or validation bounds.
const (
	// Core OAuth2 and OpenID Connect endpoints
	RouteWellKnownOAuthServer  = "/.well-known/oauth-authorization-server"
	RouteWellKnownOpenIDConfig = "/.well-known/openid-configuration"
	RouteWellKnownKeys         = "/.well-known/jwks.json"
	RouteAuthorize             = "/oauth/authorize"
	RouteToken                 = "/oauth/token"
	RouteUserInfo              = "/oauth/userinfo"
	RouteRegister              = "/oauth/register"
	RouteRevoke                = "/oauth/revoke"
	RouteIntrospect            = "/oauth/introspect"
	RouteLogout                = "/oauth/logout"
	RoutePAR                   = "/oauth/par"
	RouteCallback              = "/oauth/callback"
	RouteFederationCallback    = "/oauth/federation/callback"

	// Core web application routes
	RouteRoot      = "/"
	RouteWebLogin  = "/login"
	RouteWebLogout = "/logout"
	RouteWebSignUp = "/sign-up"

	// Profile routes
	RouteWebProfile           = "/profile"
	RouteWebProfilePassword   = "/password"
	RouteWebProfileEmail      = "/email"
	RouteWebProfileName       = "/name"
	RouteWebProfileIdentities = "/identities"

	// Administrative routes for the internal management console
	RouteAdmin                     = "/admin"
	RouteAdminDashboard            = "/dashboard"
	RouteAdminApplications         = "/applications"
	RouteAdminApplicationsProfiles = "/profiles"
	RouteAdminApplicationsGroups   = "/groups"
	RouteAdminIdentityProviders    = "/idps"
	RouteAdminUsers                = "/users"
	RouteAdminUsersIdentities      = "/identities"
	RouteAdminTenants              = "/tenants"
)
