package service

import (
	"reflect"
	"sort"
	"testing"

	"sprezz-identity/internal/domain/port"

	"github.com/stretchr/testify/assert"
)

// gatedEntryPoints lists, per use-case interface, every method that is covered by TestInactiveTenant_EveryEntryPointRefuses
// or is a deliberate decision recorded in exemptEntryPoints. The test below fails when an interface gains a method
// that is in neither list, so adding an entry point forces a conscious choice about inactive tenants.
var gatedEntryPoints = map[string][]string{
	"AuthUseCase": {
		"ProcessDiscoveryMetadata", "ProcessJWKSetRetrieval", "ProcessAuthorizeRequest", "ExchangeCodeForTokens",
		"ExchangeClientCredentials", "ExchangeExternalToken", "RotateRefreshToken", "ProcessPushedAuthorization",
		"ProcessUserInfoRequest", "ProcessDynamicRegistration", "ProcessTokenIntrospection", "IntrospectToken",
		"RegisterDynamicApplication",
	},
	"FederatedLoginUseCase":    {"InitiateFederatedLogin", "ExecuteFederatedCallback"},
	"LocalAuthUseCase":         {"AuthenticateLocalCredentials", "GetLoginContext", "GetInteractionSession"},
	"UserRegistrationUseCase":  {"RegisterUser", "ApproveUserRequest", "GetSignupContext"},
	"UserProfileUseCase":       {"CreateUserProfile", "ChangeUserPassword", "ChangeUserEmail", "ChangeUserName", "DecoupleUserIdentity", "GetUserProfile", "GetUserProfileDashboard"},
	"SSOSessionUseCase":        {"BuildSessionCookie"},
	"IdentityAssuranceUseCase": {"AssertActionTrust"},
	"AdminLogonUseCase":        {"InitiateAdminLogon"},
}

// exemptEntryPoints are methods that deliberately keep working for an inactive tenant, with the reason.
var exemptEntryPoints = map[string]map[string]string{
	"AuthUseCase": {
		"ProcessLogoutRequest":   "signing out only reduces access, and people must always be able to do it",
		"ProcessTokenRevocation": "revoking a token only reduces access",
		"RevokeToken":            "revoking a token only reduces access",
	},
	"SSOSessionUseCase": {
		"ParseSessionCookie": "only reads a cookie value; it grants nothing by itself",
	},
	"TenantUseCase": {
		"ResolveTenantContext": "refuses inactive tenants itself (TestResolveTenantContext_RefusesInactiveTenants)",
		"CreateTenant":         "operator action on the platform, not a request to a tenant",
		"ToggleSignup":         "operator action; used by the status change",
		"UpdateTenant":         "operator action",
		"DeleteTenant":         "operator action; an inactive tenant must still be deletable",
	},
	"AdminApplicationUseCase": {"*": "operator console, reached only through the console's own active tenant (admin_tenant_service.actor)"},
	"IdentityProviderUseCase": {"*": "operator console; the sign-in methods of the identity provider service are listed in gatedEntryPoints under their own names"},
	"AdminUserUseCase":        {"*": "operator console, reached only through the console's own active tenant"},
	"AdminTenantUseCase":      {"*": "operator console; AdminTenantService.actor refuses an inactive acting tenant"},
}

func methodsOf(iface any) []string {
	typ := reflect.TypeOf(iface).Elem()
	out := make([]string, 0, typ.NumMethod())
	for i := 0; i < typ.NumMethod(); i++ {
		out = append(out, typ.Method(i).Name)
	}
	sort.Strings(out)
	return out
}

func TestInactiveTenant_EveryUseCaseMethodIsAccountedFor(t *testing.T) {
	interfaces := map[string]any{
		"AuthUseCase":              (*port.AuthUseCase)(nil),
		"FederatedLoginUseCase":    (*port.FederatedLoginUseCase)(nil),
		"LocalAuthUseCase":         (*port.LocalAuthUseCase)(nil),
		"UserRegistrationUseCase":  (*port.UserRegistrationUseCase)(nil),
		"UserProfileUseCase":       (*port.UserProfileUseCase)(nil),
		"SSOSessionUseCase":        (*port.SSOSessionUseCase)(nil),
		"IdentityAssuranceUseCase": (*port.IdentityAssuranceUseCase)(nil),
		"AdminLogonUseCase":        (*port.AdminLogonUseCase)(nil),
		"TenantUseCase":            (*port.TenantUseCase)(nil),
		"AdminApplicationUseCase":  (*port.AdminApplicationUseCase)(nil),
		"IdentityProviderUseCase":  (*port.IdentityProviderUseCase)(nil),
		"AdminUserUseCase":         (*port.AdminUserUseCase)(nil),
		"AdminTenantUseCase":       (*port.AdminTenantUseCase)(nil),
	}

	for name, iface := range interfaces {
		gated := toSet(gatedEntryPoints[name])
		exempt := exemptEntryPoints[name]
		for _, method := range methodsOf(iface) {
			_, isGated := gated[method]
			_, isExempt := exempt[method]
			_, allExempt := exempt["*"]
			assert.Truef(t, isGated || isExempt || allExempt,
				"%s.%s is not covered: add a tenant gate and list it in gatedEntryPoints, or record why it is exempt in exemptEntryPoints", name, method)
		}
		// A stale entry (a method that no longer exists) would hide a gap, so those fail too.
		existing := toSet(methodsOf(iface))
		for method := range gated {
			_, ok := existing[method]
			assert.Truef(t, ok, "gatedEntryPoints lists %s.%s, which does not exist", name, method)
		}
	}
}

func toSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		out[v] = struct{}{}
	}
	return out
}
