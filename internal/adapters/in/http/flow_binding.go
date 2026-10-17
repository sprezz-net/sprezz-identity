package http

import (
	"net/http"
	"net/url"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/public"

	"github.com/google/uuid"
)

const routeAuthorize = "/oauth/authorize"

// flowMessageRefused is shown when a sign-in page or submit does not belong to the browser's pending session.
const flowMessageRefused = "We could not verify this sign-in. Make sure cookies are enabled, then start again from the application you were signing in to."

type flowResult int

const (
	// flowOK means the browser holds the pending session the flow belongs to.
	flowOK flowResult = iota
	// flowSignedIn means the browser is already signed in, so the form must not sign in again.
	flowSignedIn
	// flowRefused means there is no cookie, it belongs to another browser's flow, or the flow expired.
	flowRefused
)

// resolveFlow binds a sign-in page or submit to the browser that started the sign-in.
//
// With an interaction session (the sign-in started at /authorize) the cookie must be the pending session the
// interaction was bound to; anything else is refused, so a login or callback URL sent to another browser is useless.
// Without one (the login page opened directly) the browser's own session of the partition is used, and a pending one
// is started when mayStart is set and the browser has none.
func resolveFlow(w http.ResponseWriter, r *http.Request, sso port.SSOSessionUseCase, tenantID uuid.UUID, interaction *model.InteractionSession, directPartition int64, mayStart bool) (*model.SSOSession, flowResult) {
	cookies := requestCookies(r)

	if interaction != nil {
		session, err := sso.ResolveFlowSession(r.Context(), tenantID, interaction.PartitionID, cookies, interaction.SessionID)
		if err != nil {
			return nil, flowRefused
		}
		return session, stateOf(session)
	}

	if session, err := sso.ResolveDirectFlowSession(r.Context(), tenantID, directPartition, cookies); err == nil {
		return session, stateOf(session)
	}
	if !mayStart {
		return nil, flowRefused
	}

	flow, err := sso.StartFlow(r.Context(), port.StartFlowCommand{
		TenantID: tenantID, PartitionID: directPartition, Cookies: cookies, RequestHost: r.Host,
	})
	if err != nil {
		return nil, flowRefused
	}
	if flow.Cookie != nil {
		writeSessionCookie(w, flow.Cookie)
	}
	return &flow.Session, stateOf(&flow.Session)
}

func stateOf(session *model.SSOSession) flowResult {
	if session.State == model.SSOSessionActive {
		return flowSignedIn
	}
	return flowOK
}

// renderFlowRefused answers a page request that does not belong to the browser's flow.
func renderFlowRefused(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	w.WriteHeader(http.StatusForbidden)
	_ = public.Error(flowMessageRefused).Render(r.Context(), w)
}

// signedInRedirectURL is where a browser that is already signed in goes instead of signing in again: back to
// /authorize for the request it started (the session then completes it), or to the tenant's landing page.
func signedInRedirectURL(tenant *model.Tenant, interaction *model.InteractionSession) string {
	if interaction != nil {
		return reconstructAuthorizeURL(interaction)
	}
	if tenant != nil && tenant.Config.DefaultRedirectURI != "" {
		return tenant.Config.DefaultRedirectURI
	}
	return port.RouteWebProfile
}

// directPartitionOf is the partition of a sign-in that did not start at /authorize.
func directPartitionOf(tenant *model.Tenant) int64 {
	if tenant != nil && tenant.DefaultPartition != nil {
		return *tenant.DefaultPartition
	}
	return 0
}

// reconstructAuthorizeURL rebuilds the /authorize request an interaction session was created from.
func reconstructAuthorizeURL(session *model.InteractionSession) string {
	var sb strings.Builder
	sb.WriteString(routeAuthorize)
	sb.WriteString("?client_id=")
	sb.WriteString(url.QueryEscape(session.ClientID))
	sb.WriteString("&redirect_uri=")
	sb.WriteString(url.QueryEscape(session.RedirectURI))

	if session.CodeChallenge != "" {
		sb.WriteString("&code_challenge=")
		sb.WriteString(url.QueryEscape(session.CodeChallenge))
	}
	if session.ChallengeMethod != "" {
		sb.WriteString("&code_challenge_method=")
		sb.WriteString(url.QueryEscape(session.ChallengeMethod))
	}
	if session.IDPHint != "" {
		sb.WriteString("&idp_hint=")
		sb.WriteString(url.QueryEscape(session.IDPHint))
	}
	if session.State != "" {
		sb.WriteString("&state=")
		sb.WriteString(url.QueryEscape(session.State))
	}
	if session.Nonce != "" {
		sb.WriteString("&nonce=")
		sb.WriteString(url.QueryEscape(session.Nonce))
	}
	return sb.String()
}
