package http

import (
	"fmt"
	"log/slog"
	"net/http"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/go-chi/chi/v5"
)

type CallbackHandler struct {
	federatedUseCase port.FederatedLoginUseCase
	authUseCase      port.AuthUseCase
	ssoUseCase       port.SSOSessionUseCase
}

func NewCallbackHandler(fuc port.FederatedLoginUseCase, auc port.AuthUseCase, suc port.SSOSessionUseCase) *CallbackHandler {
	return &CallbackHandler{
		federatedUseCase: fuc,
		authUseCase:      auc,
		ssoUseCase:       suc,
	}
}

// Routes registers both the inbound local application and outbound federation callback vectors.
func (h *CallbackHandler) Routes(r chi.Router) {
	r.Get(port.RouteFederationCallback, h.HandleFederationCallback)
}

// HandleFederationCallback processes incoming responses from upstream external Identity Providers (egress loop).
func (h *CallbackHandler) HandleFederationCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	tenantUUID := TenantIDFromContext(r.Context())

	slog.Debug("HandleFederationCallback: federation callback triggered", "tenant_id", tenantUUID, "state", state, "code_len", len(code))

	if state == "" || code == "" {
		slog.Error("HandleFederationCallback: mandatory state or code query variables missing")
		h.writeWebError(w, http.StatusBadRequest, "invalid_request", "mandatory federation transaction query variables missing")
		return
	}

	// The state only redeems for a browser that holds the pending session the sign-in was started with. A callback
	// URL sent to somebody else's browser finds no matching cookie and is refused.
	flowIDs, err := h.ssoUseCase.ResolveFlowSessionIDs(r.Context(), tenantUUID, requestCookies(r))
	if err != nil {
		h.writeWebError(w, http.StatusForbidden, "access_denied", "the sign-in could not be verified")
		return
	}

	cmd := port.FederatedCallbackCommand{
		TenantID:       tenantUUID,
		IncomingState:  state,
		IncomingCode:   code,
		FlowSessionIDs: flowIDs,
		RequestURL:     r.URL.String(),
		HTTPMethod:     r.Method,
	}

	response, err := h.federatedUseCase.ExecuteFederatedCallback(r.Context(), cmd)
	if err != nil {
		slog.Error("HandleFederationCallback: ExecuteFederatedCallback failed", "err", err)
		h.writeWebError(w, http.StatusForbidden, "access_denied", "the sign-in could not be completed, please start again")
		return
	}

	// Signing in promotes the pending session: same session ID, a fresh secret, and the full lifetime.
	created, err := h.ssoUseCase.PromoteSession(r.Context(), port.PromoteSessionCommand{
		TenantID:           tenantUUID,
		SessionID:          response.FlowSessionID,
		PartitionID:        response.PartitionID,
		UserProfileID:      response.UserProfileID,
		IdentityProviderID: response.IdentityProviderID,
		RequestHost:        r.Host,
	})
	if err != nil {
		slog.Error("HandleFederationCallback: PromoteSession failed", "err", err)
		h.writeWebError(w, http.StatusForbidden, "access_denied", "the sign-in could not be completed, please start again")
		return
	}

	writeSessionCookie(w, &created.Cookie)

	redirectTarget := response.TargetLandingURI
	if redirectTarget == "" {
		redirectTarget = "/"
	}

	slog.Debug("HandleFederationCallback: redirecting user to final target dashboard", "redirectTarget", redirectTarget)

	if r.Header.Get("HX-Request") != "" {
		w.Header().Set("HX-Redirect", redirectTarget)
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, redirectTarget, http.StatusFound)
}

func (h *CallbackHandler) writeWebError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set(model.HeaderContentType, "text/plain")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "%s: %s", code, desc)
}
