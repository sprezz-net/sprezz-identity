package http

import (
	"context"
	"fmt"
	"net/http"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/public"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type LoginHandler struct {
	authUseCase      port.AuthUseCase
	federatedUseCase port.FederatedLoginUseCase
	ssoUseCase       port.SSOSessionUseCase
	localAuthUseCase port.LocalAuthUseCase
}

func NewLoginHandler(auc port.AuthUseCase, fuc port.FederatedLoginUseCase, suc port.SSOSessionUseCase, lauc port.LocalAuthUseCase) *LoginHandler {
	return &LoginHandler{
		authUseCase:      auc,
		federatedUseCase: fuc,
		ssoUseCase:       suc,
		localAuthUseCase: lauc,
	}
}

func (h *LoginHandler) Routes(r chi.Router) {
	r.Get("/", h.HandleLoginRootRedirect)
	r.Get(port.RouteWebLogin, h.HandleLoginRoot)
	r.Post(port.RouteWebLogin, h.HandleLoginSubmit)
}

func (h *LoginHandler) HandleLoginRootRedirect(w http.ResponseWriter, r *http.Request) {
	target := port.RouteWebLogin
	if q := r.URL.Query().Encode(); q != "" {
		target += "?" + q
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (h *LoginHandler) HandleLoginRoot(w http.ResponseWriter, r *http.Request) {
	tenantUUID := h.mustResolveTenant(r.Context())
	interactionID := r.URL.Query().Get("tx")
	if interactionID == "" {
		interactionID = h.parseInteractionCookie(r, tenantUUID)
	}

	if interactionID == "" {
		if h.hasActiveBearerSession(r, tenantUUID) {
			if tenant, ok := TenantFromContext(r.Context()); ok && tenant.Config.DefaultRedirectURI != "" {
				http.Redirect(w, r, tenant.Config.DefaultRedirectURI, http.StatusFound)
				return
			}
		}
	}

	ctxResp, err := h.localAuthUseCase.GetLoginContext(r.Context(), port.GetLoginContextCommand{
		TenantID:      tenantUUID,
		InteractionID: interactionID,
		IDPHintQuery:  r.URL.Query().Get("idp_hint"),
	})
	if err != nil {
		w.Header().Set(model.HeaderContentType, "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = public.Error("Internal server fault loading identity providers").Render(r.Context(), w)
		return
	}

	if ctxResp.TriggerAutoFederatedIDP != nil {
		h.triggerExternalFederationRedirection(w, r, tenantUUID, *ctxResp.TriggerAutoFederatedIDP, ctxResp.InteractionSession, ctxResp.TenantBaseURI)
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	component := public.Login(public.LoginProps{
		ErrorMessage:             "",
		AllowSignup:              ctxResp.AllowSignup,
		Providers:                ctxResp.Providers,
		ShowUsernamePasswordForm: ctxResp.ShowUsernamePasswordForm,
		PartitionID:              ctxResp.PartitionID,
		InteractionID:            interactionID,
	})
	_ = component.Render(r.Context(), w)
}

func (h *LoginHandler) HandleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderInlineFormError(w, r, "Malformed form payload parameters submitted")
		return
	}

	tenantUUID := h.mustResolveTenant(r.Context())
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		h.renderInlineFormError(w, r, "Username and password fields are both required")
		return
	}

	interactionID := r.FormValue("tx")
	if interactionID == "" {
		interactionID = h.parseInteractionCookie(r, tenantUUID)
	}
	interactionSession, _ := h.localAuthUseCase.GetInteractionSession(r.Context(), tenantUUID, interactionID)

	var partitionID int64
	var providerID uuid.UUID
	var redirectURL string

	if interactionSession != nil {
		if interactionSession.PartitionID != 0 {
			partitionID = interactionSession.PartitionID
		} else {
			tenant, ok := TenantFromContext(r.Context())
			if ok && tenant.DefaultPartition != nil {
				partitionID = *tenant.DefaultPartition
			}
		}
		providerID = interactionSession.IdentityProviderID
	} else {
		tenant, ok := TenantFromContext(r.Context())
		if ok {
			if tenant.DefaultPartition != nil {
				partitionID = *tenant.DefaultPartition
			}
			redirectURL = tenant.Config.DefaultRedirectURI
		}
	}

	// 1. Authenticate local credentials first (verifies password and handles lockouts)
	loginResp, err := h.localAuthUseCase.AuthenticateLocalCredentials(r.Context(), port.LocalLoginCommand{
		TenantID:          tenantUUID,
		PartitionID:       partitionID,
		ProviderID:        providerID,
		Identifier:        username,
		PlaintextPassword: password,
	})
	if err != nil {
		h.renderInlineFormError(w, r, err.Error())
		return
	}

	// 2. Provision the single sign-on bearer session cookie on the browser using the user's unique stable UUID
	cookieIntent, err := h.ssoUseCase.BuildSessionCookie(r.Context(), port.CookieIntentCommand{
		TenantID:       tenantUUID,
		PartitionID:    partitionID,
		PayloadValue:   fmt.Sprintf("%s:%d", loginResp.Subject, partitionID),
		LifecycleStage: "bearer",
		RequestHost:    r.Host,
	})
	if err == nil {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieIntent.CookieName,
			Value:    cookieIntent.CookieValue,
			Path:     "/",
			MaxAge:   cookieIntent.MaxAge,
			HttpOnly: true,
			Secure:   cookieIntent.Secure,
			SameSite: http.SameSiteLaxMode,
		})
	}

	// 3. If there is an active interaction session, delegate to OIDC authorize flow completion
	if interactionSession != nil {
		result, err := h.authUseCase.ProcessAuthorizeRequest(r.Context(), port.AuthorizeRequestCommand{
			TenantID:        tenantUUID,
			ClientID:        interactionSession.ClientID,
			RedirectURI:     interactionSession.RedirectURI,
			CodeChallenge:   interactionSession.CodeChallenge,
			ChallengeMethod: interactionSession.ChallengeMethod,
			State:           interactionSession.State,
			Nonce:           interactionSession.Nonce,
			ACRValues:       interactionSession.ACRValues,
			RequestHost:     r.Host,
			RequestURI:      "",
			ActiveSessionID: fmt.Sprintf("%s:%d", loginResp.Subject, partitionID),
		})
		if err != nil {
			h.renderInlineFormError(w, r, err.Error())
			return
		}
		redirectURL = result.RedirectURL

		if result.HasCookieIntent {
			http.SetCookie(w, &http.Cookie{
				Name:     result.CookieName,
				Value:    result.CookieValue,
				Path:     "/",
				MaxAge:   result.CookieMaxAge,
				HttpOnly: true,
				Secure:   result.CookieSecure,
				SameSite: http.SameSiteLaxMode,
			})
		}
	}

	if redirectURL == "" {
		redirectURL = "/"
	}

	w.Header().Set(model.HeaderHXRedirect, redirectURL)
	w.WriteHeader(http.StatusOK)
}

func (h *LoginHandler) renderInlineFormError(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<div class="p-4 bg-red-50 border border-red-200 text-red-800 rounded-lg text-sm font-medium">%s</div>`, message)
}

func (h *LoginHandler) parseInteractionCookie(r *http.Request, tenantID uuid.UUID) string {
	cookieSpec, err := h.ssoUseCase.BuildSessionCookie(r.Context(), port.CookieIntentCommand{
		TenantID:       tenantID,
		LifecycleStage: "handshake",
		RequestHost:    r.Host,
	})
	if err != nil {
		return ""
	}

	cookie, err := r.Cookie(cookieSpec.CookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}

	_, payload, err := h.ssoUseCase.ParseSessionCookie(r.Context(), cookie.Value)
	if err != nil {
		return ""
	}

	return payload
}

func (h *LoginHandler) hasActiveBearerSession(r *http.Request, tenantID uuid.UUID) bool {
	cookieSpec, err := h.ssoUseCase.BuildSessionCookie(r.Context(), port.CookieIntentCommand{
		TenantID:       tenantID,
		LifecycleStage: "clear",
		RequestHost:    r.Host,
	})
	if err != nil {
		return false
	}

	cookie, err := r.Cookie(cookieSpec.CookieName)
	if err != nil {
		return false
	}

	stage, _, err := h.ssoUseCase.ParseSessionCookie(r.Context(), cookie.Value)
	return err == nil && stage == "bearer"
}

func (h *LoginHandler) triggerExternalFederationRedirection(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, provider model.IdentityProvider, session *model.InteractionSession, baseURI string) {
	// Assemble the fully qualified absolute redirection URL loop per RFC 6749 constraints
	absoluteCallbackURI := baseURI + port.RouteFederationCallback

	// Delegate the initiation of the external federation payload directly down to the use case port
	response, err := h.federatedUseCase.InitiateFederatedLogin(r.Context(), port.InitiateFederatedLoginCommand{
		TenantID:           tenantID,
		IdentityProviderID: provider.ID,
		ClientID:           session.ClientID,
		RequestedScopes:    provider.Config.Scopes,
		LocalCallbackURI:   absoluteCallbackURI,
		FinalTargetURI:     session.RedirectURI,
	})

	if err != nil {
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusBadRequest)
		_ = public.Error(err.Error()).Render(r.Context(), w)
		return
	}

	http.Redirect(w, r, response.TargetRedirectURL, http.StatusFound)
}

func (h *LoginHandler) mustResolveTenant(ctx context.Context) uuid.UUID {
	if val := ctx.Value(tenantIDCtxKey); val != nil {
		if uid, ok := val.(uuid.UUID); ok {
			return uid
		}
	}
	return uuid.Nil
}
