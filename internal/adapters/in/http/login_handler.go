package http

import (
	"log/slog"
	"net/http"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/public"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// flowMessageExpired is shown when the ?tx= of a sign-in is unknown or has expired.
const flowMessageExpired = "Your sign-in took too long or is no longer valid. Please start again from the application you were signing in to."

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

// loadInteraction loads the pending OAuth request behind a ?tx= value. ok is false when a tx was given that is
// unknown or expired; an empty tx is a login page opened directly and gives (nil, true).
func (h *LoginHandler) loadInteraction(r *http.Request, tenantID uuid.UUID, tx string) (*model.InteractionSession, bool) {
	if tx == "" {
		return nil, true
	}
	interaction, err := h.localAuthUseCase.GetInteractionSession(r.Context(), tenantID, tx)
	if err != nil || interaction == nil {
		return nil, false
	}
	return interaction, true
}

func renderFlowExpired(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	w.WriteHeader(http.StatusGone)
	_ = public.Error(flowMessageExpired).Render(r.Context(), w)
}

func (h *LoginHandler) HandleLoginRoot(w http.ResponseWriter, r *http.Request) {
	tenantUUID := TenantIDFromContext(r.Context())
	tenant, _ := TenantFromContext(r.Context())
	tx := r.URL.Query().Get("tx")

	interaction, ok := h.loadInteraction(r, tenantUUID, tx)
	if !ok {
		renderFlowExpired(w, r)
		return
	}

	// The sign-in belongs to the browser that started it. A direct visit starts a pending session of its own.
	session, result := resolveFlow(w, r, h.ssoUseCase, tenantUUID, interaction, directPartitionOf(tenant), true)
	switch result {
	case flowRefused:
		renderFlowRefused(w, r)
		return
	case flowSignedIn:
		http.Redirect(w, r, signedInRedirectURL(tenant, interaction), http.StatusFound)
		return
	case flowOK:
	}

	ctxResp, err := h.localAuthUseCase.GetLoginContext(r.Context(), port.GetLoginContextCommand{
		TenantID:      tenantUUID,
		InteractionID: tx,
		IDPHintQuery:  r.URL.Query().Get("idp_hint"),
	})
	if err != nil {
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusInternalServerError)
		_ = public.Error("Internal server fault loading identity providers").Render(r.Context(), w)
		return
	}

	if ctxResp.TriggerAutoFederatedIDP != nil {
		h.triggerExternalFederationRedirection(w, r, tenantUUID, *ctxResp.TriggerAutoFederatedIDP, ctxResp.InteractionSession, ctxResp.TenantBaseURI, session.ID)
		return
	}

	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	component := public.Login(public.LoginProps{
		FieldErrors:              make(map[string]string),
		AllowSignup:              ctxResp.AllowSignup,
		Providers:                ctxResp.Providers,
		ShowUsernamePasswordForm: ctxResp.ShowUsernamePasswordForm,
		PartitionID:              ctxResp.PartitionID,
		InteractionID:            tx,
	})
	_ = component.Render(r.Context(), w)
}

func (h *LoginHandler) HandleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	tenantUUID := TenantIDFromContext(r.Context())
	tenant, _ := TenantFromContext(r.Context())
	tx := r.FormValue("tx")

	ctxResp, ctxErr := h.localAuthUseCase.GetLoginContext(r.Context(), port.GetLoginContextCommand{
		TenantID:      tenantUUID,
		InteractionID: tx,
	})
	if ctxErr != nil || ctxResp == nil {
		renderFlowExpired(w, r)
		return
	}

	interaction, ok := h.loadInteraction(r, tenantUUID, tx)
	if !ok {
		renderFlowExpired(w, r)
		return
	}

	// Only the browser that started the sign-in may finish it. A submit without its cookie is refused, whether the
	// cookies are blocked or the form was posted from somewhere else.
	session, result := resolveFlow(w, r, h.ssoUseCase, tenantUUID, interaction, directPartitionOf(tenant), false)
	switch result {
	case flowRefused:
		h.renderInlineFormError(w, r, ctxResp, tx, map[string]string{"global": flowMessageRefused})
		return
	case flowSignedIn:
		// A stale tab or a double submit: the existing session completes the request, no second sign-in.
		w.Header().Set(model.HeaderHxRedirect, signedInRedirectURL(tenant, interaction))
		w.WriteHeader(http.StatusOK)
		return
	case flowOK:
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		errs := make(map[string]string)
		if username == "" {
			errs["username"] = "Username field identifier is required"
		}
		if password == "" {
			errs["password"] = "Password authorization parameter is required"
		}
		h.renderInlineFormError(w, r, ctxResp, tx, errs)
		return
	}

	partitionID, providerID, redirectURL := h.localSignInTarget(tenant, interaction)

	// 1. Authenticate local credentials first (verifies password and handles lockouts)
	loginResp, err := h.localAuthUseCase.AuthenticateLocalCredentials(r.Context(), port.LocalLoginCommand{
		TenantID:          tenantUUID,
		PartitionID:       partitionID,
		ProviderID:        providerID,
		Identifier:        username,
		PlaintextPassword: password,
	})
	if err != nil {
		// Enforce a uniform, generic error string over ALL authentication errors
		// This completely masks lockouts, administrative blocks, and non-existent users.
		genericErrorMessage := "Invalid username or password"

		// We log the forensic reason internally for audit trails but never leak it to the client viewport
		slog.Warn("Local authentication checkpoint failed",
			"error", err,
			"tenant_id", tenantUUID,
			"username", username,
		)
		h.renderInlineFormError(w, r, ctxResp, tx, map[string]string{
			"username": genericErrorMessage,
			"password": genericErrorMessage,
		})
		return
	}

	// 2. Signing in promotes the pending session: same session ID, a fresh secret and the full lifetime. The cookie
	// the sign-in ran under stops working at this moment.
	created, err := h.ssoUseCase.PromoteSession(r.Context(), port.PromoteSessionCommand{
		TenantID:           tenantUUID,
		SessionID:          session.ID,
		PartitionID:        session.PartitionID,
		UserProfileID:      loginResp.UserProfileID,
		IdentityProviderID: providerID,
		RequestHost:        r.Host,
	})
	if err != nil {
		slog.Error("Local login: failed to promote the session", "error", err, "tenant_id", tenantUUID)
		h.renderInlineFormError(w, r, ctxResp, tx, map[string]string{"global": "Unable to sign you in right now. Please try again."})
		return
	}
	writeSessionCookie(w, &created.Cookie)

	// 3. If there is an interaction session, delegate to the OIDC authorize flow to complete the request
	if interaction != nil {
		result, err := h.authUseCase.ProcessAuthorizeRequest(r.Context(), port.AuthorizeRequestCommand{
			TenantID:        tenantUUID,
			ClientID:        interaction.ClientID,
			RedirectURI:     interaction.RedirectURI,
			CodeChallenge:   interaction.CodeChallenge,
			ChallengeMethod: interaction.ChallengeMethod,
			State:           interaction.State,
			Nonce:           interaction.Nonce,
			ACRValues:       interaction.ACRValues,
			RequestHost:     r.Host,
			RequestURI:      "",
			ActiveSession:   &created.Session,
		})
		if err != nil {
			h.renderInlineFormError(w, r, ctxResp, tx, map[string]string{"global": err.Error()})
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

	w.Header().Set(model.HeaderHxRedirect, redirectURL)
	w.WriteHeader(http.StatusOK)
}

// localSignInTarget works out where a local sign-in happens: the partition, the provider and, for a direct visit
// without an interaction session, where to land afterwards.
func (h *LoginHandler) localSignInTarget(tenant *model.Tenant, interaction *model.InteractionSession) (int64, uuid.UUID, string) {
	if interaction != nil {
		partitionID := interaction.PartitionID
		if partitionID == 0 {
			partitionID = directPartitionOf(tenant)
		}
		return partitionID, interaction.IdentityProviderID, ""
	}

	redirectURL := ""
	if tenant != nil {
		redirectURL = tenant.Config.DefaultRedirectURI
	}
	return directPartitionOf(tenant), uuid.Nil, redirectURL
}

// Returning an HTTP 200 OK alongside only the LoginForm sub-component partial
func (h *LoginHandler) renderInlineFormError(w http.ResponseWriter, r *http.Request, ctxResp *port.LoginContextResponse, tx string, fieldErrors map[string]string) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	w.WriteHeader(http.StatusOK)

	props := public.LoginProps{
		FieldErrors:              fieldErrors,
		AllowSignup:              ctxResp.AllowSignup,
		Providers:                ctxResp.Providers,
		ShowUsernamePasswordForm: ctxResp.ShowUsernamePasswordForm,
		PartitionID:              ctxResp.PartitionID,
		InteractionID:            tx,
		Username:                 r.FormValue("username"), // Retains the typed username
	}

	component := public.LoginForm(props)
	_ = component.Render(r.Context(), w)
}

func (h *LoginHandler) triggerExternalFederationRedirection(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, provider model.IdentityProvider, interaction *model.InteractionSession, baseURI string, flowSessionID uuid.UUID) {
	// Assemble the fully qualified absolute redirection URL loop per RFC 6749 constraints
	absoluteCallbackURI := baseURI + port.RouteFederationCallback

	var clientID, finalTarget string
	if interaction != nil {
		clientID, finalTarget = interaction.ClientID, interaction.RedirectURI
	} else if tenant, ok := TenantFromContext(r.Context()); ok {
		finalTarget = tenant.Config.DefaultRedirectURI
	}

	// Delegate the initiation of the external federation payload directly down to the use case port
	response, err := h.federatedUseCase.InitiateFederatedLogin(r.Context(), port.InitiateFederatedLoginCommand{
		TenantID:           tenantID,
		IdentityProviderID: provider.ID,
		ClientID:           clientID,
		RequestedScopes:    provider.Config.Scopes,
		LocalCallbackURI:   absoluteCallbackURI,
		FinalTargetURI:     finalTarget,
		FlowSessionID:      flowSessionID,
	})

	if err != nil {
		w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
		w.WriteHeader(http.StatusBadRequest)
		_ = public.Error(err.Error()).Render(r.Context(), w)
		return
	}

	http.Redirect(w, r, response.TargetRedirectURL, http.StatusFound)
}
