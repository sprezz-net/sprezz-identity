package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildLocalLoginTestAdapter(ctrl *minimock.Controller) (*HttpAdapter, *portmock.LocalAuthUseCaseMock, *portmock.SSOSessionUseCaseMock, *portmock.TenantUseCaseMock, *portmock.AuthUseCaseMock, *portmock.FederatedLoginUseCaseMock) {
	storage := portmock.NewStorageMock(ctrl)
	auth := portmock.NewAuthUseCaseMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	tuc := portmock.NewTenantUseCaseMock(ctrl)
	fuc := portmock.NewFederatedLoginUseCaseMock(ctrl)
	suc := portmock.NewSSOSessionUseCaseMock(ctrl)
	upuc := portmock.NewUserProfileUseCaseMock(ctrl)
	uruc := portmock.NewUserRegistrationUseCaseMock(ctrl)
	lauc := portmock.NewLocalAuthUseCaseMock(ctrl)

	adapter := NewHttpAdapter(tuc, auth, fuc, nil, suc, upuc, uruc, lauc, nil, nil, nil, storage, crypto, "unittest", "admin-domain.com")
	return adapter, lauc, suc, tuc, auth, fuc
}

const testFlowCookie = "spz_session_default"

// loginFixture is a tenant with a local provider and one sign-in that was started at /authorize: an interaction
// session bound to the pending session of a browser.
type loginFixture struct {
	t        *testing.T
	adapter  *HttpAdapter
	lauc     *portmock.LocalAuthUseCaseMock
	sso      *portmock.SSOSessionUseCaseMock
	auth     *portmock.AuthUseCaseMock
	fuc      *portmock.FederatedLoginUseCaseMock
	tenant   *model.Tenant
	provider model.IdentityProvider
	pending  model.SSOSession
	interact *model.InteractionSession
	userID   uuid.UUID
	promoted *port.PromoteSessionCommand
}

func newLoginFixture(t *testing.T) *loginFixture {
	t.Helper()
	ctrl := minimock.NewController(t)
	adapter, lauc, suc, tuc, auth, fuc := buildLocalLoginTestAdapter(ctrl)

	tenantID := uuid.New()
	part := int64(1)
	f := &loginFixture{
		t: t, adapter: adapter, lauc: lauc, sso: suc, auth: auth, fuc: fuc, userID: uuid.New(),
		tenant:   &model.Tenant{ID: tenantID, Domain: "test.com", Config: model.TenantConfig{AllowSignup: true, DefaultRedirectURI: "https://test.com/home"}, DefaultPartition: &part, IsActive: true},
		provider: model.IdentityProvider{ID: uuid.New(), TenantID: tenantID, IDPType: model.UsernamePasswordIDPType, Enabled: true},
		pending:  model.SSOSession{ID: uuid.New(), TenantID: tenantID, PartitionID: 1, State: model.SSOSessionPending},
	}
	f.interact = &model.InteractionSession{
		ID: uuid.New(), TenantID: tenantID, PartitionID: 1, ClientID: "client-abc", RedirectURI: "https://callback",
		State: "st", IdentityProviderID: f.provider.ID, SessionID: f.pending.ID,
	}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) { return f.tenant, nil })
	lauc.GetLoginContextMock.Optional().Set(func(ctx context.Context, cmd port.GetLoginContextCommand) (*port.LoginContextResponse, error) {
		return &port.LoginContextResponse{
			AllowSignup: true, Providers: []model.IdentityProvider{f.provider}, ShowUsernamePasswordForm: true, PartitionID: 1,
			InteractionSession: f.interact,
		}, nil
	})
	lauc.GetInteractionSessionMock.Optional().Set(func(ctx context.Context, tenantID uuid.UUID, id string) (*model.InteractionSession, error) {
		if f.interact != nil && id == f.interact.ID.String() {
			return f.interact, nil
		}
		return nil, port.ErrInteractionSessionNotFound
	})

	// The domain decides who owns the flow: only the cookie holding the pending secret resolves to it.
	suc.ResolveFlowSessionMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, partitionID int64, cookies map[string]string, flowID uuid.UUID) (*model.SSOSession, error) {
		if cookies[testFlowCookie] == "pending-secret" && flowID == f.pending.ID {
			return &f.pending, nil
		}
		if cookies[testFlowCookie] == "signed-in-secret" {
			active := f.pending
			active.State = model.SSOSessionActive
			return &active, nil
		}
		return nil, port.ErrSessionNotFound
	})
	return f
}

func (f *loginFixture) post(cookie string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set(model.HeaderContentType, model.ContentTypeFormUrlEncoded)
	req.Host = "test.com"
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: testFlowCookie, Value: cookie})
	}
	rec := httptest.NewRecorder()
	f.adapter.Router().ServeHTTP(rec, req)
	return rec
}

func (f *loginFixture) get(path, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "test.com"
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: testFlowCookie, Value: cookie})
	}
	rec := httptest.NewRecorder()
	f.adapter.Router().ServeHTTP(rec, req)
	return rec
}

func (f *loginFixture) credentials() url.Values {
	return url.Values{"username": {"testuser"}, "password": {"password123"}, "tx": {f.interact.ID.String()}}
}

// stubSignIn makes the credentials valid and records the promotion.
func (f *loginFixture) stubSignIn(created *port.CreatedSession) {
	f.lauc.AuthenticateLocalCredentialsMock.Set(func(ctx context.Context, cmd port.LocalLoginCommand) (*port.LocalLoginResponse, error) {
		return &port.LocalLoginResponse{UserProfileID: f.userID, PartitionID: cmd.PartitionID, Subject: f.userID.String()}, nil
	})
	f.sso.PromoteSessionMock.Set(func(ctx context.Context, cmd port.PromoteSessionCommand) (*port.CreatedSession, error) {
		f.promoted = &cmd
		return created, nil
	})
}

func TestLoginSubmit_TheBrowserThatStartedTheSignInCompletesIt(t *testing.T) {
	f := newLoginFixture(t)
	created := &port.CreatedSession{
		Session: model.SSOSession{ID: f.pending.ID, TenantID: f.tenant.ID, PartitionID: 1, State: model.SSOSessionActive, UserProfileID: f.userID},
		Cookie:  port.CookieIntentResponse{CookieName: testFlowCookie, CookieValue: "signed-in-secret", MaxAge: 86400, Secure: true},
	}
	f.stubSignIn(created)
	f.auth.ProcessAuthorizeRequestMock.Set(func(ctx context.Context, cmd port.AuthorizeRequestCommand) (*port.AuthorizeExecutionResult, error) {
		assert.Same(t, &created.Session, cmd.ActiveSession, "the promoted session completes the authorize request")
		assert.Empty(t, cmd.RequestURI)
		return &port.AuthorizeExecutionResult{Action: port.ActionEmitAuthorizationCode, RedirectURL: "https://callback?code=abc"}, nil
	})

	rec := f.post("pending-secret", f.credentials())

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "https://callback?code=abc", rec.Header().Get(model.HeaderHxRedirect))
	require.NotNil(t, f.promoted)
	assert.Equal(t, f.pending.ID, f.promoted.SessionID, "the pending session of the flow is the one promoted")
	assert.Equal(t, f.userID, f.promoted.UserProfileID)
	assert.Equal(t, f.provider.ID, f.promoted.IdentityProviderID)

	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == testFlowCookie {
			session = c
		}
	}
	require.NotNil(t, session)
	assert.Equal(t, "signed-in-secret", session.Value, "the secret is replaced at sign-in")
	assert.True(t, session.HttpOnly)
	assert.True(t, session.Secure)
	assert.Equal(t, 86400, session.MaxAge)
}

// The core of the change: a login form posted from another browser (a ?tx= taken from a URL sent to somebody) has
// no cookie that matches, so nothing is authenticated and nothing is promoted.
func TestLoginSubmit_ABrowserThatDidNotStartTheSignInIsRefused(t *testing.T) {
	for name, cookie := range map[string]string{
		"no cookie at all":                  "",
		"another browser's pending session": "someone-elses-secret",
		"an expired or deleted one":         "expired-secret",
	} {
		t.Run(name, func(t *testing.T) {
			f := newLoginFixture(t) // strict mocks: no credential check, no promotion, no authorize

			rec := f.post(cookie, f.credentials())

			require.Equal(t, http.StatusOK, rec.Code)
			assert.Contains(t, rec.Body.String(), "We could not verify this sign-in")
			assert.Empty(t, rec.Header().Get(model.HeaderHxRedirect))
			assert.Empty(t, rec.Result().Cookies(), "no session cookie is issued")
		})
	}
}

func TestLoginSubmit_AnAlreadySignedInBrowserDoesNotSignInAgain(t *testing.T) {
	f := newLoginFixture(t) // strict mocks: no credential check, no promotion

	rec := f.post("signed-in-secret", f.credentials())

	require.Equal(t, http.StatusOK, rec.Code)
	redirect := rec.Header().Get(model.HeaderHxRedirect)
	assert.True(t, strings.HasPrefix(redirect, "/oauth/authorize?client_id=client-abc"), "back to /authorize, where the existing session completes the request: %s", redirect)
}

func TestLoginSubmit_AnUnknownOrExpiredTxIsRefused(t *testing.T) {
	f := newLoginFixture(t)
	form := f.credentials()
	form.Set("tx", uuid.NewString())
	f.lauc.GetLoginContextMock.Set(func(ctx context.Context, cmd port.GetLoginContextCommand) (*port.LoginContextResponse, error) {
		return &port.LoginContextResponse{Providers: []model.IdentityProvider{f.provider}, ShowUsernamePasswordForm: true}, nil
	})

	rec := f.post("pending-secret", form)

	assert.Equal(t, http.StatusGone, rec.Code)
	assert.Contains(t, rec.Body.String(), "took too long")
}

func TestLoginSubmit_AFailedPasswordSignsNobodyIn(t *testing.T) {
	f := newLoginFixture(t) // strict: PromoteSession must not be called
	f.lauc.AuthenticateLocalCredentialsMock.Return(nil, port.ErrInvalidCredentials)

	rec := f.post("pending-secret", f.credentials())

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Invalid username or password")
	assert.Empty(t, rec.Result().Cookies())
}

func TestLoginSubmit_APromotionThatFailsIsReportedAndSignsNobodyIn(t *testing.T) {
	f := newLoginFixture(t)
	f.lauc.AuthenticateLocalCredentialsMock.Return(&port.LocalLoginResponse{UserProfileID: f.userID}, nil)
	f.sso.PromoteSessionMock.Return(nil, port.ErrSessionNotFound) // a double submit lost the race

	rec := f.post("pending-secret", f.credentials())

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Unable to sign you in right now")
	assert.Empty(t, rec.Header().Get(model.HeaderHxRedirect))
}

func TestLoginSubmit_MissingCredentialsAreReportedPerField(t *testing.T) {
	f := newLoginFixture(t)
	form := url.Values{"username": {""}, "password": {""}, "tx": {f.interact.ID.String()}}

	rec := f.post("pending-secret", form)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Username field identifier is required")
	assert.Contains(t, rec.Body.String(), "Password authorization parameter is required")
}

// ---- the login page ----

func TestLoginPage_TheBrowserThatStartedTheSignInSeesTheForm(t *testing.T) {
	f := newLoginFixture(t)

	rec := f.get("/login?tx="+f.interact.ID.String(), "pending-secret")

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Sign up first")
	assert.Contains(t, rec.Body.String(), f.interact.ID.String(), "the tx travels in the form")
}

func TestLoginPage_AnotherBrowserIsRefusedAndNoProviderIsListed(t *testing.T) {
	f := newLoginFixture(t) // strict: the login context (providers) is never loaded

	rec := f.get("/login?tx="+f.interact.ID.String(), "")

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "We could not verify this sign-in")
	assert.NotContains(t, rec.Body.String(), "Sign up first")
}

func TestLoginPage_AnExpiredTxShowsAClearMessage(t *testing.T) {
	f := newLoginFixture(t)

	rec := f.get("/login?tx="+uuid.NewString(), "pending-secret")

	assert.Equal(t, http.StatusGone, rec.Code)
	assert.Contains(t, rec.Body.String(), "took too long")
}

func TestLoginPage_ASignedInBrowserIsSentBackToTheRequest(t *testing.T) {
	f := newLoginFixture(t)

	rec := f.get("/login?tx="+f.interact.ID.String(), "signed-in-secret")

	require.Equal(t, http.StatusFound, rec.Code)
	assert.True(t, strings.HasPrefix(rec.Header().Get("Location"), "/oauth/authorize?client_id=client-abc"))
}

// ---- the login page opened directly (no /authorize, no tx) ----

func TestLoginPage_ADirectVisitStartsAPendingSessionOfItsOwn(t *testing.T) {
	f := newLoginFixture(t)
	f.interact = nil // nothing to bind to
	f.sso.ResolveDirectFlowSessionMock.Return(nil, port.ErrSessionNotFound)
	f.sso.StartFlowMock.Set(func(ctx context.Context, cmd port.StartFlowCommand) (*port.StartedFlow, error) {
		assert.Equal(t, int64(1), cmd.PartitionID, "the default partition of the tenant")
		return &port.StartedFlow{Session: f.pending, Cookie: &port.CookieIntentResponse{CookieName: testFlowCookie, CookieValue: "pending-secret", MaxAge: 900}}, nil
	})

	rec := f.get("/login", "")

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Sign up first")
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == testFlowCookie {
			cookie = c
		}
	}
	require.NotNil(t, cookie, "the browser gets the cookie of its pending session")
	assert.Equal(t, "pending-secret", cookie.Value)
}

func TestLoginPage_ADirectVisitOfASignedInBrowserGoesToTheLandingPage(t *testing.T) {
	f := newLoginFixture(t)
	f.interact = nil
	active := f.pending
	active.State = model.SSOSessionActive
	f.sso.ResolveDirectFlowSessionMock.Return(&active, nil)

	rec := f.get("/login", "signed-in-secret")

	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "https://test.com/home", rec.Header().Get("Location"))
}

func TestLoginSubmit_ADirectSubmitNeedsTheCookieOfAnExistingPendingSession(t *testing.T) {
	f := newLoginFixture(t) // strict: nothing is authenticated
	f.interact = nil
	f.sso.ResolveDirectFlowSessionMock.Return(nil, port.ErrSessionNotFound)

	rec := f.post("", url.Values{"username": {"testuser"}, "password": {"password123"}})

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "We could not verify this sign-in", "a submit never creates the session it is checked against")
}

func TestLoginSubmit_ADirectSignInPromotesItsPendingSessionAndGoesToTheLandingPage(t *testing.T) {
	f := newLoginFixture(t)
	f.interact = nil
	f.sso.ResolveDirectFlowSessionMock.Return(&f.pending, nil)
	f.stubSignIn(&port.CreatedSession{
		Session: model.SSOSession{ID: f.pending.ID, PartitionID: 1, State: model.SSOSessionActive},
		Cookie:  port.CookieIntentResponse{CookieName: testFlowCookie, CookieValue: "signed-in-secret", MaxAge: 86400},
	})

	rec := f.post("pending-secret", url.Values{"username": {"testuser"}, "password": {"password123"}})

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "https://test.com/home", rec.Header().Get(model.HeaderHxRedirect))
	assert.Equal(t, f.pending.ID, f.promoted.SessionID)
}

func TestLoginPage_AFederatedProviderIsStartedForTheBrowserThatOwnsTheFlow(t *testing.T) {
	f := newLoginFixture(t)
	federated := model.IdentityProvider{ID: uuid.New(), TenantID: f.tenant.ID, IDPType: model.OpenIDConnectIDPType, Enabled: true, Alias: "corp"}
	f.lauc.GetLoginContextMock.Set(func(ctx context.Context, cmd port.GetLoginContextCommand) (*port.LoginContextResponse, error) {
		return &port.LoginContextResponse{TriggerAutoFederatedIDP: &federated, InteractionSession: f.interact, TenantBaseURI: "https://test.com"}, nil
	})
	f.fuc.InitiateFederatedLoginMock.Set(func(ctx context.Context, cmd port.InitiateFederatedLoginCommand) (*port.InitiateFederatedLoginResponse, error) {
		assert.Equal(t, f.pending.ID, cmd.FlowSessionID, "the handshake is bound to the browser that owns the flow")
		assert.Equal(t, "https://callback", cmd.FinalTargetURI)
		assert.Equal(t, "client-abc", cmd.ClientID)
		return &port.InitiateFederatedLoginResponse{TargetRedirectURL: "https://upstream/authorize?x=1"}, nil
	})

	rec := f.get("/login?tx="+f.interact.ID.String(), "pending-secret")

	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "https://upstream/authorize?x=1", rec.Header().Get("Location"))
}

func TestLoginPage_AFederatedProviderIsNotStartedForAnotherBrowser(t *testing.T) {
	f := newLoginFixture(t) // strict federated use case: nothing is initiated
	federated := model.IdentityProvider{ID: uuid.New(), IDPType: model.OpenIDConnectIDPType, Enabled: true, Alias: "corp"}
	f.lauc.GetLoginContextMock.Set(func(ctx context.Context, cmd port.GetLoginContextCommand) (*port.LoginContextResponse, error) {
		return &port.LoginContextResponse{TriggerAutoFederatedIDP: &federated, InteractionSession: f.interact}, nil
	})

	rec := f.get("/login?tx="+f.interact.ID.String(), "another-browser")

	assert.Equal(t, http.StatusForbidden, rec.Code)
}
