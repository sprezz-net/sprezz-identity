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

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signupFixture is a sign-up that was reached from a sign-in started at /authorize.
type signupFixture struct {
	adapter    *HttpAdapter
	tenant     *model.Tenant
	provider   model.IdentityProvider
	pending    model.SSOSession
	interact   *model.InteractionSession
	promoted   *port.PromoteSessionCommand
	userID     uuid.UUID
	noProvider bool
	serve      func(req *http.Request) *httptest.ResponseRecorder
	register   func(cmd port.RegisterUserCommand)
}

func newSignupFixture(t *testing.T) *signupFixture {
	t.Helper()
	ctrl := minimock.NewController(t)
	adapter, _, _, _, tuc, _, suc, _, uruc := setupTestEnv(ctrl)

	tenantID := uuid.New()
	part := int64(5)
	f := &signupFixture{
		adapter:  adapter,
		tenant:   &model.Tenant{ID: tenantID, Domain: "test.com", DefaultPartition: &part, IsActive: true, Config: model.TenantConfig{DefaultRedirectURI: "https://test.com/home"}},
		provider: model.IdentityProvider{ID: uuid.New(), TenantID: tenantID, IDPType: model.UsernamePasswordIDPType, Enabled: true, PartitionID: 5},
		pending:  model.SSOSession{ID: uuid.New(), TenantID: tenantID, PartitionID: 5, State: model.SSOSessionPending},
		userID:   uuid.New(),
	}
	f.interact = &model.InteractionSession{ID: uuid.New(), TenantID: tenantID, PartitionID: 5, ClientID: "client-abc", RedirectURI: "https://cb", State: "st", SessionID: f.pending.ID}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) { return f.tenant, nil })
	uruc.GetSignupContextMock.Optional().Set(func(ctx context.Context, cmd port.GetSignupContextCommand) (*port.SignupContextResponse, error) {
		resp := &port.SignupContextResponse{Provider: &f.provider}
		if f.noProvider {
			resp.Provider = nil
		}
		if cmd.InteractionID == f.interact.ID.String() {
			resp.InteractionSession = f.interact
		}
		return resp, nil
	})
	suc.ResolveFlowSessionMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, partitionID int64, cookies map[string]string, flowID uuid.UUID) (*model.SSOSession, error) {
		switch cookies[testFlowCookie] {
		case "pending-secret":
			if flowID == f.pending.ID {
				return &f.pending, nil
			}
		case "signed-in-secret":
			active := f.pending
			active.State = model.SSOSessionActive
			return &active, nil
		}
		return nil, port.ErrSessionNotFound
	})
	suc.PromoteSessionMock.Optional().Set(func(ctx context.Context, cmd port.PromoteSessionCommand) (*port.CreatedSession, error) {
		f.promoted = &cmd
		return &port.CreatedSession{
			Session: model.SSOSession{ID: cmd.SessionID, PartitionID: cmd.PartitionID, State: model.SSOSessionActive, UserProfileID: cmd.UserProfileID},
			Cookie:  port.CookieIntentResponse{CookieName: testFlowCookie, CookieValue: "signed-in-secret", MaxAge: 86400, Secure: true},
		}, nil
	})
	uruc.RegisterUserMock.Optional().Set(func(ctx context.Context, cmd port.RegisterUserCommand) (*model.UserProfile, error) {
		if f.register != nil {
			f.register(cmd)
		}
		return &model.UserProfile{ID: f.userID}, nil
	})
	f.serve = func(req *http.Request) *httptest.ResponseRecorder {
		req.Host = "test.com"
		rec := httptest.NewRecorder()
		f.adapter.Router().ServeHTTP(rec, req)
		return rec
	}
	return f
}

func (f *signupFixture) form(extra url.Values) url.Values {
	v := url.Values{"name": {"Alice Doe"}, "username": {"alice"}, "email": {"alice@example.com"}, "password": {"s3cret-pass"}, "confirm_password": {"s3cret-pass"}, "tx": {f.interact.ID.String()}}
	for k, vals := range extra {
		v[k] = vals
	}
	return v
}

func (f *signupFixture) post(cookie string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, port.RouteWebSignUp, strings.NewReader(form.Encode()))
	req.Header.Set(model.HeaderContentType, model.ContentTypeFormUrlEncoded)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: testFlowCookie, Value: cookie})
	}
	return f.serve(req)
}

func (f *signupFixture) get(path, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: testFlowCookie, Value: cookie})
	}
	return f.serve(req)
}

func TestSignUpForm_TheBrowserThatStartedTheSignInSeesTheForm(t *testing.T) {
	f := newSignupFixture(t)

	rec := f.get(port.RouteWebSignUp+"?tx="+f.interact.ID.String(), "pending-secret")

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), f.interact.ID.String(), "the form carries the tx")
}

func TestSignUpForm_AnotherBrowserIsRefused(t *testing.T) {
	f := newSignupFixture(t)

	rec := f.get(port.RouteWebSignUp+"?tx="+f.interact.ID.String(), "")

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "We could not verify this sign-in")
}

func TestSignUpForm_ATenantWithoutSelfServiceSignupIsForbidden(t *testing.T) {
	f := newSignupFixture(t)
	f.noProvider = true

	rec := f.get(port.RouteWebSignUp, "")

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "Self-service signup is not configured")
}

func TestSignUpForm_AnExpiredTxIsRefused(t *testing.T) {
	f := newSignupFixture(t)

	rec := f.get(port.RouteWebSignUp+"?tx="+uuid.NewString(), "pending-secret")

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestSignUpForm_ASignedInBrowserIsSentBackToTheRequest(t *testing.T) {
	f := newSignupFixture(t)

	rec := f.get(port.RouteWebSignUp+"?tx="+f.interact.ID.String(), "signed-in-secret")

	require.Equal(t, http.StatusFound, rec.Code)
	assert.True(t, strings.HasPrefix(rec.Header().Get("Location"), "/oauth/authorize?client_id=client-abc"))
}

func TestSignUpSubmit_TheBrowserThatStartedTheSignInRegistersAndIsSignedIn(t *testing.T) {
	f := newSignupFixture(t)
	f.register = func(cmd port.RegisterUserCommand) {
		assert.Equal(t, "alice", cmd.Username)
		assert.Equal(t, f.provider.ID, cmd.ProviderID)
	}

	rec := f.post("pending-secret", f.form(nil))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, f.promoted)
	assert.Equal(t, f.pending.ID, f.promoted.SessionID, "the pending session of this flow is promoted")
	assert.Equal(t, f.userID, f.promoted.UserProfileID)
	assert.Equal(t, int64(5), f.promoted.PartitionID)
	assert.NotEmpty(t, rec.Header().Get(model.HeaderHxRedirect))
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == testFlowCookie {
			cookie = c
		}
	}
	require.NotNil(t, cookie)
	assert.Equal(t, "signed-in-secret", cookie.Value)
	assert.True(t, cookie.HttpOnly)
}

func TestSignUpSubmit_ABrowserThatDidNotStartTheSignInRegistersNobody(t *testing.T) {
	for name, cookie := range map[string]string{"no cookie": "", "another browser": "someone-elses"} {
		t.Run(name, func(t *testing.T) {
			f := newSignupFixture(t)
			f.register = func(port.RegisterUserCommand) {
				t.Error("no account may be created for a browser that does not own the sign-in")
			}

			rec := f.post(cookie, f.form(nil))

			require.Equal(t, http.StatusOK, rec.Code)
			assert.Contains(t, rec.Body.String(), "We could not verify this sign-in")
			assert.Nil(t, f.promoted)
		})
	}
}

func TestSignUpSubmit_AnAlreadySignedInBrowserRegistersNobody(t *testing.T) {
	f := newSignupFixture(t)
	f.register = func(port.RegisterUserCommand) { t.Error("a signed-in browser does not register again") }

	rec := f.post("signed-in-secret", f.form(nil))

	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, strings.HasPrefix(rec.Header().Get(model.HeaderHxRedirect), "/oauth/authorize?client_id=client-abc"))
	assert.Nil(t, f.promoted)
}

func TestSignUpSubmit_MismatchedPasswordsRegisterNobody(t *testing.T) {
	f := newSignupFixture(t)
	f.register = func(port.RegisterUserCommand) { t.Error("mismatched passwords must not register") }

	rec := f.post("pending-secret", f.form(url.Values{"confirm_password": {"different"}}))

	assert.Contains(t, rec.Body.String(), "Passwords provided do not match")
	assert.Nil(t, f.promoted)
}
