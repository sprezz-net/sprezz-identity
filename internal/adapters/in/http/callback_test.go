package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type callbackFixture struct {
	adapter  *HttpAdapter
	fuc      *portmock.FederatedLoginUseCaseMock
	sso      *portmock.SSOSessionUseCaseMock
	tenantID uuid.UUID
	flowID   uuid.UUID
	userID   uuid.UUID
	gotCmd   *port.FederatedCallbackCommand
	promoted *port.PromoteSessionCommand
}

func newCallbackFixture(t *testing.T) *callbackFixture {
	t.Helper()
	ctrl := minimock.NewController(t)
	adapter, _, _, _, tuc, fuc, suc, _, _ := setupTestEnv(ctrl)
	f := &callbackFixture{adapter: adapter, fuc: fuc, sso: suc, tenantID: uuid.New(), flowID: uuid.New(), userID: uuid.New()}

	tuc.ResolveTenantContextMock.Set(func(ctx context.Context, host string) (*model.Tenant, error) {
		return &model.Tenant{ID: f.tenantID, Domain: "test.com", IsActive: true}, nil
	})

	// The domain finds the pending sessions behind the cookies of the request; only "pending-secret" is one.
	suc.ResolveFlowSessionIDsMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, cookies map[string]string) ([]uuid.UUID, error) {
		for _, v := range cookies {
			if v == "pending-secret" {
				return []uuid.UUID{f.flowID}, nil
			}
		}
		return []uuid.UUID{}, nil
	})
	// The storage only redeems the state for the session that started the handshake.
	fuc.ExecuteFederatedCallbackMock.Optional().Set(func(ctx context.Context, cmd port.FederatedCallbackCommand) (*port.FederatedCallbackResponse, error) {
		f.gotCmd = &cmd
		for _, id := range cmd.FlowSessionIDs {
			if id == f.flowID {
				return &port.FederatedCallbackResponse{
					UserProfileID: f.userID, PartitionID: 123, TargetLandingURI: "https://test.com/dashboard",
					FlowSessionID: f.flowID, IdentityProviderID: uuid.New(),
				}, nil
			}
		}
		return nil, port.ErrSessionNotFound
	})
	suc.PromoteSessionMock.Optional().Set(func(ctx context.Context, cmd port.PromoteSessionCommand) (*port.CreatedSession, error) {
		f.promoted = &cmd
		return &port.CreatedSession{
			Session: model.SSOSession{ID: cmd.SessionID, PartitionID: cmd.PartitionID, State: model.SSOSessionActive, UserProfileID: cmd.UserProfileID},
			Cookie:  port.CookieIntentResponse{CookieName: "spz_session", CookieValue: "opaque-secret", MaxAge: 86400, Secure: true},
		}, nil
	})
	return f
}

func (f *callbackFixture) call(query, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, port.RouteFederationCallback+query, nil)
	req.Host = "test.com"
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "spz_session_default", Value: cookie})
	}
	rec := httptest.NewRecorder()
	f.adapter.Router().ServeHTTP(rec, req)
	return rec
}

func TestFederationCallback_TheBrowserThatStartedTheSignInCompletesIt(t *testing.T) {
	f := newCallbackFixture(t)

	rec := f.call("?state=mock-state&code=mock-code", "pending-secret")

	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	assert.Equal(t, "https://test.com/dashboard", rec.Header().Get("Location"))
	require.NotNil(t, f.gotCmd)
	assert.Equal(t, "mock-state", f.gotCmd.IncomingState)
	assert.Equal(t, "mock-code", f.gotCmd.IncomingCode)
	assert.Equal(t, []uuid.UUID{f.flowID}, f.gotCmd.FlowSessionIDs, "the state is offered the sessions behind this browser's cookies")

	require.NotNil(t, f.promoted)
	assert.Equal(t, f.flowID, f.promoted.SessionID, "the pending session is promoted, keeping its ID")
	assert.Equal(t, f.userID, f.promoted.UserProfileID)
	assert.Equal(t, int64(123), f.promoted.PartitionID)

	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "spz_session" {
			session = c
		}
	}
	require.NotNil(t, session)
	assert.Equal(t, "opaque-secret", session.Value)
	assert.True(t, session.HttpOnly)
}

// The attack this closes: the callback URL of somebody else's sign-in, opened in the victim's browser.
func TestFederationCallback_ABrowserThatDidNotStartTheSignInIsRefused(t *testing.T) {
	for name, cookie := range map[string]string{"no cookie": "", "another browser's cookie": "victim-session"} {
		t.Run(name, func(t *testing.T) {
			f := newCallbackFixture(t)

			rec := f.call("?state=attackers-state&code=attackers-code", cookie)

			require.Equal(t, http.StatusForbidden, rec.Code)
			assert.Nil(t, f.promoted, "nobody is signed in")
			assert.Empty(t, rec.Result().Cookies(), "no session cookie is issued")
			assert.Empty(t, f.gotCmd.FlowSessionIDs, "the state was offered no session to redeem for")
		})
	}
}

func TestFederationCallback_AFailureDoesNotLeakTheReason(t *testing.T) {
	f := newCallbackFixture(t)
	f.fuc.ExecuteFederatedCallbackMock.Set(func(ctx context.Context, cmd port.FederatedCallbackCommand) (*port.FederatedCallbackResponse, error) {
		return nil, errors.New("upstream token exchange failed: connection refused to 10.0.0.5")
	})

	rec := f.call("?state=s&code=c", "pending-secret")

	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.NotContains(t, rec.Body.String(), "10.0.0.5")
	assert.Contains(t, rec.Body.String(), "please start again")
	assert.Nil(t, f.promoted)
}

func TestFederationCallback_APromotionThatFailsSignsNobodyIn(t *testing.T) {
	f := newCallbackFixture(t)
	f.sso.PromoteSessionMock.Set(func(ctx context.Context, cmd port.PromoteSessionCommand) (*port.CreatedSession, error) {
		return nil, port.ErrSessionNotFound // the sign-in expired while the user was at the upstream provider
	})

	rec := f.call("?state=s&code=c", "pending-secret")

	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, rec.Result().Cookies())
}

func TestFederationCallback_MissingStateOrCodeIsABadRequest(t *testing.T) {
	for _, query := range []string{"", "?state=only", "?code=only"} {
		f := newCallbackFixture(t)

		rec := f.call(query, "pending-secret")

		assert.Equal(t, http.StatusBadRequest, rec.Code, query)
		assert.Nil(t, f.gotCmd, "nothing is redeemed without both parameters")
	}
}

func TestFederationCallback_ACookieLookupThatFailsRefusesTheCallback(t *testing.T) {
	f := newCallbackFixture(t)
	f.sso.ResolveFlowSessionIDsMock.Set(func(ctx context.Context, tID uuid.UUID, cookies map[string]string) ([]uuid.UUID, error) {
		return nil, port.ErrTenantInactive
	})

	rec := f.call("?state=s&code=c", "pending-secret")

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Nil(t, f.gotCmd)
}
