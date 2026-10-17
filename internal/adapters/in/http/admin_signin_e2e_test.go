package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"sprezz-identity/internal/adapters/out/memory"
	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"
	"sprezz-identity/internal/domain/service"

	"github.com/gojuno/minimock/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	e2eTenantHost   = "tenant.example.com"
	e2eAdminHost    = "admin.example.com"
	e2eUpstreamAuth = "https://admin.example.com/oauth/authorize"
)

// adminSignInWorld wires the real services over the in-memory store: a tenant created the way the platform creates
// every tenant (with its fixed sprezz_admin partition and its admin-sso provider), the real federation, admin logon
// and session services, and the real HTTP adapter. Only the upstream (the admin tenant acting as the identity
// provider) is stubbed, because it is another server.
type adminSignInWorld struct {
	t         *testing.T
	storage   *memory.Storage
	sso       *service.SSOSessionService
	handler   http.Handler
	tenant    *model.Tenant
	adminPart *model.Partition
	clock     *portmock.MockClock
}

func newAdminSignInWorld(t *testing.T) *adminSignInWorld {
	t.Helper()
	ctrl := minimock.NewController(t)
	ctx := context.Background()

	storage := memory.NewStorage("production")
	clock := portmock.NewMockClock(time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC))

	crypto := portmock.NewCryptoMock(ctrl)
	crypto.VerifyExternalTokenWithProviderMock.Optional().Set(func(_ context.Context, token, _, _ string) (map[string]any, error) {
		return map[string]any{"sub": "upstream-admin-1", "email": "admin@example.com", "email_verified": true, "name": "Admin"}, nil
	})

	fedClient := portmock.NewFederationClientMock(ctrl)
	fedClient.FetchOIDCDiscoveryMetadataMock.Optional().Return(&model.OIDCDiscoveryMetadata{
		Issuer: "https://" + e2eAdminHost, AuthorizationEndpoint: e2eUpstreamAuth, TokenEndpoint: "https://admin.example.com/oauth/token",
		JwksURI: "https://admin.example.com/.well-known/jwks.json",
	}, nil)
	fedClient.ExchangeAuthorizationCodeMock.Optional().Return(&port.UpstreamTokenSet{AccessToken: "at", IDToken: "idt", ExpiresIn: 900}, nil)

	idpService := service.NewIdentityProviderService(storage, storage, crypto, clock, fedClient)
	tenantService := service.NewTenantService(storage, storage, clock, idpService, "production", e2eAdminHost)

	tenant, err := tenantService.CreateTenant(ctx, port.CreateTenantCommand{TenantName: "Customer", DomainName: e2eTenantHost})
	require.NoError(t, err)
	adminPart, err := storage.GetPartitionByAlias(ctx, tenant.ID, model.AdminPartitionAliasName)
	require.NoError(t, err, "every tenant gets the fixed administrative partition")

	// The client of the admin-sso provider is registered on first use (DCR); here it is provisioned already.
	providers, err := storage.GetIdentityProviders(ctx, tenant.ID)
	require.NoError(t, err)
	for _, p := range providers {
		if p.Alias == "admin-sso" {
			p.Config.ClientID = "admin_ui"
			require.NoError(t, storage.CreateIdentityProvider(ctx, tenant.ID, p))
		}
	}

	validator := service.NewOAuthValidatorService(idpService)
	federation := service.NewFederationService(storage, fedClient, crypto, clock, idpService, validator)
	adminLogon := service.NewAdminLogonService(storage, storage, nil, crypto, fedClient, federation, clock, "production", e2eAdminHost)
	sso := service.NewSSOSessionService(storage, clock, "production", service.SSOSessionPolicy{})

	adapter := NewHttpAdapter(tenantService, portmock.NewAuthUseCaseMock(ctrl), federation, adminLogon, sso,
		portmock.NewUserProfileUseCaseMock(ctrl), portmock.NewUserRegistrationUseCaseMock(ctrl), portmock.NewLocalAuthUseCaseMock(ctrl),
		nil, storage, nil, storage, crypto, "production", e2eAdminHost)

	return &adminSignInWorld{t: t, storage: storage, sso: sso, handler: adapter.Router(), tenant: tenant, adminPart: adminPart, clock: clock}
}

// browser is a cookie jar that talks to the tenant host.
type browser struct {
	w       *adminSignInWorld
	cookies map[string]string
}

func (w *adminSignInWorld) newBrowser() *browser {
	return &browser{w: w, cookies: map[string]string{}}
}

func (b *browser) get(path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = e2eTenantHost
	for name, value := range b.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	rec := httptest.NewRecorder()
	b.w.handler.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
	return rec
}

// startAdminSignIn opens the console, which starts the sign-in, and returns the state sent to the upstream.
func (b *browser) startAdminSignIn() string {
	b.w.t.Helper()
	rec := b.get("/admin")
	require.Equal(b.w.t, http.StatusFound, rec.Code, rec.Body.String())
	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(b.w.t, err)
	require.Equal(b.w.t, e2eUpstreamAuth, location.Scheme+"://"+location.Host+location.Path, "the browser is sent to the upstream identity provider")
	state := location.Query().Get("state")
	require.NotEmpty(b.w.t, state)
	return state
}

func (b *browser) adminCookieName() string {
	return "__Host-spz_session_" + model.AdminPartitionAliasName
}

func TestAdminSignIn_TheDashboardSignsInThroughTheSharedFederationFlow(t *testing.T) {
	w := newAdminSignInWorld(t)
	browserA := w.newBrowser()

	// 1. Opening the console starts a sign-in: a pending session in the administrative partition.
	state := browserA.startAdminSignIn()
	pendingSecret := browserA.cookies[browserA.adminCookieName()]
	require.NotEmpty(t, pendingSecret, "the cookie is named after the fixed administrative partition")
	_, err := w.sso.ResolveSession(context.Background(), w.tenant.ID, pendingSecret)
	require.ErrorIs(t, err, port.ErrSessionNotFound, "a sign-in in progress authenticates nothing")
	assert.Equal(t, http.StatusFound, browserA.get("/admin").Code, "the console is still locked")

	// 2. The upstream sends the browser back to the same callback every upstream identity provider uses.
	rec := browserA.get(port.RouteFederationCallback + "?state=" + url.QueryEscape(state) + "&code=upstream-code")
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	assert.Equal(t, "https://"+e2eTenantHost+port.RouteAdmin, rec.Header().Get("Location"))

	// 3. The session was promoted, into the administrative partition, under a fresh secret.
	signedInSecret := browserA.cookies[browserA.adminCookieName()]
	require.NotEmpty(t, signedInSecret)
	assert.NotEqual(t, pendingSecret, signedInSecret, "the secret of the flow is replaced at sign-in")
	session, err := w.sso.ResolveSession(context.Background(), w.tenant.ID, signedInSecret)
	require.NoError(t, err)
	assert.Equal(t, w.adminPart.ID, session.PartitionID, "the session lives in the sprezz_admin partition")
	assert.Equal(t, model.SSOSessionActive, session.State)

	// 4. The console accepts it.
	assert.Equal(t, http.StatusOK, browserA.get("/admin").Code, "the guard of the console accepts the promoted session")

	// 5. The cookie the flow ran under no longer opens anything.
	older := w.newBrowser()
	older.cookies[older.adminCookieName()] = pendingSecret
	assert.Equal(t, http.StatusFound, older.get("/admin").Code, "the old pending cookie does not open the console")
}

// The attack the binding closes: the callback URL of somebody's sign-in opened in another browser.
func TestAdminSignIn_ACallbackOpenedInAnotherBrowserSignsNobodyIn(t *testing.T) {
	w := newAdminSignInWorld(t)
	attacker := w.newBrowser()
	state := attacker.startAdminSignIn()
	callback := port.RouteFederationCallback + "?state=" + url.QueryEscape(state) + "&code=attackers-code"

	for name, victim := range map[string]*browser{"a browser with no cookies": w.newBrowser(), "a browser with its own pending sign-in": func() *browser {
		b := w.newBrowser()
		b.startAdminSignIn()
		return b
	}()} {
		t.Run(name, func(t *testing.T) {
			before := victim.cookies[victim.adminCookieName()]

			rec := victim.get(callback)

			require.Equal(t, http.StatusForbidden, rec.Code)
			assert.Equal(t, before, victim.cookies[victim.adminCookieName()], "the victim is not given a session")
			assert.Equal(t, http.StatusFound, victim.get("/admin").Code, "the victim is not signed in")
		})
	}

	// The refused attempts did not consume the state: the browser that started the sign-in can still finish it.
	rec := attacker.get(callback)
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	assert.Equal(t, http.StatusOK, attacker.get("/admin").Code)
}

func TestAdminSignIn_ACallbackCanOnlyBeUsedOnce(t *testing.T) {
	w := newAdminSignInWorld(t)
	b := w.newBrowser()
	state := b.startAdminSignIn()
	callback := port.RouteFederationCallback + "?state=" + url.QueryEscape(state) + "&code=c"
	staleCookie := b.cookies[b.adminCookieName()]
	require.Equal(t, http.StatusFound, b.get(callback).Code)

	replay := w.newBrowser()
	replay.cookies[replay.adminCookieName()] = staleCookie // the cookie of the flow, replayed

	assert.Equal(t, http.StatusForbidden, replay.get(callback).Code, "a replayed callback signs in nobody")
}

// The admin-sso provider is created in the administrative partition by CreateTenant. The console depends on it.
func TestAdminSignIn_TheAdminSSOProviderOfEveryTenantLivesInTheAdministrativePartition(t *testing.T) {
	w := newAdminSignInWorld(t)

	providers, err := w.storage.GetIdentityProviders(context.Background(), w.tenant.ID)
	require.NoError(t, err)
	var found bool
	for _, p := range providers {
		if p.Alias == "admin-sso" {
			found = true
			assert.Equal(t, w.adminPart.ID, p.PartitionID)
			assert.True(t, p.IsSystem)
		}
	}
	require.True(t, found)
}

// Opening the console again while the first sign-in is at the identity provider (a refresh, a second tab) must not
// strand it: the guard may not evict the pending cookie, and the same pending session serves both.
func TestAdminSignIn_ASecondVisitWhileSigningInKeepsTheSignInAlive(t *testing.T) {
	w := newAdminSignInWorld(t)
	b := w.newBrowser()
	firstState := b.startAdminSignIn()
	pending := b.cookies[b.adminCookieName()]

	secondState := b.startAdminSignIn() // the second tab

	assert.Equal(t, pending, b.cookies[b.adminCookieName()], "the pending cookie is kept, not evicted or replaced")
	assert.NotEqual(t, firstState, secondState, "each visit has its own state")

	// Either tab can complete its sign-in, and the browser ends up signed in.
	rec := b.get(port.RouteFederationCallback + "?state=" + url.QueryEscape(firstState) + "&code=c")
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	assert.Equal(t, http.StatusOK, b.get("/admin").Code)
}

// A session that has expired is evicted and replaced by a fresh sign-in, not kept.
func TestAdminSignIn_AnExpiredPendingSessionIsReplacedByAFreshOne(t *testing.T) {
	w := newAdminSignInWorld(t)
	b := w.newBrowser()
	b.startAdminSignIn()
	dead := b.cookies[b.adminCookieName()]
	w.clock.Advance(16 * time.Minute)

	b.startAdminSignIn()

	assert.NotEqual(t, dead, b.cookies[b.adminCookieName()], "a dead pending session is replaced")
}
