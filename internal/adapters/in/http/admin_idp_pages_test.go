package http

import (
	"context"
	"net/http"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const idpSecret = "super-secret-value-123"

func testIDP() model.IdentityProvider {
	return model.IdentityProvider{
		ID: uuid.New(), Name: "Corp SSO", Alias: "corp-sso", IDPType: model.OpenIDConnectIDPType, Enabled: true, PartitionID: 1,
		Issuer: "https://idp.example.com",
		Config: model.IdentityProviderConfig{
			DiscoveryEndpoint: "https://idp.example.com/.well-known/openid-configuration",
			ClientID:          "sprezz", ClientSecret: idpSecret, AuthenticationMethod: "client_secret_basic",
			Scopes: []string{"openid", "email"}, AAL: 1, IAL: 1, DomainAliases: []string{"example.com"},
			DiscoveryResult: `{"issuer":"https://idp.example.com","authorization_endpoint":"https://idp.example.com/auth","token_endpoint":"https://idp.example.com/token","code_challenge_methods_supported":["S256"]}`,
		},
	}
}

func (f *pagesFixture) stubIDPPage(p model.IdentityProvider, usage model.IdentityProviderUsage) {
	usage.ProviderID = p.ID
	f.idps.GetIdentityProviderMock.Optional().Set(func(ctx context.Context, tID, id uuid.UUID) (*model.IdentityProvider, error) {
		if id != p.ID {
			return nil, port.ErrIdentityProviderNotFound
		}
		clone := p
		return &clone, nil
	})
	f.idps.GetIdentityProviderUsageMock.Optional().Return(map[uuid.UUID]model.IdentityProviderUsage{p.ID: usage}, nil)
	f.idps.GetIdentityProvidersMock.Optional().Return([]model.IdentityProvider{p}, nil)
	f.storage.GetPartitionsMock.Optional().Return([]model.Partition{{ID: 1, Name: "default", AliasName: "main"}}, nil)
}

func TestIDPDetail_RendersCardsAndNeverTheSecret(t *testing.T) {
	f := newPagesFixture(t)
	p := testIDP()
	f.stubIDPPage(p, model.IdentityProviderUsage{LinkedUsers: 4})
	path := "/admin/idps/" + p.ID.String()

	full := f.do(http.MethodGet, path, nil, nil)
	require.Equal(t, http.StatusOK, full.Code)
	body := full.Body.String()
	assert.Contains(t, body, "<html")
	for _, section := range []string{"general", "connection", "credentials", "behavior", "assurance"} {
		assert.Contains(t, body, `hx-put="`+path+`/`+section+`"`)
	}
	assert.NotContains(t, body, idpSecret, "the stored secret is never sent to the browser")
	assert.Contains(t, body, "A secret is stored")
	assert.Contains(t, body, "https://idp.example.com/auth", "the discovery summary is rendered on the server")

	fragment := f.do(http.MethodGet, path, nil, htmx())
	assert.NotContains(t, fragment.Body.String(), "<html")
	assert.NotContains(t, fragment.Body.String(), idpSecret)
}

func TestIDPDetail_LocalProviderShowsPolicyCard(t *testing.T) {
	f := newPagesFixture(t)
	p := model.IdentityProvider{ID: uuid.New(), Name: "Local", Alias: "username-password", IDPType: model.UsernamePasswordIDPType, Enabled: true, PartitionID: 1,
		Config: model.IdentityProviderConfig{UsernameField: "email", MaxFailedVerificationCount: 5, PasswordBlockedTime: 900, AAL: 1, IAL: 1}}
	f.stubIDPPage(p, model.IdentityProviderUsage{})

	body := f.do(http.MethodGet, "/admin/idps/"+p.ID.String(), nil, nil).Body.String()
	assert.Contains(t, body, `id="section-local-policy"`)
	assert.NotContains(t, body, `id="section-connection"`)
}

func TestIDPDetail_SystemProviderIsReadOnlyWithoutDeletion(t *testing.T) {
	f := newPagesFixture(t)
	p := testIDP()
	p.IsSystem = true
	f.stubIDPPage(p, model.IdentityProviderUsage{})

	body := f.do(http.MethodGet, "/admin/idps/"+p.ID.String(), nil, nil).Body.String()
	assert.Contains(t, body, "Managed by Sprezz")
	assert.NotContains(t, body, "Danger zone")
	assert.Contains(t, body, "<fieldset disabled", "every card is locked")
}

func TestIDPDetail_UnknownOrMalformedID(t *testing.T) {
	f := newPagesFixture(t)
	f.idps.GetIdentityProviderMock.Optional().Return(nil, port.ErrIdentityProviderNotFound)

	assert.Equal(t, http.StatusNotFound, f.do(http.MethodGet, "/admin/idps/not-a-uuid", nil, nil).Code)
	assert.Equal(t, http.StatusNotFound, f.do(http.MethodGet, "/admin/idps/"+uuid.NewString(), nil, nil).Code)
}

func TestIDPList_ShowsUsageAndFilters(t *testing.T) {
	f := newPagesFixture(t)
	sso := testIDP()
	local := model.IdentityProvider{ID: uuid.New(), Name: "Local", Alias: "username-password", IDPType: model.UsernamePasswordIDPType, Enabled: false, PartitionID: 1}
	last := time.Now()
	f.idps.GetIdentityProvidersMock.Optional().Return([]model.IdentityProvider{sso, local}, nil)
	f.idps.GetIdentityProviderUsageMock.Optional().Return(map[uuid.UUID]model.IdentityProviderUsage{
		sso.ID: {ProviderID: sso.ID, LinkedUsers: 7, GroupNames: []string{"staff"}, LastLoginAt: &last},
	}, nil)
	f.storage.GetPartitionsMock.Optional().Return([]model.Partition{{ID: 1, Name: "default", AliasName: "main"}}, nil)

	all := f.do(http.MethodGet, "/admin/idps", nil, htmx()).Body.String()
	assert.Contains(t, all, "Corp SSO")
	assert.Contains(t, all, "Local")
	assert.Contains(t, all, `href="/admin/idps/`+sso.ID.String()+`"`, "rows link to routed pages, not modals")

	assert.NotContains(t, f.do(http.MethodGet, "/admin/idps?type=oidc", nil, htmx()).Body.String(), ">Local<")
	assert.NotContains(t, f.do(http.MethodGet, "/admin/idps?status=active", nil, htmx()).Body.String(), ">Local<")
	assert.NotContains(t, f.do(http.MethodGet, "/admin/idps?q=corp", nil, htmx()).Body.String(), ">Local<")
	assert.Contains(t, f.do(http.MethodGet, "/admin/idps?q=nomatch", nil, htmx()).Body.String(), "No identity providers found")
}
