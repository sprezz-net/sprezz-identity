package http

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testProfile() model.ApplicationProfile {
	return model.ApplicationProfile{
		ID:                      uuid.New(),
		ProfileName:             "web",
		IsEnabled:               true,
		TokenEndpointAuthMethod: model.AuthMethodClientSecretPost,
		SigningAlgorithm:        model.AlgRS256,
		GrantTypes:              []model.GrantType{model.GrantTypeAuthorizationCode},
		AccessTokenLifetime:     15 * time.Minute,
		IDTokenLifetime:         15 * time.Minute,
		RefreshTokenLifetime:    24 * time.Hour,
	}
}

func (f *pagesFixture) stubProfilePage(p model.ApplicationProfile, used []model.ApplicationSummary) {
	f.apps.GetProfileMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, id uuid.UUID) (*model.ApplicationProfile, error) {
		clone := p
		return &clone, nil
	})
	f.apps.ListApplicationsByProfileMock.Optional().Set(func(ctx context.Context, tID uuid.UUID, id uuid.UUID) ([]model.ApplicationSummary, error) {
		return used, nil
	})
}

func TestProfileDetail_ShowsCardsAndUsage(t *testing.T) {
	f := newPagesFixture(t)
	p := testProfile()
	f.stubProfilePage(p, []model.ApplicationSummary{{ClientID: "shop", ApplicationName: "Shop"}})

	body := f.do(http.MethodGet, "/admin/applications/profiles/"+p.ID.String(), nil, nil).Body.String()

	for _, section := range []string{"section-general", "section-authentication", "section-lifetimes"} {
		assert.Contains(t, body, `id="`+section+`"`)
	}
	assert.Contains(t, body, "Shop")
	assert.Contains(t, body, "used by 1 application(s)", "a profile in use cannot be deleted and says why")
	assert.NotContains(t, body, `hx-delete=`)
}

func TestProfileSection_LifetimesReadSecondsAndSaveOnlyThatSection(t *testing.T) {
	f := newPagesFixture(t)
	p := testProfile()
	f.stubProfilePage(p, nil)

	var got port.PatchProfileCommand
	f.apps.PatchProfileMock.Set(func(ctx context.Context, cmd port.PatchProfileCommand) error {
		got = cmd
		return nil
	})

	rec := f.do(http.MethodPut, "/admin/applications/profiles/"+p.ID.String()+"/lifetimes", url.Values{
		"access_token_lifetime":  {"300"},
		"id_token_lifetime":      {"600"},
		"refresh_token_lifetime": {"172800"},
	}, htmx())

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, port.ProfileSectionLifetimes, got.Section)
	assert.Equal(t, 5*time.Minute, got.AccessTokenLifetime)
	assert.Equal(t, 10*time.Minute, got.IDTokenLifetime)
	assert.Equal(t, 48*time.Hour, got.RefreshTokenLifetime)
	assert.NotContains(t, rec.Body.String(), `id="section-authentication"`)
}

func TestProfileSection_RejectsNonNumericLifetimesBeforeTheUseCase(t *testing.T) {
	f := newPagesFixture(t)
	p := testProfile()
	f.stubProfilePage(p, nil)
	f.apps.PatchProfileMock.Optional().Set(func(ctx context.Context, cmd port.PatchProfileCommand) error {
		t.Error("an unparseable lifetime must not reach the use case")
		return nil
	})

	rec := f.do(http.MethodPut, "/admin/applications/profiles/"+p.ID.String()+"/lifetimes", url.Values{
		"access_token_lifetime":  {"soon"},
		"id_token_lifetime":      {"600"},
		"refresh_token_lifetime": {"-5"},
	}, htmx())

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), "enter a positive whole number")
}

func TestProfileSection_AuthenticationForwardsGrantsAndRTR(t *testing.T) {
	f := newPagesFixture(t)
	p := testProfile()
	f.stubProfilePage(p, nil)

	var got port.PatchProfileCommand
	f.apps.PatchProfileMock.Set(func(ctx context.Context, cmd port.PatchProfileCommand) error {
		got = cmd
		return nil
	})

	rec := f.do(http.MethodPut, "/admin/applications/profiles/"+p.ID.String()+"/authentication", url.Values{
		"token_endpoint_auth_method": {"none"},
		"signing_algorithm":          {"ES256"},
		"grant_types":                {"authorization_code", "refresh_token"},
		"enforce_rtr":                {"true"},
	}, htmx())

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, model.AuthMethodNone, got.TokenEndpointAuthMethod)
	assert.Equal(t, model.AlgES256, got.SigningAlgorithm)
	assert.Equal(t, []model.GrantType{model.GrantTypeAuthorizationCode, model.GrantTypeRefreshToken}, got.GrantTypes)
	assert.True(t, got.EnforceRTR)
}
