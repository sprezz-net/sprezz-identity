package http

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func sampleSummaries() []model.ApplicationSummary {
	return []model.ApplicationSummary{
		{ClientID: "shop-web", ApplicationName: "Shop", GroupName: "partners", ProfileName: "web", GroupID: uuid.New(), ProfileID: uuid.New()},
		{ClientID: "dyn_abc", ApplicationName: "Partner Portal", IsDynamic: true, GroupID: uuid.New(), ProfileID: uuid.New()},
		{ClientID: "billing", ApplicationName: "Billing", GroupID: uuid.New(), ProfileID: uuid.New()},
	}
}

func TestFilterApplications(t *testing.T) {
	apps := sampleSummaries()

	tests := []struct {
		name  string
		kind  string
		query string
		want  []string
	}{
		{name: "no filter", want: []string{"shop-web", "dyn_abc", "billing"}},
		{name: "static only", kind: "static", want: []string{"shop-web", "billing"}},
		{name: "dynamic only", kind: "dynamic", want: []string{"dyn_abc"}},
		{name: "search by name ignores case", query: "SHOP", want: []string{"shop-web"}},
		{name: "search by client id", query: "dyn_", want: []string{"dyn_abc"}},
		{name: "search trims whitespace", query: "  bill ", want: []string{"billing"}},
		{name: "filter and search combine", kind: "static", query: "portal", want: []string{}},
		{name: "unknown type shows everything", kind: "other", want: []string{"shop-web", "dyn_abc", "billing"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := []string{}
			for _, app := range filterApplications(apps, tt.kind, tt.query) {
				got = append(got, app.ClientID)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestApplicationsList_FilterAndSearchAreAddressable(t *testing.T) {
	f := newPagesFixture(t)
	f.stubDashboard(0, nil, nil)
	f.apps.GetApplicationDashboardMock.Optional().Set(func(ctx context.Context, tID uuid.UUID) ([]model.ApplicationSummary, []model.ApplicationProfile, []model.ApplicationGroup, error) {
		return sampleSummaries(), make([]model.ApplicationProfile, 2), make([]model.ApplicationGroup, 4), nil
	})

	q := url.Values{"type": {"static"}, "q": {"shop"}}.Encode()
	body := f.do(http.MethodGet, "/admin/applications?"+q, nil, htmx()).Body.String()

	assert.Contains(t, body, "Shop")
	assert.NotContains(t, body, "Partner Portal", "the dynamic application is filtered out")
	assert.NotContains(t, body, "Billing", "the search narrows the list")
	assert.Contains(t, body, `value="shop"`, "the search box keeps its value")
	assert.Contains(t, body, `(3)`, "the tab counts come from the unfiltered totals")
	assert.Contains(t, body, `aria-current="page"`)
}

func TestApplicationsList_EmptyStateAndFlashMessage(t *testing.T) {
	f := newPagesFixture(t)
	f.stubDashboard(0, nil, nil)

	body := f.do(http.MethodGet, "/admin/applications?msg=Application+deleted", nil, nil).Body.String()

	assert.Contains(t, body, "No applications found")
	assert.Contains(t, body, "Application deleted")
	assert.Contains(t, body, `href="/admin/applications/new"`)
}

func TestSubNavigation_EveryTabHasItsOwnAddress(t *testing.T) {
	f := newPagesFixture(t)
	f.stubDashboard(2, make([]model.ApplicationGroup, 3), make([]model.ApplicationProfile, 1))

	body := f.do(http.MethodGet, "/admin/applications", nil, nil).Body.String()

	for _, href := range []string{`href="/admin/applications"`, `href="/admin/applications/groups"`, `href="/admin/applications/profiles"`} {
		assert.Contains(t, body, href)
	}
	assert.Contains(t, body, `hx-push-url="true"`)
}
