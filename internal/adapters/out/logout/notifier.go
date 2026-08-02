package logout

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"sprezz-identity/internal/pkg/httpclient"
)

type LogoutHttpClient struct {
	client *http.Client
}

func NewLogoutHttpClient() *LogoutHttpClient {
	return &LogoutHttpClient{
		client: httpclient.New(),
	}
}

func (n *LogoutHttpClient) SendBackChannelLogout(ctx context.Context, logoutURI string, logoutToken string) error {
	form := url.Values{}
	form.Set("logout_token", logoutToken)

	req, err := http.NewRequestWithContext(ctx, "POST", logoutURI, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("create back-channel logout request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("execute back-channel logout request: %w", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("back-channel logout returned error status: %d", resp.StatusCode)
	}

	return nil
}
