package port

import "context"

type LogoutNotifier interface {
	SendBackChannelLogout(ctx context.Context, logoutURI string, logoutToken string) error
}
