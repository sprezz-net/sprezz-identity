package port

import "time"

// Clock abstracts the time source, returning UTC time truncated to whole seconds
// to align with standard OAuth2/OIDC numeric temporal claims and prevent sub-second test flakiness.
type Clock interface {
	Now() time.Time
}
