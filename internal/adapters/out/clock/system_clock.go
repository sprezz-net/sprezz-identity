package clock

import (
	"time"

	"sprezz-identity/internal/domain/port"
)

// SystemClock is the production implementation of the port.Clock interface, returning real UTC system times.
type SystemClock struct{}

// NewSystemClock creates a new production SystemClock.
func NewSystemClock() port.Clock {
	return &SystemClock{}
}

// Now returns the current UTC time, truncated to whole seconds.
func (c *SystemClock) Now() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}
