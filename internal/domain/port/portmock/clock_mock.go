package portmock

import "time"

// MockClock is a hand-crafted test clock implementing the port.Clock interface, enabling precise temporal control.
type MockClock struct {
	currentTime time.Time
}

// NewMockClock returns an initialized MockClock with temporal precision truncated to seconds to prevent sub-second JWT assertions from failing.
func NewMockClock(t time.Time) *MockClock {
	return &MockClock{currentTime: t.Truncate(time.Second)}
}

// Now returns the active mockup time.
func (m *MockClock) Now() time.Time {
	return m.currentTime
}

// SetTime manually overrides the mockup time.
func (m *MockClock) SetTime(t time.Time) {
	m.currentTime = t.Truncate(time.Second)
}

// Advance fast-forwards the clock by the specified duration.
func (m *MockClock) Advance(d time.Duration) {
	m.currentTime = m.currentTime.Add(d)
}
