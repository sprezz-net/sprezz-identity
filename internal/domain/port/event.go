package port

import (
	"context"

	"github.com/google/uuid"
)

type AuditEvent struct {
	EventID   uuid.UUID
	TenantID  uuid.UUID
	EventType string
	ClientID  string
	Subject   string
	Payload   map[string]string
}

type Event interface {
	Publish(ctx context.Context, event AuditEvent) error
}
