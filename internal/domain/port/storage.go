package port

import (
	"context"
	"errors"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

var ErrTenantNotFound = errors.New("tenant not found")

type Storage interface {
	SaveClient(ctx context.Context, client model.ClientApplication) error
	GetClient(ctx context.Context, tenantID uuid.UUID, clientID string) (*model.ClientApplication, error)
	SaveAuthSession(ctx context.Context, session model.AuthorizationCodeSession) error
	GetAndConsumeAuthSession(ctx context.Context, tenantID uuid.UUID, code string) (*model.AuthorizationCodeSession, error)
	ResolveTenantByDomain(ctx context.Context, domain string) (*model.Tenant, error)
	ResolveTenantByID(ctx context.Context, tenantID uuid.UUID) (*model.Tenant, error)
	CreateTenant(ctx context.Context, tenant model.Tenant) error
	RevokeSession(ctx context.Context, tenantID uuid.UUID, subject string, clientID string) error
}
