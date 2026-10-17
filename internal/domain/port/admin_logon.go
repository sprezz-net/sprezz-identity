package port

import (
	"context"

	"github.com/google/uuid"
)

type AdminLogonUseCase interface {
	InitiateAdminLogon(ctx context.Context, localTenantID uuid.UUID, flowSessionID uuid.UUID, callbackURI string, targetAdminUI string) (*InitiateFederatedLoginResponse, error)
}
