package port

import (
	"context"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

type AdminLogonUseCase interface {
	InitiateAdminLogon(ctx context.Context, localTenantID uuid.UUID, callbackURI string, targetAdminUI string) (*InitiateFederatedLoginResponse, error)
	CompleteAdminLogon(ctx context.Context, localTenantID uuid.UUID, incomingState string, incomingCode string) (*model.TokenSetResponse, string, error)
}
