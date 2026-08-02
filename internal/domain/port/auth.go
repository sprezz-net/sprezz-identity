package port

import (
	"context"

	"sprezz-identity/internal/domain/model"

	"github.com/google/uuid"
)

// Cleaned: Renamed from OAuthFlowUseCase to Auth
type Auth interface {
	InitiateAuthorize(ctx context.Context, session model.AuthorizationCodeSession) error
	ExchangeCodeForTokens(ctx context.Context, tenantID uuid.UUID, clientID string, code string, codeVerifier string) (*model.TokenSetResponse, error)
	ProcessLogout(ctx context.Context, tenantID uuid.UUID, subject string, clientID string, tokenJTI string) error
	RevokeToken(ctx context.Context, tenantID uuid.UUID, clientID string, tokenStr string) error
	IntrospectToken(ctx context.Context, tenantID uuid.UUID, clientID string, tokenStr string) (*model.IntrospectionResponse, error)
}
