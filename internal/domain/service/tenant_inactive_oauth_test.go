package service

import (
	"context"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

func inactiveOAuthCases() []inactiveCase {
	return []inactiveCase{
		{"OAuth discovery", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.oauth.ProcessDiscoveryMetadata(ctx, e.tenantID, true)
			return err
		}},
		{"OAuth JWKS", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.oauth.ProcessJWKSetRetrieval(ctx, e.tenantID, "off.example.com", "https")
			return err
		}},
		{"OAuth authorize", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.oauth.ProcessAuthorizeRequest(ctx, port.AuthorizeRequestCommand{TenantID: e.tenantID, ClientID: "c", State: "abcdefghijklmnop"})
			return err
		}},
		{"OAuth pushed authorization", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.oauth.ProcessPushedAuthorization(ctx, port.PushedAuthCommand{TenantID: e.tenantID, ClientID: "c", IsClientAuthenticated: true})
			return err
		}},
		{"OAuth code exchange", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.oauth.ExchangeCodeForTokens(ctx, port.ExchangeCodeForTokensCommand{TenantID: e.tenantID, ClientID: "c", Code: "code"})
			return err
		}},
		{"OAuth refresh rotation", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.oauth.RotateRefreshToken(ctx, port.RotateRefreshTokenCommand{TenantID: e.tenantID, ClientID: "c", RefreshToken: "rt"})
			return err
		}},
		{"OAuth client credentials", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.oauth.ExchangeClientCredentials(ctx, port.ExchangeClientCredentialsCommand{TenantID: e.tenantID, ClientID: "c"})
			return err
		}},
		{"OAuth external token exchange", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.oauth.ExchangeExternalToken(ctx, e.tenantID, "c", "jwt", model.TokenTypeIDToken)
			return err
		}},
		{"OAuth dynamic registration", func(ctx context.Context, e *inactiveEnv) error {
			_, _, err := e.oauth.RegisterDynamicApplication(ctx, e.tenantID, model.DynamicRegistrationPayload{})
			return err
		}},
		{"federated login start", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.fed.InitiateFederatedLogin(ctx, port.InitiateFederatedLoginCommand{TenantID: e.tenantID, IdentityProviderID: uuid.New()})
			return err
		}},
		{"federated login callback", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.fed.ExecuteFederatedCallback(ctx, port.FederatedCallbackCommand{TenantID: e.tenantID, IncomingState: "s"})
			return err
		}},
		{"admin console login", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.adminLog.InitiateAdminLogon(ctx, e.tenantID, "https://off.example.com/cb", "https://off.example.com/admin")
			return err
		}},
	}
}
