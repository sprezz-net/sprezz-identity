package service

import (
	"context"

	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

func inactiveSignInCases() []inactiveCase {
	return []inactiveCase{
		{"local sign-in", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.local.AuthenticateLocalCredentials(ctx, port.LocalLoginCommand{TenantID: e.tenantID, PartitionID: inactivePartition, Identifier: "u", PlaintextPassword: "p"})
			return err
		}},
		{"login page context", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.local.GetLoginContext(ctx, port.GetLoginContextCommand{TenantID: e.tenantID})
			return err
		}},
		{"pending sign-in session", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.local.GetInteractionSession(ctx, e.tenantID, uuid.NewString())
			return err
		}},
		{"password check", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.idp.VerifyPassword(ctx, e.tenantID, uuid.New(), "p")
			return err
		}},
		{"username and password sign-in", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.idp.AuthenticateUsernamePassword(ctx, e.tenantID, inactivePartition, "u", "p")
			return err
		}},
		{"password change by provider service", func(ctx context.Context, e *inactiveEnv) error {
			return e.idp.ChangePassword(ctx, e.tenantID, uuid.New(), "old", "new")
		}},
		{"self-service registration", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.reg.RegisterUser(ctx, port.RegisterUserCommand{TenantID: e.tenantID, ProviderID: uuid.New()})
			return err
		}},
		{"registration approval", func(ctx context.Context, e *inactiveEnv) error {
			return e.reg.ApproveUserRequest(ctx, port.ApproveUserCommand{TenantID: e.tenantID, PartitionID: inactivePartition, ProfileID: uuid.New()})
		}},
		{"signup page context", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.reg.GetSignupContext(ctx, port.GetSignupContextCommand{TenantID: e.tenantID})
			return err
		}},
		{"session cookie issuing (handshake)", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.sso.BuildSessionCookie(ctx, port.CookieIntentCommand{TenantID: e.tenantID, PartitionID: inactivePartition, LifecycleStage: "handshake", PayloadValue: "x"})
			return err
		}},
		{"session cookie issuing (bearer)", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.sso.BuildSessionCookie(ctx, port.CookieIntentCommand{TenantID: e.tenantID, PartitionID: inactivePartition, LifecycleStage: "bearer", PayloadValue: "x"})
			return err
		}},
		{"assurance check", func(ctx context.Context, e *inactiveEnv) error {
			return e.assure.AssertActionTrust(ctx, port.SecurityAccessAssertion{TenantID: e.tenantID, ProviderID: uuid.New(), TargetAction: "profile_view"})
		}},
	}
}
