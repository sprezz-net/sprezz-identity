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
		{"starting a sign-in", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.sso.StartFlow(ctx, port.StartFlowCommand{TenantID: e.tenantID, PartitionID: inactivePartition})
			return err
		}},
		{"completing a sign-in", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.sso.PromoteSession(ctx, port.PromoteSessionCommand{TenantID: e.tenantID, PartitionID: inactivePartition, SessionID: uuid.New(), UserProfileID: uuid.New()})
			return err
		}},
		{"opening a session", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.sso.CreateSession(ctx, port.CreateSessionCommand{TenantID: e.tenantID, PartitionID: inactivePartition, UserProfileID: uuid.New()})
			return err
		}},
		{"resolving a flow session", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.sso.ResolveFlowSession(ctx, e.tenantID, inactivePartition, map[string]string{}, uuid.New())
			return err
		}},
		{"resolving a direct flow session", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.sso.ResolveDirectFlowSession(ctx, e.tenantID, inactivePartition, map[string]string{})
			return err
		}},
		{"resolving the flow sessions of a callback", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.sso.ResolveFlowSessionIDs(ctx, e.tenantID, map[string]string{})
			return err
		}},
		{"resolving a signed-in session", func(ctx context.Context, e *inactiveEnv) error {
			_, err := e.sso.ResolveSession(ctx, e.tenantID, "x")
			return err
		}},
		{"assurance check", func(ctx context.Context, e *inactiveEnv) error {
			return e.assure.AssertActionTrust(ctx, port.SecurityAccessAssertion{TenantID: e.tenantID, ProviderID: uuid.New(), TargetAction: "profile_view"})
		}},
	}
}
