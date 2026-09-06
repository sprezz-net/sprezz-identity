package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

type LocalAuthService struct {
	storage port.Storage
	crypto  port.Crypto
	clock   port.Clock
}

func NewLocalAuthService(s port.Storage, c port.Crypto, cl port.Clock) *LocalAuthService {
	return &LocalAuthService{
		storage: s,
		crypto:  c,
		clock:   cl,
	}
}

// AuthenticateLocalCredentials executes Use Case 1.1 to process native username/password entries.
func (s *LocalAuthService) AuthenticateLocalCredentials(ctx context.Context, cmd port.LocalLoginCommand) (*port.LocalLoginResponse, error) {
	// A standard high-entropy Argon2id hash used to perform a dummy comparison path
	// This forces a consistent CPU execution time when a user profile does not exist
	const dummyArgon2Hash = "$argon2id$v=19$m=65536,t=1,p=4$NDg4bVUzcmM2M1NxM2I0Yg$d2U4M3I2M3FzYTQ4OG11M3JjNjNzcTNidDRi"

	// 1. Locate the specific target identity record for this authentication attempt
	identity, err := s.storage.GetUserIdentityByIdentifier(ctx, cmd.TenantID, cmd.PartitionID, cmd.ProviderID, cmd.Identifier)
	if err != nil {
		// Defensive Timing Attack Mitigation: Run a dummy matching cycle
		_, _ = s.crypto.CompareCredential(dummyArgon2Hash, cmd.PlaintextPassword)
		return nil, port.ErrInvalidCredentials
	}

	// 2. Fetch the target Identity Provider profile to pull threshold rules
	idp, err := s.storage.GetIdentityProviderByUUID(ctx, cmd.TenantID, cmd.ProviderID)
	if err != nil {
		return nil, port.ErrInvalidCredentials
	}

	// 4. PASSWORD DECRYPTION: Fetch password hash and execute Argon2id verification
	passwordCred, err := s.storage.GetPasswordCredentialByProfileID(ctx, cmd.TenantID, cmd.PartitionID, identity.UserProfileID, cmd.ProviderID)
	if err != nil {
		_, _ = s.crypto.CompareCredential(dummyArgon2Hash, cmd.PlaintextPassword)
		return nil, port.ErrInvalidCredentials
	}

	// 3. LAYER 1 SECURITY GATING: Evaluate Provider-Specific Lockouts
	now := s.clock.Now()
	if passwordCred.IsBlocked(now) {
		_, _ = s.crypto.CompareCredential(dummyArgon2Hash, cmd.PlaintextPassword)
		return nil, port.ErrAccountTemporarilyLocked
	}

	// Option 2 (Fixed Window): reset if block has elapsed
	if passwordCred.BlockedUntil != nil && now.After(*passwordCred.BlockedUntil) {
		_ = s.storage.ResetPasswordCounters(ctx, cmd.TenantID, cmd.PartitionID, identity.UserProfileID, cmd.ProviderID)
		passwordCred.FailedVerificationCount = 0
		passwordCred.BlockedUntil = nil
	}

	// Execute actual hash check using your existing crypto interface binding method
	match, err := s.crypto.CompareCredential(passwordCred.Argon2Hash, cmd.PlaintextPassword)
	if err != nil || !match {
		_ = s.handleFailedPasswordAttempt(ctx, cmd.TenantID, cmd.PartitionID, identity.UserProfileID, cmd.ProviderID, passwordCred, idp, now)
		return nil, port.ErrInvalidCredentials
	}

	// 5. LAYER 2 SECURITY GATING: Evaluate Global Profile Lifecycles
	profile, err := s.storage.GetUserProfileByID(ctx, cmd.TenantID, cmd.PartitionID, identity.UserProfileID)
	if err != nil {
		return nil, port.ErrInvalidCredentials
	}

	// Evaluates the dual-return model signature guard rule
	allowed, loginErr := profile.IsLoginAllowed()
	if !allowed || loginErr != nil {
		switch {
		case errors.Is(loginErr, model.ErrAccountBlocked):
			return nil, port.ErrAccountBlocked
		case errors.Is(loginErr, model.ErrAccountNotActivated):
			return nil, port.ErrActivationRequired
		default:
			return nil, port.ErrInvalidCredentials
		}
	}

	// 6. SUCCESS: Wipe metric tracks and return operational boundaries
	if passwordCred.FailedVerificationCount > 0 {
		_ = s.storage.ResetPasswordCounters(ctx, cmd.TenantID, cmd.PartitionID, identity.UserProfileID, cmd.ProviderID)
	}

	// Increment overall usage parameters
	_ = s.storage.IncrementUserIdentityLoginTracker(ctx, cmd.TenantID, cmd.PartitionID, identity.ID, s.clock.Now())

	sessionID := uuid.New().String()

	return &port.LocalLoginResponse{
		UserProfileID: profile.ID,
		PartitionID:   profile.PartitionID,
		SessionID:     sessionID,
		Subject:       profile.ID.String(),
	}, nil
}

// handleFailedPasswordAttempt increments thresholds and handles administrative blocking conditions.
func (s *LocalAuthService) handleFailedPasswordAttempt(
	ctx context.Context,
	tenantID uuid.UUID,
	partitionID int64,
	userProfileID uuid.UUID,
	providerID uuid.UUID,
	passwordCred *model.PasswordCredential,
	idp *model.IdentityProvider,
	now time.Time,
) error {
	nextFailureCount := passwordCred.FailedVerificationCount + 1
	var blockedUntil *time.Time

	if nextFailureCount >= idp.Config.MaxFailedVerificationCount {
		cooldownDuration := time.Duration(idp.Config.PasswordBlockedTime) * time.Second
		exp := now.Add(cooldownDuration)
		blockedUntil = &exp
	}

	err := s.storage.UpdatePasswordLockoutState(ctx, tenantID, partitionID, userProfileID, providerID, nextFailureCount, &now, blockedUntil)
	if err != nil {
		return fmt.Errorf("auth_service: failed to commit security lockout metric state: %w", err)
	}
	return nil
}

func (s *LocalAuthService) GetLoginContext(ctx context.Context, cmd port.GetLoginContextCommand) (*port.LoginContextResponse, error) {
	// 1. Fetch Tenant configuration permissions
	tenant, err := s.storage.ResolveTenantByUUID(ctx, cmd.TenantID)
	if err != nil {
		return nil, fmt.Errorf("local_auth_service: failed resolving tenant context: %w", err)
	}

	var allowSignup bool
	var tenantBaseURI string
	if tenant != nil {
		allowSignup = tenant.Config.AllowSignup
		tenantBaseURI = tenant.GetBaseURI()
	}

	// 2. Fetch enabled providers for the tenant
	allProviders, err := s.storage.GetEnabledIdentityProviders(ctx, cmd.TenantID)
	if err != nil {
		return nil, fmt.Errorf("local_auth_service: failed gathering enabled providers: %w", err)
	}

	// 3. Fetch interaction session if interaction ID is provided
	var interactionSession *model.InteractionSession
	var allowedIDPs []string
	var partitionID int64
	var isDirectAccess = true

	if tenant != nil {
		if tenant.DefaultPartition != nil && *tenant.DefaultPartition != 0 {
			partitionID = *tenant.DefaultPartition
		} else {
			parts, err := s.storage.GetPartitions(ctx, cmd.TenantID)
			if err == nil && len(parts) > 0 {
				partitionID = parts[0].ID
			}
		}
	}

	if cmd.InteractionID != "" {
		sessionUUID, err := uuid.Parse(cmd.InteractionID)
		if err == nil {
			session, err := s.storage.GetInteractionSession(ctx, cmd.TenantID, sessionUUID)
			if err == nil && session != nil {
				interactionSession = session
				isDirectAccess = false
				partitionID = session.PartitionID
				if session.IDPHint != "" {
					allowedIDPs = []string{session.IDPHint}
				}
			}
		}
	}

	// 4. Apply provider filtering matching lineage logic
	var finalProviders []model.IdentityProvider
	if isDirectAccess {
		for _, p := range allProviders {
			if p.PartitionID == partitionID {
				finalProviders = append(finalProviders, p)
			}
		}
	} else {
		for _, p := range allProviders {
			for _, allowedAlias := range allowedIDPs {
				if p.Alias == allowedAlias {
					finalProviders = append(finalProviders, p)
					break
				}
			}
		}
	}

	// 5. Resolve default client/group default provider and idp hint redirects
	var group *model.ApplicationGroup
	if interactionSession != nil {
		_, _, grp, _ := s.storage.GetApplicationByClientID(ctx, cmd.TenantID, interactionSession.ClientID)
		group = grp
	}

	hint := cmd.IDPHintQuery
	if hint == "" && interactionSession != nil {
		hint = interactionSession.IDPHint
	}
	if hint == "" && group != nil && group.DefaultIDPID != nil {
		idp, err := s.storage.GetIdentityProviderByUUID(ctx, group.TenantID, *group.DefaultIDPID)
		if err == nil && idp != nil {
			hint = idp.Alias
		}
	}

	var triggerAutoFederatedIDP *model.IdentityProvider
	if hint != "" {
		for _, p := range finalProviders {
			if p.Alias == hint && p.IDPType != model.UsernamePasswordIDPType {
				pCopy := p
				triggerAutoFederatedIDP = &pCopy
				break
			}
		}
	}

	showPasswordForm := false
	var matchedPartition int64
	for _, p := range finalProviders {
		if p.IDPType == model.UsernamePasswordIDPType {
			showPasswordForm = true
			matchedPartition = p.PartitionID
			break
		}
	}

	return &port.LoginContextResponse{
		AllowSignup:              allowSignup,
		Providers:                finalProviders,
		ShowUsernamePasswordForm: showPasswordForm,
		PartitionID:              matchedPartition,
		InteractionSession:       interactionSession,
		TriggerAutoFederatedIDP:  triggerAutoFederatedIDP,
		TenantBaseURI:            tenantBaseURI,
	}, nil
}

func (s *LocalAuthService) GetInteractionSession(ctx context.Context, tenantID uuid.UUID, interactionID string) (*model.InteractionSession, error) {
	uid, err := uuid.Parse(interactionID)
	if err != nil {
		return nil, fmt.Errorf("local_auth_service: invalid interaction ID format: %w", err)
	}
	session, err := s.storage.GetInteractionSession(ctx, tenantID, uid)
	if err != nil {
		return nil, fmt.Errorf("local_auth_service: failed to retrieve interaction session: %w", err)
	}
	return session, nil
}
