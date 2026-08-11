package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/pkg/httpclient"

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"
)

type IdentityProviderService struct {
	storage port.Storage
	clock   port.Clock
}

func NewIdentityProviderService(storage port.Storage, cl port.Clock) *IdentityProviderService {
	return &IdentityProviderService{storage: storage, clock: cl}
}

func (s *IdentityProviderService) getOrCreateIdentity(ctx context.Context, userID uuid.UUID, providerID uuid.UUID, now time.Time) (*model.UserIdentity, error) {
	identity, err := s.storage.GetIdentityByProfileAndProvider(ctx, userID, providerID)
	if err != nil {
		if errors.Is(err, port.ErrIdentityNotFound) {
			return &model.UserIdentity{
				ID:                 uuid.New(),
				UserProfileID:      userID,
				IdentityProviderID: providerID,
				ExternalIdentityID: userID.String(),
				CoupledAt:          now,
			}, nil
		}
		return nil, err
	}
	return identity, nil
}

func (s *IdentityProviderService) checkPasswordCredential(ctx context.Context, userID uuid.UUID, providerID uuid.UUID, password string) (bool, error) {
	passwordRecord, err := s.storage.GetPasswordCredential(ctx, userID, providerID)
	if err != nil {
		if errors.Is(err, port.ErrPasswordCredentialNotFound) {
			return false, nil
		}
		return false, err
	}
	return verifyArgon2idPassword(password, passwordRecord.Argon2Hash), nil
}

func (s *IdentityProviderService) resolvePartitionID(ctx context.Context, tenantID uuid.UUID, partitionID int64) int64 {
	if partitionID != 0 {
		return partitionID
	}
	tenant, err := s.storage.ResolveTenantByID(ctx, tenantID)
	if err == nil && tenant.DefaultPartition != nil {
		return *tenant.DefaultPartition
	}
	return 0
}

func (s *IdentityProviderService) findUsernamePasswordProvider(providers []model.IdentityProvider, partitionID int64) *model.IdentityProvider {
	for _, candidate := range providers {
		if candidate.IDPType != model.UsernamePasswordIDPType {
			continue
		}
		if partitionID == 0 || candidate.PartitionID == partitionID {
			return &candidate
		}
	}
	return nil
}

func (s *IdentityProviderService) recordSuccessfulLogin(ctx context.Context, profileID uuid.UUID, providerID uuid.UUID, now time.Time) error {
	identity, err := s.storage.GetIdentityByProfileAndProvider(ctx, profileID, providerID)
	if err != nil {
		return fmt.Errorf("lookup identity record: %w", err)
	}
	identity.LastLoginAt = now
	identity.LoginCount++
	if err := s.storage.UpsertIdentity(ctx, *identity); err != nil {
		return fmt.Errorf("upsert identity record: %w", err)
	}
	return nil
}

func (s *IdentityProviderService) AuthenticateUsernamePassword(ctx context.Context, tenantID uuid.UUID, partitionID int64, username string, password string) (*model.LoginResult, error) {
	providers, err := s.storage.GetEnabledIdentityProviders(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve enabled identity providers: %w", err)
	}
	if len(providers) == 0 {
		return nil, errors.New("no identity providers configured for tenant")
	}

	resolvedPartitionID := s.resolvePartitionID(ctx, tenantID, partitionID)
	provider := s.findUsernamePasswordProvider(providers, resolvedPartitionID)
	if provider == nil {
		return nil, fmt.Errorf("identity provider %s is not configured for tenant", model.UsernamePasswordIDPType)
	}

	profile, err := s.storage.GetUserProfileByIdentifier(ctx, tenantID, resolvedPartitionID, provider.ID, username)
	if err != nil {
		return nil, errors.New("invalid username or password")
	}

	ok, err := s.VerifyPassword(ctx, tenantID, profile.ID, password)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("invalid username or password")
	}

	now := s.clock.Now()
	if err := s.recordSuccessfulLogin(ctx, profile.ID, provider.ID, now); err != nil {
		return nil, err
	}

	identity, err := s.storage.GetIdentityByProfileAndProvider(ctx, profile.ID, provider.ID)
	if err != nil {
		return nil, err
	}

	return &model.LoginResult{UserProfile: profile, Identity: identity}, nil
}

func verifyArgon2idPassword(password string, hash string) bool {
	match, err := argon2id.ComparePasswordAndHash(password, hash)
	return err == nil && match
}

func (s *IdentityProviderService) GetIdentityProviders(ctx context.Context, tenantID uuid.UUID) ([]model.IdentityProvider, error) {
	return s.storage.GetIdentityProviders(ctx, tenantID)
}

func (s *IdentityProviderService) resolveUserPartitionProvider(ctx context.Context, tenantID uuid.UUID, profile *model.UserProfile) (*model.IdentityProvider, error) {
	providers, err := s.storage.GetIdentityProviders(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("get identity providers: %w", err)
	}
	for _, p := range providers {
		if p.IDPType == model.UsernamePasswordIDPType && p.PartitionID == profile.PartitionID {
			return &p, nil
		}
	}
	return nil, errors.New("username-password provider not found for user partition")
}

func (s *IdentityProviderService) checkTemporalBlock(identity *model.UserIdentity, provider *model.IdentityProvider, now time.Time) bool {
	if !identity.Blocked {
		return false
	}
	blockedDuration := time.Duration(provider.Config.PasswordBlockedTime) * time.Second
	if now.Sub(identity.LastVerificationAttemptAt) <= blockedDuration {
		identity.LastVerificationAttemptAt = now
		_ = s.storage.UpsertIdentity(context.Background(), *identity)
		return true
	}
	return false
}

func (s *IdentityProviderService) updateFailedAttempts(identity *model.UserIdentity, provider *model.IdentityProvider, correct bool) {
	if correct {
		identity.Blocked = false
		identity.FailedVerificationCount = 0
		return
	}
	if !identity.Blocked {
		identity.FailedVerificationCount++
		if identity.FailedVerificationCount >= provider.Config.MaxFailedVerificationCount {
			identity.Blocked = true
		}
	}
}

func (s *IdentityProviderService) VerifyPassword(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, password string) (bool, error) {
	profile, err := s.storage.GetUserProfileByID(ctx, tenantID, userID)
	if err != nil {
		return false, fmt.Errorf("get user profile: %w", err)
	}

	provider, err := s.resolveUserPartitionProvider(ctx, tenantID, profile)
	if err != nil {
		return false, err
	}

	now := s.clock.Now()
	identity, err := s.getOrCreateIdentity(ctx, userID, provider.ID, now)
	if err != nil {
		return false, fmt.Errorf("get or create identity: %w", err)
	}

	if s.checkTemporalBlock(identity, provider, now) {
		return false, nil
	}

	correct, err := s.checkPasswordCredential(ctx, userID, provider.ID, password)
	if err != nil {
		return false, fmt.Errorf("check password credential: %w", err)
	}

	identity.LastVerificationAttemptAt = now
	s.updateFailedAttempts(identity, provider, correct)

	_ = s.storage.UpsertIdentity(ctx, *identity)
	return correct, nil
}

func (s *IdentityProviderService) ChangePassword(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, currentPassword string, newPassword string) error {
	provider, err := s.storage.GetIdentityProviderByType(ctx, tenantID, model.UsernamePasswordIDPType)
	if err != nil {
		return fmt.Errorf("username-password provider not found: %w", err)
	}

	valid, err := s.VerifyPassword(ctx, tenantID, userID, currentPassword)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid username or password")
	}

	passwordRecord, err := s.storage.GetPasswordCredential(ctx, userID, provider.ID)
	if err != nil {
		return fmt.Errorf("lookup password credential: %w", err)
	}

	newHash, err := argon2id.CreateHash(newPassword, argon2id.DefaultParams)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	passwordRecord.Argon2Hash = newHash
	if err := s.storage.SavePasswordCredential(ctx, *passwordRecord); err != nil {
		return fmt.Errorf("failed to save password credential: %w", err)
	}

	return nil
}

func (s *IdentityProviderService) CreateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) (*model.IdentityProvider, error) {
	if provider.Alias == "" {
		return nil, fmt.Errorf("provider alias is required")
	}
	if provider.IDPType == "" {
		return nil, fmt.Errorf("provider IDP type is required")
	}

	if provider.IDPType == model.UsernamePasswordIDPType {
		existing, err := s.storage.GetIdentityProviders(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		for _, ext := range existing {
			if ext.IDPType == model.UsernamePasswordIDPType && ext.PartitionID == provider.PartitionID {
				return nil, errors.New("a username-password identity provider already exists for this partition")
			}
		}
	}

	provider.ID = uuid.New()
	provider.TenantID = tenantID

	if err := s.storage.CreateIdentityProvider(ctx, tenantID, provider); err != nil {
		return nil, err
	}

	return &provider, nil
}

func (s *IdentityProviderService) DeleteIdentityProvider(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) error {
	return s.storage.DeleteIdentityProvider(ctx, tenantID, idpID)
}

func (s *IdentityProviderService) UpdateIdentityProvider(ctx context.Context, tenantID uuid.UUID, provider model.IdentityProvider) (*model.IdentityProvider, error) {
	if provider.Alias == "" {
		return nil, fmt.Errorf("provider alias is required")
	}
	if provider.IDPType == "" {
		return nil, fmt.Errorf("provider IDP type is required")
	}

	if provider.IDPType == model.UsernamePasswordIDPType {
		existing, err := s.storage.GetIdentityProviders(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		for _, ext := range existing {
			if ext.IDPType == model.UsernamePasswordIDPType && ext.ID != provider.ID && ext.PartitionID == provider.PartitionID {
				return nil, errors.New("a username-password identity provider already exists for this partition")
			}
		}
	}

	provider.TenantID = tenantID
	// In our PostgresStorage implementation, CreateIdentityProvider uses ON CONFLICT DO UPDATE
	if err := s.storage.CreateIdentityProvider(ctx, tenantID, provider); err != nil {
		return nil, err
	}

	return &provider, nil
}

func (s *IdentityProviderService) DiscoverOIDC(ctx context.Context, endpoint string) (string, error) {
	if endpoint == "" {
		return "", errors.New("discovery endpoint is required")
	}
	client := httpclient.New()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("invalid json response from discovery endpoint: %w", err)
	}

	return string(body), nil
}

func (s *IdentityProviderService) ResolveFederatedLevels(config model.IdentityProviderConfig, externalAcr string, externalAmrs []string) (int, int) {
	// 1. Establish initial system baselines from Identity Provider Defaults
	resolvedAAL := config.AAL
	if resolvedAAL < 1 {
		resolvedAAL = 1 // Safe minimal structural floor
	}

	resolvedIAL := config.IAL
	if resolvedIAL < 1 {
		resolvedIAL = 1 // Safe minimal structural floor
	}

	// 2. Process multi-dimensional Tuple matches if an external ACR is present
	if externalAcr != "" && config.AcrToTuple != nil {
		if tuple, exists := config.AcrToTuple[externalAcr]; exists {
			// If AAL is mapped (> 0), apply it; if 0 (unmapped), leave it as the IDP default
			if tuple.AAL >= 1 && tuple.AAL <= 3 {
				resolvedAAL = tuple.AAL
			}
			// If IAL is mapped (> 0), apply it; if 0 (unmapped), leave it as the IDP default
			if tuple.IAL >= 1 && tuple.IAL <= 3 {
				resolvedIAL = tuple.IAL
			}
		}
	}

	// 3. Process traditional AMR adjustments against AAL if mapped
	if config.AmrToAAL != nil {
		highestAMRMapped := 0
		for _, amr := range externalAmrs {
			cleanAmr := strings.ToLower(strings.TrimSpace(amr))
			if level, exists := config.AmrToAAL[cleanAmr]; exists && level > highestAMRMapped {
				highestAMRMapped = level
			}
		}
		// AMR map values override if they exceed baseline thresholds
		if highestAMRMapped >= 1 && highestAMRMapped <= 3 {
			if highestAMRMapped > resolvedAAL {
				resolvedAAL = highestAMRMapped
			}
		}
	}

	return resolvedAAL, resolvedIAL
}

func (s *IdentityProviderService) NormalizeFederatedAmr(reachedAAL int) string {
	switch reachedAAL {
	case 2:
		return "federated mfa"
	case 3, 4:
		return "federated hwk"
	default:
		return "federated"
	}
}

type SprezzAssuranceClaims struct {
	AMR []string `json:"amr"`
	ACR string   `json:"acr"`
}

// NormalizeFederatedClaims translates upstream factors and configuration parameters into Sprezz token standards
func NormalizeFederatedClaims(upstreamAMR []string, upstreamACR string, defaultAAL int, acrToTupleMap map[string]model.AcrTuple, amrToAalMap map[string]int) SprezzAssuranceClaims {
	// 1. Establish initial baseline AAL fallback
	resolvedAAL := defaultAAL
	if resolvedAAL < 1 {
		resolvedAAL = 1 // Safe absolute lower boundary
	}

	// Lowercase upstream AMR strings for O(1) map matching checks
	amrMap := make(map[string]bool)
	for _, val := range upstreamAMR {
		amrMap[strings.ToLower(strings.TrimSpace(val))] = true
	}

	// 2. Step A: Check administrative ACR Tuple Matrix first (highest priority)
	if upstreamACR != "" && acrToTupleMap != nil {
		if tuple, exists := acrToTupleMap[upstreamACR]; exists && tuple.AAL > 0 {
			resolvedAAL = tuple.AAL
		}
	}

	// 3. Step B: Evaluate via custom/standard administrative AMR maps
	if amrToAalMap != nil {
		highestAMRMapped := 0
		for factor := range amrMap {
			if level, exists := amrToAalMap[factor]; exists && level > highestAMRMapped {
				highestAMRMapped = level
			}
		}
		if highestAMRMapped > 0 {
			resolvedAAL = highestAMRMapped
		}
	}

	// 4. Step C: Hardcoded Spec Fallback (RFC 8176) if no explicit custom admin map hit
	hasAcrMapping := false
	if upstreamACR != "" && acrToTupleMap != nil {
		if tuple, exists := acrToTupleMap[upstreamACR]; exists && tuple.AAL > 0 {
			hasAcrMapping = true
		}
	}

	if !hasAcrMapping && len(amrToAalMap) == 0 {
		// Evaluate strict Level 3 Hardware isolation
		if amrMap["hwk"] || amrMap["fido"] || amrMap["userpresence"] || amrMap["sc"] {
			resolvedAAL = 3
		} else if amrMap["mfa"] || amrMap["otp"] || amrMap["sms"] || amrMap["pin"] ||
			amrMap["face"] || amrMap["fpt"] || amrMap["swk"] || amrMap["pop"] || amrMap["user"] {
			// Standard Multi-factor / Cryptographic software context
			resolvedAAL = 2
		}
	}

	// 5. Compile Outbound Token Claims Structure
	var outboundAMR []string
	var outboundACR string

	switch resolvedAAL {
	case 3:
		outboundAMR = []string{"federated", "hwk"}
		outboundACR = "urn:sprezz:assurance:aal3"
	case 2:
		outboundAMR = []string{"federated", "mfa"}
		outboundACR = "urn:sprezz:assurance:aal2"
	default:
		outboundAMR = []string{"federated"}
		outboundACR = "urn:sprezz:assurance:aal1"
	}

	return SprezzAssuranceClaims{
		AMR: outboundAMR,
		ACR: outboundACR,
	}
}
