package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

type FederationService struct {
	storage          port.Storage          // Driven Port: Relational DB persistence
	federationClient port.FederationClient // Driven Port: Outbound HTTP network client [1.3]
	crypto           port.Crypto           // Driven Port: JWT verify and token signature checks
	clock            port.Clock            // Driven Port: Deterministic System Clock
	validator        OAuthValidatorService
}

// NewFederationService instantiates a fully isolated federation engine domain loop
func NewFederationService(
	s port.Storage,
	fc port.FederationClient,
	c port.Crypto,
	cl port.Clock,
) *FederationService {
	return &FederationService{
		storage:          s,
		federationClient: fc,
		crypto:           c,
		clock:            cl,
	}
}

func (s *FederationService) createStateToken() (string, error) {
	// 1. Generate 16 bytes of cryptographically secure pseudo-random noise directly
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("federation_service: high-entropy failure: %w", err)
	}

	// 2. Compact the payload into a 22-character url-safe string with zero allocations overhead
	stateToken := base64.RawURLEncoding.EncodeToString(tokenBytes)
	return stateToken, nil
}

func (s *FederationService) createCodeVerifier() (string, error) {
	// 1. Allocate 32 bytes of secure cryptographic noise for the verifier (entropy > 256 bits)
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", fmt.Errorf("federation_service: random safety source failure: %w", err)
	}

	// 2. Encode to create the RFC 7636 compliant high-entropy code_verifier string (43 characters)
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	return codeVerifier, nil
}

func (s *FederationService) createPKCEChallenge(codeVerifier string) string {
	// 3. Compute the SHA-256 cryptographic digest over the verifier string bytes
	hashDigest := sha256.Sum256([]byte(codeVerifier))

	// 4. Compact the raw binary digest to build your final S256 code_challenge
	pkceChallenge := base64.RawURLEncoding.EncodeToString(hashDigest[:])
	return pkceChallenge
}

// InitiateFederatedLogin coordinates Use Case 2.0: Outbound Handshake Construction with dynamic PAR fallback capabilities
func (s *FederationService) InitiateFederatedLogin(
	ctx context.Context,
	cmd port.InitiateFederatedLoginCommand,
) (*port.InitiateFederatedLoginResponse, error) {

	// 1. Resolve configuration schemas for the target provider and assert status values
	idp, err := s.storage.GetIdentityProviderByUUID(ctx, cmd.TenantID, cmd.IdentityProviderID)
	if err != nil {
		return nil, fmt.Errorf("federation_service: initiate failed: %w", port.ErrIdentityProviderNotFound)
	}

	if !idp.Enabled {
		return nil, fmt.Errorf("federation_service: target provider container is administratively deactivated")
	}

	// 2. Fetch runtime network capabilities directly via OIDC Discovery configurations conditionally
	var discovery *model.OIDCDiscoveryMetadata
	if idp.Config.DiscoveryEndpoint != "" {
		discovery, err = s.federationClient.FetchOIDCDiscoveryMetadata(ctx, idp.Config.DiscoveryEndpoint)
		if err != nil {
			return nil, fmt.Errorf("federation_service: live metadata harvesting failed: %w", err)
		}
	}

	// 3. Hierarchy Resolution: Prioritize explicit DB endpoints, fall back to discovery keys
	authEndpoint := idp.Config.AuthorizationEndpoint
	if authEndpoint == "" && discovery != nil {
		authEndpoint = discovery.AuthorizationEndpoint
	}

	parEndpoint := idp.Config.PushedAuthorizationEndpoint
	if parEndpoint == "" && discovery != nil {
		parEndpoint = discovery.PushedAuthorizationRequestEndpoint
	}

	if authEndpoint == "" {
		return nil, fmt.Errorf("federation_service: authorization endpoint is unresolvable for idp %s", idp.ID)
	}

	// 4. DYNAMIC PKCE DETECTION: Optional fallback parsing via CodeChallengeMethodsSupported arrays
	pkceSupportedUpstream := false
	if discovery != nil {
		for _, method := range discovery.CodeChallengeMethodsSupported {
			if strings.ToUpper(method) == "S256" {
				pkceSupportedUpstream = true
				break
			}
		}
	}
	isPkceRequired := idp.Config.PkceEnabled || pkceSupportedUpstream

	stateToken, err := s.createStateToken()
	if err != nil {
		return nil, err
	}

	var codeVerifier, pkceChallenge string
	if isPkceRequired {
		codeVerifier, err = s.createCodeVerifier()
		if err != nil {
			return nil, err
		}
		pkceChallenge = s.createPKCEChallenge(codeVerifier)
	}

	now := s.clock.Now()

	handshakeRecord := model.OutboundHandshakeSession{
		ID:                 stateToken,
		TenantID:           cmd.TenantID,
		PartitionID:        idp.PartitionID,
		IdentityProviderID: idp.ID,
		ClientID:           cmd.ClientID,
		CodeVerifier:       codeVerifier,
		CreatedAt:          now,
		ExpiresAt:          now.Add(5 * time.Minute), // Strict expiration constraint
		CallbackURI:        cmd.LocalCallbackURI,     // e.g., https://sprezz.net
		TargetURI:          cmd.FinalTargetURI,       // Final landing path inside tenant perimeter
	}

	if err := s.storage.SaveOutboundHandshake(ctx, handshakeRecord); err != nil {
		return nil, fmt.Errorf("federation_service: failed to persist context bounds: %w", err)
	}

	// 5. SANITIZE SCOPES: Enforce strict RFC-compliant space-separated string mappings
	targetScopes := idp.Config.Scopes
	if len(targetScopes) == 0 {
		targetScopes = cmd.RequestedScopes // Graceful runtime fallback allocation from controller Command
	}
	scopesStr := strings.Join(targetScopes, " ")

	// 6. Encapsulate parameters matching your updated ports layer structures
	oidcParams := port.OutboundOIDCParams{
		ClientID:         idp.Config.ClientID,
		RedirectURI:      cmd.LocalCallbackURI,
		TargetURI:        cmd.FinalTargetURI,
		Scopes:           targetScopes,
		IdentityProvider: idp,
	}

	var redirectionTargetURL string

	// DUAL-TRACK ROUTING DECISION MATRIX: Determine if PAR can be executed safely
	if parEndpoint != "" {
		// Upstream server supports modern RFC 9126 PAR routines; process via back-channel socket
		requestURI, err := s.federationClient.ExecutePushedAuthorization(
			ctx,
			parEndpoint,
			oidcParams,
			stateToken,
			pkceChallenge,
			scopesStr,
		)
		if err == nil {
			// Backchannel execution completed successfully; return short PAR handle pointing to auth endpoint
			redirectionTargetURL = fmt.Sprintf("%s?client_id=%s&request_uri=%s",
				authEndpoint,
				idp.Config.ClientID,
				url.QueryEscape(requestURI),
			)
		}
		// If backchannel execution fails unexpectedly, it will drop through cleanly to the legacy tracking fallback line
	}

	if redirectionTargetURL == "" {
		// FRONT-CHANNEL FALLBACK: Build classic legacy query parameters because PAR is unsupported or down
		v := url.Values{}
		v.Set("response_type", "code")
		v.Set("client_id", idp.Config.ClientID)
		v.Set("redirect_uri", cmd.LocalCallbackURI)
		v.Set("state", stateToken)
		if scopesStr != "" {
			v.Set("scope", scopesStr)
		}
		if isPkceRequired {
			v.Set("code_challenge", pkceChallenge)
			v.Set("code_challenge_method", "S256")
		}

		redirectionTargetURL = fmt.Sprintf("%s?%s", discovery.AuthorizationEndpoint, v.Encode())
	}

	// 5. Package results to allow transport layers to safely redirect client browser frames
	return &port.InitiateFederatedLoginResponse{
		TargetRedirectURL: redirectionTargetURL,
		StateToken:        stateToken,
	}, nil
}

// ExecuteFederatedCallback coordinates the multi-stage external handshake pipeline natively [5.7]
func (s *FederationService) ExecuteFederatedCallback(
	ctx context.Context,
	cmd port.FederatedCallbackCommand,
) (*port.FederatedCallbackResponse, error) {

	// 1. STAGE 1: Evict and validate the tracking state parameter to block XSRF replays
	handshake, err := s.storage.GetAndConsumeOutboundHandshake(ctx, cmd.TenantID, cmd.IncomingState)
	if err != nil {
		return nil, fmt.Errorf("federation_service: tracking state invalid or replayed: %w", port.ErrSessionNotFound)
	}

	// Enforce strict time-window tracking boundaries
	if s.clock.Now().After(handshake.ExpiresAt) {
		return nil, errors.New("federation_service: outbound authentication tracking state expired")
	}

	// 2. STAGE 2: Resolve the specific IdP profile parameters from persistent schema storage
	idp, err := s.storage.GetIdentityProviderByUUID(ctx, cmd.TenantID, handshake.IdentityProviderID)
	if err != nil {
		return nil, fmt.Errorf("federation_service: target idp config unresolvable: %w", port.ErrIdentityProviderNotFound)
	}

	if !idp.Enabled {
		return nil, errors.New("federation_service: target provider instance is currently deactivated")
	}

	// STAGE 3: Execute back-channel token trade over the abstract driven port
	// Hydrate the parameters on the fly using stored handshake and configuration data
	oidcParams := port.OutboundOIDCParams{ // TODO Extend with more params, like acr request values?
		ClientID:         idp.Config.ClientID,
		RedirectURI:      handshake.CallbackURI, // Matches the exact redirect string registered upstream [3]
		TargetURI:        handshake.TargetURI,   // Preserves destination landing zone context [3]
		Scopes:           idp.Config.Scopes,     // Matches original requested scope vectors
		IdentityProvider: idp,                   // Enforces complete multi-tenant context passing
	}

	providerTokenSet, err := s.federationClient.ExchangeAuthorizationCode(
		ctx,
		idp.Config.TokenEndpoint,
		oidcParams,
		cmd.IncomingCode,
		handshake.CodeVerifier,
	)
	if err != nil {
		return nil, fmt.Errorf("federation_service: provider token swap failed: %w", err)
	}

	// Verify the external ID token integrity signatures against the provider's JWKS registry
	externalClaims, err := s.crypto.VerifyExternalTokenWithProvider(ctx, providerTokenSet.IDToken, idp.Config.JwksURI, idp.Issuer)
	if err != nil {
		return nil, fmt.Errorf("federation_service: cryptographic id token signature invalid: %w", err)
	}

	var upstreamACR string
	if acrVal, ok := externalClaims["acr"].(string); ok {
		upstreamACR = acrVal
	}

	var upstreamAMR []string
	if amrInterface, ok := externalClaims["amr"]; ok {
		if amrSlice, ok := amrInterface.([]any); ok {
			for _, val := range amrSlice {
				if str, ok := val.(string); ok {
					upstreamAMR = append(upstreamAMR, str)
				}
			}
		} else if amrStr, ok := amrInterface.(string); ok {
			upstreamAMR = strings.Split(amrStr, " ")
		}
	}

	// Calculate internal assurance levels via the centralized validator service.
	assurance := s.validator.TranslateIDPReachedLevels(idp, upstreamACR, upstreamAMR)

	// Generate downstream space-delimited ACR string configurations.
	tenant, err := s.storage.ResolveTenantByUUID(ctx, cmd.TenantID)
	if err != nil {
		return nil, fmt.Errorf("federation_service: failed to resolve tenant context: %w", err)
	}
	_ = s.validator.CompileSessionAssuranceToClientACR(tenant, idp, upstreamACR, upstreamAMR)

	// 4. STAGE 4: Identity Mapping and Security-Gated Auto-Linking [5.7]
	var targetUser *model.UserProfile
	now := s.clock.Now()

	// Strategy A: Direct Match lookup via existing coupled profile link record
	// Extract and assert the unique provider subject identifier (sub)
	subject, ok := externalClaims["sub"].(string)
	if !ok || subject == "" {
		return nil, errors.New("federation_service: assertion token validation failed - missing or invalid 'sub' claim")
	}
	identity, err := s.storage.GetUserIdentityByProviderAndExternalID(ctx, cmd.TenantID, handshake.PartitionID, idp.ID, subject)
	if err == nil {
		// Existing linkage established, query corresponding core profile
		targetUser, err = s.storage.GetUserProfileByID(ctx, cmd.TenantID, handshake.PartitionID, identity.UserProfileID)
		if err != nil {
			return nil, fmt.Errorf("federation_service: linked user profile missing from record: %w", port.ErrUserProfileNotFound)
		}
	} else {
		// Strategy B: Link missing. Assert strict security gates before checking email parity [5.7]
		email, ok := externalClaims["email"].(string)
		if !ok || email == "" {
			return nil, errors.New("federation_service: assertion token validation failed - missing or invalid 'email' claim")
		}

		emailVerified, _ := externalClaims["email_verified"].(bool)
		if !emailVerified {
			return nil, errors.New("federation_service: dynamic profile link blocked - external provider email is unverified")
		}

		// Look up account matching the verified email explicitly locked inside the handshake's target Partition [3.1]
		targetUser, err = s.storage.FindProfileByEmail(ctx, handshake.PartitionID, email)
		if err != nil {
			if idp.Config.AutoProvisionUser {
				// JIT Provision User Profile
				username := email
				displayName := ""
				if nameVal, ok := externalClaims["name"].(string); ok {
					displayName = nameVal
				} else if preferredVal, ok := externalClaims["preferred_username"].(string); ok {
					displayName = preferredVal
				} else {
					displayName = email
				}

				isEmailVerified := idp.Config.AutoVerifyEmail && emailVerified

				targetUser = &model.UserProfile{
					ID:                uuid.New(),
					TenantID:          cmd.TenantID,
					PartitionID:       handshake.PartitionID,
					Email:             email,
					EmailVerified:     isEmailVerified,
					PreferredUsername: username,
					Name:              displayName,
					LifecycleState:    model.LifecycleActivated,
					CreatedAt:         now,
					UpdatedAt:         now,
				}

				if errSave := s.storage.SaveUserProfile(ctx, cmd.TenantID, handshake.PartitionID, *targetUser); errSave != nil {
					return nil, fmt.Errorf("federation_service: failed to JIT provision user profile: %w", errSave)
				}
			} else {
				return nil, fmt.Errorf("federation_service: no matching system profile found to stitch account link against: %w", port.ErrUserProfileNotFound)
			}
		}

		// Strategy C: Structural Account stitching registration
		newLink := model.UserIdentity{
			ID:                 uuid.New(),
			UserProfileID:      targetUser.ID,
			IdentityProviderID: idp.ID,
			ExternalIdentityID: subject,
			CoupledAt:          now,
		}

		if err := s.storage.UpsertUserIdentity(ctx, cmd.TenantID, handshake.PartitionID, newLink); err != nil {
			return nil, fmt.Errorf("federation_service: failed to commit structural profile identity link context: %w", err)
		}
	}

	// Verify profile account state transitions before authorizing entrance permissions
	allowed, err := targetUser.IsLoginAllowed()
	if !allowed {
		return nil, err
	}

	// 6. STAGE 5: Persist upstream tokens

	// Default safety fallback lifespan (1 hour) if provider fails to pass implicit 'expires_in' metrics
	tokenLifespan := 15 * time.Minute
	if providerTokenSet.ExpiresIn > 0 {
		tokenLifespan = time.Duration(providerTokenSet.ExpiresIn) * time.Second
	}

	fedSessionRecord := model.FederatedSession{
		ID:                   uuid.New(), // Distinct tracking key allocated natively [5.7]
		TenantUUID:           cmd.TenantID,
		PartitionID:          handshake.PartitionID,
		SessionID:            cmd.SessionID, // Securely binds to our active native cookie session reference
		IdentityProviderID:   idp.ID,
		UpstreamSubject:      subject,
		UpstreamAccessToken:  providerTokenSet.AccessToken,
		UpstreamIDToken:      providerTokenSet.IDToken,
		UpstreamRefreshToken: providerTokenSet.RefreshToken,
		CreatedAt:            now,
		ExpiresAt:            now.Add(tokenLifespan), // Strictly locked to upstream expiration limits [6.3]
	}

	// Commit the cryptographic tracking payload securely to disk
	if err := s.storage.SaveFederatedSession(ctx, fedSessionRecord); err != nil {
		return nil, fmt.Errorf("federation_service: failed to commit federated session record tracking track: %w", err)
	}

	// 7. STAGE 6: Pack and return clean data boundaries back up to the caller ring [3.1, 5.7]
	return &port.FederatedCallbackResponse{
		UserProfileID:        targetUser.ID,
		UpstreamAccessToken:  providerTokenSet.AccessToken,  // Maps operational session parameters
		UpstreamIDToken:      providerTokenSet.IDToken,      // Preserved for the SLO id_token_hint parameter
		UpstreamRefreshToken: providerTokenSet.RefreshToken, // Preserved for background refresh access if needed
		PartitionID:          handshake.PartitionID,         // Preserves internal database int64 sequence column natively [3.1]
		TargetLandingURI:     handshake.TargetURI,           // Restores intended routing location gracefully [5.7]
		ReachedAAL:           assurance.AAL,
		ReachedIAL:           assurance.IAL,
	}, nil
}

// Private helper to prevent cross-service dependencies while retaining decoupling purity
//
//nolint:unused
func (s *FederationService) resolveFederatedLevels(config model.IdentityProviderConfig, externalAcr string, externalAmrs []string) (int, int) {
	resolvedAAL := config.AAL
	if resolvedAAL < 1 {
		resolvedAAL = 1
	}

	resolvedIAL := config.IAL
	if resolvedIAL < 1 {
		resolvedIAL = 1
	}

	if externalAcr != "" && config.AcrToTuple != nil {
		if tuple, exists := config.AcrToTuple[externalAcr]; exists {
			if tuple.AAL >= 1 && tuple.AAL <= 4 {
				resolvedAAL = tuple.AAL
			}
			if tuple.IAL >= 1 && tuple.IAL <= 4 {
				resolvedIAL = tuple.IAL
			}
		}
	}

	if config.AmrToAAL != nil {
		highestAMRMapped := 0
		for _, amr := range externalAmrs {
			cleanAmr := strings.ToLower(strings.TrimSpace(amr))
			if level, exists := config.AmrToAAL[cleanAmr]; exists && level > highestAMRMapped {
				highestAMRMapped = level
			}
		}
		if highestAMRMapped >= 1 && highestAMRMapped <= 4 && highestAMRMapped > resolvedAAL {
			resolvedAAL = highestAMRMapped
		}
	}

	return resolvedAAL, resolvedIAL
}
