package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TODO: Clean up port interfaces with just those methods used
// Reduce code complexity
// Optimize single database round trip
// Use a port for the route paths

var strictScopeSyntaxFilter = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\s]+$`)

type mintTokensCommand struct {
	PartitionAlias        string
	ClientID              string
	Subject               string
	SessionID             string
	Scopes                []string
	IdentityProviderID    uuid.UUID
	IdentityProviderAlias string
	ACR                   string
	AMR                   []string
	Confirmation          *model.Confirmation
	ExistingTokenFamilyID string
	OverrideAudiences     []string
	IsMachineToMachine    bool
	Application           *model.Application
	ApplicationProfile    *model.ApplicationProfile
	ApplicationGroup      *model.ApplicationGroup
}

type OAuthService struct {
	storage    port.Storage
	crypto     port.Crypto
	event      port.Event
	notifier   port.LogoutNotifier
	clock      port.Clock
	ssoUseCase port.SSOSessionUseCase
	validator  *OAuthValidatorService
}

func NewOAuthService(
	s port.Storage,
	c port.Crypto,
	e port.Event,
	n port.LogoutNotifier,
	cl port.Clock,
	sso port.SSOSessionUseCase,
	v *OAuthValidatorService,
) *OAuthService {
	return &OAuthService{
		storage:    s,
		crypto:     c,
		event:      e,
		notifier:   n,
		clock:      cl,
		ssoUseCase: sso,
		validator:  v,
	}
}

// ============================================================================
// DISCOVERY
// ============================================================================

func (s *OAuthService) ProcessDiscoveryMetadata(ctx context.Context, tenantID uuid.UUID, isOIDC bool) (*port.DiscoveryResponse, error) {
	tenant, err := s.storage.ResolveTenantByUUID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("oauth_service: tenant unresolvable: %w", err)
	}

	scopesSupported := tenant.Config.PredefinedScopes
	if len(scopesSupported) == 0 {
		scopesSupported = []string{"openid", "profile", "email", "offline_access"}
	}

	acrValues := make([]string, 0, len(tenant.Config.ACRToLevels))
	for acr := range tenant.Config.ACRToLevels {
		acrValues = append(acrValues, acr)
	}
	sort.Strings(acrValues)

	issuer := tenant.GetBaseURI()
	res := &port.DiscoveryResponse{
		Issuer:                             issuer,
		JWKSURI:                            issuer + "/.well-known/jwks.json",
		AuthorizationEndpoint:              issuer + "/oauth/authorize",
		TokenEndpoint:                      issuer + "/oauth/token",
		RegistrationEndpoint:               issuer + "/oauth/register",
		IntrospectionEndpoint:              issuer + "/oauth/introspect",
		RevocationEndpoint:                 issuer + "/oauth/revoke",
		PushedAuthorizationRequestEndpoint: issuer + "/oauth/par",
		AuthorizationResponseIssParameterSupported: true,
		ResponseTypesSupported:                     []string{"code"},
		ResponseModesSupported:                     []string{"query", "form_post"},
		GrantTypesSupported:                        []string{"authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"},
		ScopesSupported:                            scopesSupported,
		ACRValuesSupported:                         acrValues,
		TokenEndpointAuthMethodsSupported:          []string{"client_secret_basic", "client_secret_post", "none"},
		RevocationEndpointAuthMethodsSupported:     []string{"client_secret_basic", "client_secret_post", "none"},
		IntrospectionEndpointAuthMethodsSupported:  []string{"client_secret_basic", "client_secret_post"},
		DPoPSigningAlgValuesSupported:              []string{string(model.AlgRS256), string(model.AlgES256), string(model.AlgEdDSA)},
		CodeChallengeMethodsSupported:              []string{"S256"},
		RequestURIParameterSupported:               false,
		RequirePushedAuthorizationRequests:         false,
	}

	if isOIDC {
		res.UserInfoEndpoint = issuer + "/oauth/userinfo"
		res.EndSessionEndpoint = issuer + "/oauth/logout"
		res.FrontChannelLogoutSupported = true
		res.FrontChannelLogoutSessionSupported = true
		res.ClaimsSupported = []string{"sub", "name", "preferred_username", "email", "email_verified", "tid", "pid"}
		res.IDTokenSigningAlgValuesSupported = []string{string(model.AlgRS256), string(model.AlgES256)}
		res.SubjectTypesSupported = []string{"public"}
	}

	return res, nil
}

func (s *OAuthService) ProcessJWKSetRetrieval(ctx context.Context, tenantID uuid.UUID, host string, scheme string) (map[string]any, error) {
	_, err := s.storage.ResolveTenantByUUID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("oauth_service: tenant unresolvable: %w", err)
	}

	jwkSet, err := s.crypto.JWKSForTenant(ctx, host, scheme)
	if err != nil {
		return nil, fmt.Errorf("oauth_service: failed resolving keyset footprint: %w", err)
	}

	return map[string]any{
		"keys": jwkSet,
	}, nil
}

// ============================================================================
// AUTHORIZE & PAR CORE WORKFLOWS
// ============================================================================

// ProcessAuthorizeRequest coordinates the multi-stage validation, parameters consolidation,
// and execution routing for standard browser-initiated authorization requests.
func (s *OAuthService) ProcessAuthorizeRequest(ctx context.Context, cmd port.AuthorizeRequestCommand) (*port.AuthorizeExecutionResult, error) {
	if cmd.RequestURI != "" {
		if !strings.HasPrefix(cmd.RequestURI, model.URIPrefixPAR) {
			return nil, fmt.Errorf("%w: invalid request_uri scheme prefix", port.ErrInvalidRequest)
		}

		// Perform a destructive read: Atomically retrieve and delete the PAR cache allocation row
		par, err := s.getAndConsumePAR(ctx, cmd.TenantID, cmd.RequestURI)
		if err != nil {
			return nil, fmt.Errorf("%w: request_uri is invalid, expired, or replayed", port.ErrInvalidRequest)
		}

		// Prevent Client Impersonation / Parameter Tampering attacks [RFC 9126 Section 4]
		if cmd.ClientID != "" && cmd.ClientID != par.ClientID {
			return nil, fmt.Errorf("%w: client_id mismatch against pushed authorization session parameters", port.ErrInvalidClient)
		}

		// Re-map the state context elements cleanly onto our local execution variables
		cmd.ClientID = par.ClientID
		cmd.RedirectURI = par.RedirectURI
		cmd.CodeChallenge = par.CodeChallenge
		cmd.ChallengeMethod = par.ChallengeMethod
		cmd.IDPHint = par.IDPHint
		cmd.State = par.State
		cmd.Nonce = par.Nonce
		cmd.ACRValues = par.ACRValues
		cmd.Scopes = par.Scopes
	}

	if err := s.validator.ValidateState(ctx, cmd.State); err != nil {
		return nil, fmt.Errorf("%w: state parameters failed verification: %w", port.ErrInvalidRequest, err)
	}
	if cmd.ClientID == "" {
		return nil, fmt.Errorf("%w: client_id parameter is mandatory", port.ErrInvalidRequest)
	}

	tenant, err := s.storage.ResolveTenantByUUID(ctx, cmd.TenantID)
	if err != nil {
		return nil, fmt.Errorf("oauth_service: tenant unresolvable: %w", err)
	}

	app, profile, group, err := s.storage.GetApplicationByClientID(ctx, cmd.TenantID, cmd.ClientID)
	if err != nil {
		return nil, fmt.Errorf("%w: target application unresolvable: %w", port.ErrInvalidClient, err)
	}
	if app == nil || !app.IsEnabled {
		return nil, fmt.Errorf("%s: target application is disabled", port.ErrInvalidClient)
	}
	if group == nil || !group.IsEnabled {
		return nil, fmt.Errorf("%s: target application group is disabled", port.ErrInvalidClient)
	}
	if profile == nil || !profile.IsEnabled {
		return nil, fmt.Errorf("%s: target application profile is disabled", port.ErrInvalidClient)
	}

	// 2. Resolve optional redirect_uri fallbacks via pre-registered application groups
	redirectURI := cmd.RedirectURI
	if redirectURI == "" && group != nil {
		// First Track: Attempt to inherit the explicit scalar field definition
		if group.RedirectURI != "" {
			redirectURI = group.RedirectURI
		} else if len(group.RedirectURIs) > 0 {
			// Second Track: Fall back to the head entry of the whitelisted configuration slice array
			redirectURI = group.RedirectURIs[0]
		}
	}
	if redirectURI == "" {
		return nil, fmt.Errorf("%w: redirect_uri parameter missing and no pre-registered defaults exist", port.ErrInvalidRequest)
	}

	if err := s.validator.ValidateRedirect(ctx, tenant, group, redirectURI); err != nil {
		return nil, fmt.Errorf("%w: redirect_uri is not white-listed: %w", port.ErrInvalidRequest, err)
	}

	activeProvider, truePartitionID, err := s.resolveClientRouting(ctx, cmd.TenantID, group, cmd.IDPHint)
	if err != nil {
		return nil, fmt.Errorf("%w: structural routing calculation failed: %w", port.ErrInvalidRequest, err)
	}

	// Strict Multi-Partition Cookie isolation guard:
	// If the active session is associated with a different partition than the
	// client's target partition, treat the user as unauthenticated for this request.
	if cmd.ActiveSessionID != "" {
		parts := strings.Split(cmd.ActiveSessionID, ":")
		if len(parts) >= 2 {
			if parsedPartitionID, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				if parsedPartitionID != truePartitionID {
					cmd.ActiveSessionID = "" // Invalidate session context for this cross-partition request
				}
			} else {
				cmd.ActiveSessionID = "" // Malformed session ID, clear it
			}
		} else {
			cmd.ActiveSessionID = "" // Missing partition namespace, clear it
		}
	}

	now := s.clock.Now()
	// ------------------------------------------------------------------------
	// BRANCH A: User is unauthenticated -> Stage Interaction Session & Handshake
	// ------------------------------------------------------------------------
	if cmd.ActiveSessionID == "" {
		sessionACR := cmd.ACRValues
		if cmd.ClaimsJSON != "" {
			sessionACR = cmd.ClaimsJSON
		}

		interaction := model.InteractionSession{
			ID:              uuid.New(),
			TenantID:        cmd.TenantID,
			PartitionID:     truePartitionID,
			ClientID:        cmd.ClientID,
			RedirectURI:     redirectURI,
			CodeChallenge:   cmd.CodeChallenge,
			ChallengeMethod: cmd.ChallengeMethod,
			IDPHint:         cmd.IDPHint,
			ExpiresAt:       now.Add(10 * time.Minute),
			State:           cmd.State,
			Nonce:           cmd.Nonce,
			ACRValues:       sessionACR, // TODO Add AMR
		}

		// Persist strictly as an internal Interaction Session.
		if err := s.storage.SaveInteractionSession(ctx, interaction); err != nil {
			return nil, fmt.Errorf("oauth_service: transient session storage failure: %w", err)
		}

		// Call SSOSessionUseCase driven port interface directly to build the response cookie configuration.
		// The service now passes raw parameters down-funnel, staying agnostic to string parsing formats or transport security tags.
		cookieIntent, err := s.ssoUseCase.BuildSessionCookie(ctx, port.CookieIntentCommand{
			TenantID:       cmd.TenantID,
			PartitionID:    truePartitionID,
			PayloadValue:   interaction.ID.String(),
			LifecycleStage: "handshake",
			RequestHost:    cmd.RequestHost,
		})
		if err != nil {
			return nil, fmt.Errorf("oauth_service: cookie metadata generation failed: %w", err)
		}

		return &port.AuthorizeExecutionResult{
			Action:          port.ActionRedirectToLoginUI,
			RedirectURL:     port.RouteWebLogin + "?tx=" + interaction.ID.String(),
			HasCookieIntent: true,
			CookieName:      cookieIntent.CookieName,
			CookieValue:     cookieIntent.CookieValue,
			CookieMaxAge:    cookieIntent.MaxAge,
			CookieSecure:    cookieIntent.Secure,
		}, nil
	}

	// ------------------------------------------------------------------------
	// BRANCH B: User is authenticated -> Generate Single-Use Authorization Code
	// ------------------------------------------------------------------------
	code := uuid.NewString()
	reachedACR := s.validator.CompileSessionAssuranceToClientACR(tenant, activeProvider, "", nil)
	if reachedACR == "" {
		reachedACR = "aal1" // TODO Review if this should be empty otherwise
	}

	parts := strings.Split(cmd.ActiveSessionID, ":")
	subjectID := cmd.ClientID
	if len(parts) >= 1 {
		subjectID = parts[0]
	}

	if len(cmd.Scopes) > 0 {
		if err := s.validator.ValidateScopes(ctx, tenant, group, cmd.Scopes); err != nil {
			return nil, fmt.Errorf("%w: requested scopes deviate from whitelists: %w", port.ErrInvalidRequest, err)
		}
	}

	grantedScopes := cmd.Scopes
	if len(grantedScopes) == 0 {
		grantedScopes = group.DefaultScopes
	}

	authSession := model.AuthorizationCodeSession{
		Code:                  code,
		TenantID:              cmd.TenantID,
		PartitionID:           truePartitionID,
		ClientID:              cmd.ClientID,
		Subject:               subjectID,
		CodeChallenge:         cmd.CodeChallenge,
		ChallengeMethod:       cmd.ChallengeMethod,
		RedirectURI:           redirectURI,
		Scopes:                grantedScopes,
		ExpiresAt:             now.Add(5 * time.Minute),
		SessionID:             cmd.ActiveSessionID,
		State:                 cmd.State,
		Nonce:                 cmd.Nonce,
		IdentityProviderID:    activeProvider.ID,
		IdentityProviderAlias: activeProvider.Alias,
		ACRValues:             reachedACR, // TODO Add AMR
	}

	if err := s.saveAuthSession(ctx, authSession); err != nil {
		return nil, fmt.Errorf("oauth_service: authorization code storage failure: %w", err)
	}

	v := url.Values{}
	v.Set("code", code)
	if cmd.State != "" {
		v.Set("state", cmd.State)
	}
	v.Set("iss", tenant.GetBaseURI())

	finalRedirectURL := redirectURI
	if strings.Contains(finalRedirectURL, "?") {
		finalRedirectURL += "&" + v.Encode()
	} else {
		finalRedirectURL += "?" + v.Encode()
	}

	return &port.AuthorizeExecutionResult{
		Action:          port.ActionEmitAuthorizationCode,
		RedirectURL:     finalRedirectURL,
		HasCookieIntent: false,
	}, nil
}

func (s *OAuthService) saveAuthSession(ctx context.Context, session model.AuthorizationCodeSession) error {
	if session.Code == "" {
		return errors.New("authorize code must not be empty")
	}
	if session.RedirectURI == "" {
		return errors.New("redirect_uri must not be empty")
	}
	return s.storage.SaveAuthSession(ctx, session)
}

func (s *OAuthService) savePAR(ctx context.Context, req model.PushedAuthorizationRequest) error {
	return s.storage.SavePAR(ctx, req)
}

func (s *OAuthService) getAndConsumePAR(ctx context.Context, tenantID uuid.UUID, requestURI string) (*model.PushedAuthorizationRequest, error) {
	return s.storage.GetAndConsumePAR(ctx, tenantID, requestURI)
}

// mintTokensFromSession converts an authorized authentication context into a signed stateless JWT pair [5.7].
func (s *OAuthService) mintTokensFromSession(ctx context.Context, tenant *model.Tenant, cmd mintTokensCommand) (*model.TokenSetResponse, error) {
	// 1. Fetch the target application metadata profile to compute accurate lifetimes
	app := cmd.Application
	profile := cmd.ApplicationProfile
	group := cmd.ApplicationGroup

	if app == nil || profile == nil || group == nil {
		ap, pr, gr, err := s.storage.GetApplicationByClientID(ctx, tenant.ID, cmd.ClientID)
		if err != nil {
			return nil, fmt.Errorf("oauth_service: target client application unresolvable: %w", err)
		}
		app = ap
		profile = pr
		group = gr
	}

	// Ironclad Safety Gate: Deny token rotation if any single entity node is administratively suspended [5.7]
	if app == nil || !app.IsEnabled {
		return nil, fmt.Errorf("%w: target application is disabled", port.ErrInvalidGrant)
	}
	if group == nil || !group.IsEnabled {
		return nil, fmt.Errorf("%w: target application group is disabled", port.ErrInvalidGrant)
	}
	if profile == nil || !profile.IsEnabled {
		return nil, fmt.Errorf("%w: target application profile is disabled", port.ErrInvalidGrant)
	}

	now := s.clock.Now()
	accessTokenExpiration := now.Add(profile.AccessTokenLifetime)
	idTokenExpiration := now.Add(profile.IDTokenLifetime)
	refreshTokenExpiration := now.Add(profile.RefreshTokenLifetime)

	// Compile target audiences dynamically if not explicitly overridden [5.7]
	targetAudiences := cmd.OverrideAudiences
	if len(targetAudiences) == 0 {
		targetAudiences = []string{cmd.ClientID}
		if len(group.AllowedAudiences) > 0 {
			for _, aud := range group.AllowedAudiences {
				if aud != cmd.ClientID {
					targetAudiences = append(targetAudiences, aud)
				}
			}
		}
	}

	// 2. Assemble Token Claims utilizing the flattened embedded BaseTokenClaims layout format

	if cmd.IsMachineToMachine {
		// No human actor is involved
		cmd.ACR = ""
		cmd.AMR = nil
		cmd.PartitionAlias = ""
	}

	accessTokenClaims := model.TokenClaims{
		BaseTokenClaims: model.BaseTokenClaims{
			Issuer:                tenant.GetBaseURI(),
			Subject:               cmd.Subject,
			ExpiresAt:             accessTokenExpiration.Unix(),
			IssuedAt:              now.Unix(),
			TokenID:               uuid.New().String(),
			TenantID:              tenant.ID,
			ClientID:              cmd.ClientID,
			SessionID:             cmd.SessionID,
			IdentityProviderID:    cmd.IdentityProviderID,
			IdentityProviderAlias: cmd.IdentityProviderAlias,
			ACR:                   cmd.ACR,
			AMR:                   cmd.AMR,
			Confirmation:          cmd.Confirmation,
		},
		Audiences:      targetAudiences,
		PartitionAlias: cmd.PartitionAlias,
		Scopes:         cmd.Scopes,
	}

	// 3. Cryptographically sign the target access token via the driving ports layer
	signedAccessToken, err := s.crypto.SignAccessToken(ctx, accessTokenClaims, profile.SigningAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("oauth_service: access token signature sequence failed: %w", err)
	}

	var signedIDToken string
	var refreshTokenID string

	if !cmd.IsMachineToMachine {
		// ------------------------------------------------------------------------
		// OIDC ID TOKEN GENERATION PIPELINE (OIDCTokenClaims) [5.7]
		// ------------------------------------------------------------------------
		isOpenIDRequested := false
		for _, sc := range cmd.Scopes {
			if sc == "openid" {
				isOpenIDRequested = true
				break
			}
		}

		if isOpenIDRequested {
			parsedSubUUID, err := uuid.Parse(cmd.Subject)
			if err == nil {
				// Pull user details securely scoping via the stateless alias partition filter
				userProfile, _ := s.storage.GetUserProfileByIDAndPartitionAlias(ctx, tenant.ID, cmd.PartitionAlias, parsedSubUUID)

				idTokenClaims := model.OIDCTokenClaims{
					BaseTokenClaims: model.BaseTokenClaims{
						Issuer:                tenant.GetBaseURI(),
						Subject:               cmd.Subject,
						ExpiresAt:             idTokenExpiration.Unix(),
						IssuedAt:              now.Unix(),
						TokenID:               uuid.New().String(),
						TenantID:              tenant.ID,
						ClientID:              cmd.ClientID,
						SessionID:             cmd.SessionID,
						IdentityProviderID:    cmd.IdentityProviderID,
						IdentityProviderAlias: cmd.IdentityProviderAlias,
						ACR:                   cmd.ACR,
						AMR:                   cmd.AMR,
						Confirmation:          cmd.Confirmation,
					},
					Audience: cmd.ClientID, // OIDC tokens are always bound to the clientID as audience
					AuthTime: now.Unix(),   // Binds local baseline token completion anchor
				}

				if userProfile != nil {
					idTokenClaims.Name = userProfile.Name
					idTokenClaims.GivenName = userProfile.FirstName
					idTokenClaims.FamilyName = userProfile.LastName
					idTokenClaims.PreferredUsername = userProfile.PreferredUsername
					idTokenClaims.Email = userProfile.Email
					idTokenClaims.EmailVerified = userProfile.EmailVerified
				}

				signedIDToken, err = s.crypto.SignIDToken(ctx, idTokenClaims, cmd.Scopes, profile.SigningAlgorithm)
				if err != nil {
					return nil, fmt.Errorf("oauth_service: failed to sign oidc id_token payload: %w", err)
				}
			}
		}

		// 4. Structure and persist the Single-Use Refresh Token track to the database registry
		rtBuffer := make([]byte, 32)
		if _, err := rand.Read(rtBuffer); err != nil {
			return nil, fmt.Errorf("oauth_service: random bytes generation failure: %w", err)
		}
		refreshTokenID = base64.RawURLEncoding.EncodeToString(rtBuffer)

		tokenFamilyID := cmd.ExistingTokenFamilyID
		if tokenFamilyID == "" {
			familyBuffer := make([]byte, 32)
			if _, err := rand.Read(familyBuffer); err == nil {
				tokenFamilyID = base64.RawURLEncoding.EncodeToString(familyBuffer)
			}
		}

		dbRefreshToken := model.RefreshToken{
			TokenID:               refreshTokenID,
			TenantID:              tenant.ID,
			ClientID:              cmd.ClientID,
			Subject:               cmd.Subject,
			Scopes:                cmd.Scopes,
			TokenFamilyID:         tokenFamilyID,
			IsUsed:                false,
			ExpiresAt:             refreshTokenExpiration,
			CreatedAt:             now,
			IdentityProviderID:    cmd.IdentityProviderID,
			IdentityProviderAlias: cmd.IdentityProviderAlias,
			SessionID:             cmd.SessionID,
		}

		if err := s.storage.SaveRefreshToken(ctx, dbRefreshToken); err != nil {
			return nil, fmt.Errorf("oauth_service: failed to log token lineage tracking state: %w", err)
		}
	}

	return &model.TokenSetResponse{
		AccessToken:  signedAccessToken,
		IDToken:      signedIDToken,
		RefreshToken: refreshTokenID,
		TokenType:    "Bearer",
		ExpiresIn:    int64(profile.AccessTokenLifetime.Seconds()),
	}, nil
}

// ExchangeCodeForTokens executes Use Case 3.1: Authorization Code Exchange with PKCE validation & PID injection
func (s *OAuthService) ExchangeCodeForTokens(
	ctx context.Context,
	cmd port.ExchangeCodeForTokensCommand,
) (*model.TokenSetResponse, error) {
	now := s.clock.Now()

	// 1. Destructive Read: Atomically fetch and consume the authorization session to prevent replay vectors
	authSession, err := s.storage.GetAndConsumeAuthSession(ctx, cmd.TenantID, cmd.Code)
	if err != nil {
		return nil, fmt.Errorf("%w: code is invalid, used, or mismatched: %w", port.ErrInvalidGrant, err)
	}

	// 2. Temporal Guardrail: Assert code validity window (standard maximum 5-minute ceiling)
	if now.After(authSession.ExpiresAt) {
		return nil, fmt.Errorf("%w: authorization code has expired", port.ErrInvalidGrant)
	}

	// 3. Structural Boundary Verification: Validate client matching context rules
	if authSession.ClientID != cmd.ClientID {
		return nil, fmt.Errorf("%w: client identity context mismatch", port.ErrInvalidGrant)
	}

	// 4. Cryptographic Validation Layer: Enforce High-Entropy PKCE S256 Verifier verification
	if authSession.CodeChallenge != "" {
		if cmd.CodeVerifier == "" {
			return nil, fmt.Errorf("%w: missing mandatory code_verifier parameter", port.ErrInvalidGrant)
		}

		// Compute the S256 digest transformation loop over the incoming verifier string
		hashDigest := sha256.Sum256([]byte(cmd.CodeVerifier))
		computedChallenge := base64.RawURLEncoding.EncodeToString(hashDigest[:])

		if authSession.CodeChallenge != computedChallenge {
			return nil, fmt.Errorf("%w: pkce code verification challenge mismatch", port.ErrInvalidGrant)
		}
	}

	// 5. Dual-Track Namespace Translation: Resolve raw database PartitionID to stateless wire-level Alias
	partition, err := s.storage.GetPartitionByID(ctx, cmd.TenantID, authSession.PartitionID)
	if err != nil {
		return nil, fmt.Errorf("oauth_service: internal partition context unresolved: %w", err)
	}

	tenant := cmd.Tenant
	if tenant == nil {
		tn, err := s.storage.ResolveTenantByUUID(ctx, cmd.TenantID)
		if err != nil {
			return nil, fmt.Errorf("oauth_service: multi-tenant structural boundaries missing: %w", err)
		}
		tenant = tn
	}

	// 6. Session to client tracking [Section 7.2]
	// Dynamically register that this client application is actively participating inside this SSO session loop
	if authSession.SessionID != "" {
		if err := s.storage.RecordClientSessionLink(ctx, cmd.TenantID, authSession.SessionID, cmd.ClientID, now); err != nil {
			return nil, fmt.Errorf("oauth_service: failed to log client session association: %w", err)
		}
	}

	// 7. Invoke our consolidated token emission routine using the type-safe command structure [1.14]
	// Sourced flatly out of your temporary database storage row object, carrying forward both ACR and AMR footprints.
	return s.mintTokensFromSession(ctx, tenant, mintTokensCommand{
		PartitionAlias:        partition.AliasName,
		ClientID:              cmd.ClientID,
		Subject:               authSession.Subject,
		SessionID:             authSession.SessionID,
		Scopes:                authSession.Scopes,
		IdentityProviderID:    authSession.IdentityProviderID,
		IdentityProviderAlias: authSession.IdentityProviderAlias,
		ACR:                   authSession.ACRValues, // Pre-calculated system string injected natively
		AMR:                   authSession.AMRValues, // Verified authenticators list array injected natively
		Confirmation:          nil,                   // No confirmation thumbprint signatures during initial basic code trades
		ExistingTokenFamilyID: "",                    // Triggers fresh tree lineage family generation
		OverrideAudiences:     nil,                   // Triggers database application group compilation [5.7]
		Application:           cmd.Application,
		ApplicationProfile:    cmd.ApplicationProfile,
		ApplicationGroup:      cmd.ApplicationGroup,
	})
}

// RotateRefreshToken executes Use Case 3.2: Single-use Refresh Token Rotation using live Access Token claims [5.7]
func (s *OAuthService) RotateRefreshToken(
	ctx context.Context,
	cmd port.RotateRefreshTokenCommand,
) (*model.TokenSetResponse, error) {
	// 1. Verify and unpack the raw token string using the injected Crypto adapter port
	claimsMap, err := s.crypto.VerifyToken(cmd.RefreshToken)
	if err != nil {
		return nil, port.ErrInvalidGrant // Invalid signature or expired token lifetime window
	}

	// 2. Map the raw dictionary into standard type-safe domain structures via your helper
	tokenClaims := s.mapMapClaimsToTokenClaims(cmd.TenantID, claimsMap)

	// 3. Map raw claims map fields type-safely into internal primitives
	jti, _ := claimsMap["jti"].(string)
	familyID, _ := claimsMap["fid"].(string) // Assumes 'fid' maps the immutable TokenFamilyID

	if jti == "" || familyID == "" {
		return nil, port.ErrInvalidGrant
	}

	// 4. Fetch the lean reference tracking row from the database registry [7.3]
	tokenRecord, err := s.storage.GetRefreshToken(ctx, cmd.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("%s: refresh token is unrecognized or invalid: %w", port.ErrInvalidGrant, err)
	}

	// 5. Strict Boundary Verification: Validate multi-tenant and client mapping contexts
	if tokenRecord.TenantID != cmd.TenantID || tokenRecord.ClientID != cmd.ClientID {
		return nil, fmt.Errorf("%s: access token context boundary violation", port.ErrInvalidGrant)
	}

	// 7. Structural Replay Verification: Confirm the incoming Refresh Token is bound to this specific Access Token session
	if tokenRecord.SessionID != tokenClaims.SessionID {
		return nil, fmt.Errorf("%s: session tracking token mismatch", port.ErrInvalidGrant)
	}

	// 8. Temporal Guardrail: Assert token validity window has not expired
	if s.clock.Now().After(tokenRecord.ExpiresAt) {
		return nil, fmt.Errorf("%s: refresh token has expired", port.ErrInvalidGrant)
	}

	// ------------------------------------------------------------------------
	// AUTOMATED BREACH ESCALATION TRAP (RTR REUSE DETECTION) [5.7]
	// ------------------------------------------------------------------------
	if tokenRecord.IsUsed {
		_ = s.storage.RevokeRefreshTokenFamily(ctx, tokenRecord.TokenFamilyID)

		if tokenRecord.SessionID != "" {
			_ = s.storage.RevokeSession(ctx, cmd.TenantID, tokenRecord.Subject, cmd.ClientID)
		}

		return nil, fmt.Errorf("%s: structural compromise detected - token family revoked", port.ErrInvalidGrant)
	}

	// 9. Mark the incoming leaf node as used immediately before minting new children (Destructive Update)
	if err := s.storage.MarkRefreshTokenUsed(ctx, cmd.RefreshToken); err != nil {
		return nil, fmt.Errorf("oauth_service: token status invalidation pass failed: %w", err)
	}

	// 10. Gather multi-tenant metadata to resolve stateless wire properties
	tenant := cmd.Tenant
	if tenant == nil {
		tn, err := s.storage.ResolveTenantByUUID(ctx, cmd.TenantID)
		if err != nil {
			return nil, fmt.Errorf("oauth_service: multi-tenant structural boundaries missing: %w", err)
		}
		tenant = tn
	}

	// 11. Mint rotated sliding child tokens while preserving historical lineage anchors [1.14]
	return s.mintTokensFromSession(ctx, tenant, mintTokensCommand{
		PartitionAlias:        tokenClaims.PartitionAlias, // Inherited zero-lookup partition propagation [5.7]
		ClientID:              cmd.ClientID,
		Subject:               tokenRecord.Subject,
		SessionID:             tokenRecord.SessionID,
		Scopes:                tokenRecord.Scopes,
		IdentityProviderID:    tokenRecord.IdentityProviderID,
		IdentityProviderAlias: tokenRecord.IdentityProviderAlias,
		ACR:                   tokenClaims.ACR,           // Inherited zero-lookup trust carryover [5.7]
		AMR:                   tokenClaims.AMR,           // Inherited zero-lookup trust carryover [5.7]
		Confirmation:          tokenClaims.Confirmation,  // Pass forward proof-of-possession parameters if active
		ExistingTokenFamilyID: tokenRecord.TokenFamilyID, // Retain historical lineage family anchor
		OverrideAudiences:     tokenClaims.Audiences,     // Inherited zero-lookup audience footprint arrays [5.7]
		Application:           cmd.Application,
		ApplicationProfile:    cmd.ApplicationProfile,
		ApplicationGroup:      cmd.ApplicationGroup,
	})
}

func (s *OAuthService) mapMapClaimsToTokenClaims(tenantID uuid.UUID, claims map[string]any) model.TokenClaims {
	sub, _ := claims["sub"].(string)
	sid, _ := claims["sid"].(string)
	pid, _ := claims["pid"].(string)
	azp, _ := claims["azp"].(string)
	acr, _ := claims["acr"].(string)

	var auds []string
	if rawAud, exists := claims["aud"]; exists {
		if single, ok := rawAud.(string); ok {
			auds = []string{single}
		} else if slice, ok := rawAud.([]any); ok {
			for _, a := range slice {
				if str, ok := a.(string); ok {
					auds = append(auds, str)
				}
			}
		}
	}

	return model.TokenClaims{
		BaseTokenClaims: model.BaseTokenClaims{
			Subject:   sub,
			SessionID: sid,
			TenantID:  tenantID,
			ClientID:  azp,
			ACR:       acr,
		},
		Audiences:      auds,
		PartitionAlias: pid,
	}
}

// ExchangeExternalToken executes an RFC 8693 compliant Token Exchange workflow,
// translating external provider assertions into native stateless system token sets [5.7].
func (s *OAuthService) ExchangeExternalToken(
	ctx context.Context,
	tenantID uuid.UUID,
	clientID string,
	subjectToken string,
	subjectTokenType model.TokenType,
) (*model.TokenSetResponse, error) {
	slog.Debug("ExchangeExternalToken: starting token exchange", "tenant_id", tenantID, "client_id", clientID, "subject_token_type", subjectTokenType)

	// 1. Enforce strict RFC 8693 standard incoming subject token profile constraints [5.7]
	if subjectTokenType != model.TokenTypeIDToken {
		slog.Error("ExchangeExternalToken: unsupported subject token type profile", "type", subjectTokenType)
		return nil, fmt.Errorf("%s: unsupported subject token type profile", port.ErrInvalidGrant)
	}

	// 2. Destructive Read: Parse the incoming token unverified to extract its cryptographic issuer claim safely [5.7]
	parser := jwt.NewParser()
	unverifiedToken, _, err := parser.ParseUnverified(subjectToken, jwt.MapClaims{})
	if err != nil {
		slog.Error("ExchangeExternalToken: structural token decoding failed", "err", err)
		return nil, fmt.Errorf("%s: structural token decoding failed: %w", port.ErrInvalidGrant, err)
	}

	unverifiedClaims, ok := unverifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		slog.Error("ExchangeExternalToken: corrupt token claims container layout")
		return nil, fmt.Errorf("%s: corrupt token claims container layout", port.ErrInvalidGrant)
	}

	rawIssuer, _ := unverifiedClaims["iss"].(string)
	rawEmail, _ := unverifiedClaims["email"].(string)
	slog.Debug("ExchangeExternalToken: unverified token claims extracted", "iss", rawIssuer, "email", rawEmail)
	if rawIssuer == "" {
		slog.Error("ExchangeExternalToken: token is missing mandatory issuer identity assertions")
		return nil, fmt.Errorf("%s: token is missing mandatory issuer identity assertions", port.ErrInvalidGrant)
	}

	// 3. Resolve and verify the specific Identity Provider by its explicit issuer string [5.7]
	activeProvider, err := s.matchIdentityProvider(ctx, tenantID, rawIssuer, rawEmail)
	if err != nil {
		slog.Error("ExchangeExternalToken: external token issuer unrecognized or unmapped", "iss", rawIssuer, "err", err)
		return nil, fmt.Errorf("%s: external token issuer is unrecognized or unmapped for this tenant: %w", port.ErrInvalidGrant, err)
	}

	slog.Debug("ExchangeExternalToken: matched identity provider", "id", activeProvider.ID, "alias", activeProvider.Alias, "partition_id", activeProvider.PartitionID)

	if !activeProvider.Enabled {
		slog.Error("ExchangeExternalToken: resolved federated identity provider is administratively deactivated", "id", activeProvider.ID)
		return nil, fmt.Errorf("%s: resolved federated identity provider is administratively deactivated", port.ErrInvalidGrant)
	}

	// 4. Cryptographic Validation: Verify asymmetric signatures against the securely resolved provider parameters [5.7]
	externalClaims, err := s.crypto.VerifyExternalTokenWithProvider(ctx, subjectToken, activeProvider.Config.JwksURI, activeProvider.Issuer)
	if err != nil {
		slog.Error("ExchangeExternalToken: cryptographic token signature verification failed", "jwks", activeProvider.Config.JwksURI, "issuer", activeProvider.Issuer, "err", err)
		return nil, fmt.Errorf("%s: cryptographic token signature verification failed: %w", port.ErrInvalidGrant, err)
	}

	subject, _ := externalClaims["sub"].(string)
	email, _ := externalClaims["email"].(string)
	emailVerified, _ := externalClaims["email_verified"].(bool)
	slog.Debug("ExchangeExternalToken: cryptographic signature verified successfully", "sub", subject, "email", email, "email_verified", emailVerified)

	if subject == "" || email == "" {
		slog.Error("ExchangeExternalToken: external identity assertions missing mandatory subject or email mapping credentials")
		return nil, fmt.Errorf("%s: external identity assertions missing mandatory subject mapping credentials", port.ErrInvalidGrant)
	}

	// 5. Fetch client metadata profiles to enforce lifecycle security gates and gather whitelists [5.7]
	app, profile, group, err := s.storage.GetApplicationByClientID(ctx, tenantID, clientID)
	if err != nil {
		slog.Error("ExchangeExternalToken: target client application unresolvable", "client_id", clientID, "err", err)
		return nil, fmt.Errorf("oauth_service: target client application unresolvable: %w", err)
	}

	if app == nil || !app.IsEnabled || group == nil || !group.IsEnabled || profile == nil || !profile.IsEnabled {
		slog.Error("ExchangeExternalToken: target application architecture context is deactivated", "client_id", clientID)
		return nil, fmt.Errorf("%s: target application architecture context is deactivated", port.ErrInvalidGrant)
	}

	// Enforce that the application group is strictly bound to this Identity Provider [5.7]
	idpPermitted := false
	slog.Debug("ExchangeExternalToken: verifying group allowed IDPs", "group_id", group.ID, "group_name", group.GroupName, "allowed_ids", group.AllowedIDPIDs, "provider_id", activeProvider.ID)
	for _, allowedIDP := range group.AllowedIDPIDs {
		if allowedIDP == activeProvider.ID {
			idpPermitted = true
			break
		}
	}
	if !idpPermitted {
		slog.Error("ExchangeExternalToken: identity provider is not authorized for use with this application client group", "group_allowed", group.AllowedIDPIDs, "provider_id", activeProvider.ID)
		return nil, fmt.Errorf("%w: identity provider is not authorized for use with this application client group", port.ErrInvalidGrant)
	}

	// 6. Namespace Translation: Resolve partition tracking models to pass string aliases forward to tokens [5.7]
	partition, err := s.storage.GetPartitionByID(ctx, tenantID, activeProvider.PartitionID)
	if err != nil {
		slog.Error("ExchangeExternalToken: failed to resolve partition tracking metadata", "partition_id", activeProvider.PartitionID, "err", err)
		return nil, fmt.Errorf("oauth_service: failed to resolve partition tracking metadata: %w", err)
	}

	// 7. Search local records strictly within the matched provider's specific PartitionID [5.7]
	userProfile, err := s.findUserProfile(ctx, tenantID, activeProvider, subject, email, emailVerified)
	if err != nil {
		return nil, fmt.Errorf("%s: profile correlation or linkage registration rejected: %w", port.ErrInvalidGrant, err)
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
		}
	}

	// Generate fresh session lineage anchors for token exchange branches
	sessionID := uuid.NewString()
	now := s.clock.Now()

	// 8. Session to client tracking [Section 5.7]
	// Dynamically register that this federated identity entrance binds the app to single sign-out rules
	if err := s.storage.RecordClientSessionLink(ctx, tenantID, sessionID, clientID, now); err != nil {
		return nil, fmt.Errorf("oauth_service: failed to log client session association during exchange: %w", err)
	}

	tenant, err := s.storage.ResolveTenantByUUID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("oauth_service: failed to resolve tenant boundaries: %w", err)
	}

	// 9. Mint native tokens, passing group whitelisted audiences forward statelessly [1.14, 5.7]
	return s.mintTokensFromSession(ctx, tenant, mintTokensCommand{
		PartitionAlias:        partition.AliasName,
		ClientID:              clientID,
		Subject:               userProfile.ID.String(),
		SessionID:             sessionID,
		Scopes:                []string{"openid", "profile", "email"},
		IdentityProviderID:    activeProvider.ID,
		IdentityProviderAlias: activeProvider.Alias,
		ACR:                   upstreamACR,
		AMR:                   upstreamAMR,
		Confirmation:          nil,
		ExistingTokenFamilyID: "",
		OverrideAudiences:     group.AllowedAudiences, // Inherit whitelisted microservice resource footprints statelessly
		Application:           app,
		ApplicationProfile:    profile,
		ApplicationGroup:      group,
	})
}

// ExchangeClientCredentials executes machine-to-machine OAuth2 token issuance loops securely.
func (s *OAuthService) ExchangeClientCredentials(ctx context.Context, cmd port.ExchangeClientCredentialsCommand) (*model.TokenSetResponse, error) {
	// 1. Fetch client metadata context structures from storage to verify the grant capability ceiling
	profile := cmd.ApplicationProfile
	group := cmd.ApplicationGroup
	if profile == nil || group == nil {
		_, pr, gr, err := s.storage.GetApplicationByClientID(ctx, cmd.TenantID, cmd.ClientID)
		if err != nil {
			return nil, fmt.Errorf("oauth_service: client credentials target client unresolvable: %w", err)
		}
		profile = pr
		group = gr
	}

	// 2. Enforce that client credentials grant is explicitly whitelisted for this application profile
	grantAllowed := false
	for _, gt := range profile.GrantTypes {
		if gt == model.GrantTypeClientCredentials {
			grantAllowed = true
			break
		}
	}
	if !grantAllowed {
		return nil, fmt.Errorf("%w: client_credentials grant type not allowed for this client profile", port.ErrInvalidGrant)
	}

	// 3. Multi-Tenant Structural Boundaries Check
	tenant := cmd.Tenant
	if tenant == nil {
		tn, err := s.storage.ResolveTenantByUUID(ctx, cmd.TenantID)
		if err != nil {
			return nil, fmt.Errorf("oauth_service: multi-tenant structural boundaries missing: %w", err)
		}
		tenant = tn
	}

	// 4. DELEGATE: Mint native machine tokens with completely zeroed out/nil IdP parameters and empty PartitionAlias.
	// This forces the minting routine to omit the 'pid' claim while providing the authoritative 'tid' claim.
	return s.mintTokensFromSession(ctx, tenant, mintTokensCommand{
		PartitionAlias:        "", // No human actor involved
		ClientID:              cmd.ClientID,
		Subject:               cmd.ClientID,        // For machine tokens, the subject is the ClientID itself (RFC 6749)
		SessionID:             uuid.NewString(),    // Allocate a fresh tracking anchor for the backend lineage
		Scopes:                group.DefaultScopes, // Default to pre-whitelisted backend scopes configured on the group
		IdentityProviderID:    uuid.Nil,            // No IDP involved
		IdentityProviderAlias: "",
		ACR:                   "",  // ACR does not apply for M2M tokens
		AMR:                   nil, // AMR does not apply for M2M tokens
		Confirmation:          nil,
		ExistingTokenFamilyID: "",
		OverrideAudiences:     group.AllowedAudiences, // Inherit microservice resource audience footprints statelessly
		IsMachineToMachine:    true,                   // Suppresses generation of Refresh and ID Tokens completely
	})
}

// ProcessLogoutRequest completely orchestrates specification-driven OIDC Single Sign-Out workflows,
// invalidating native persistence sessions, querying active client session footprints,
// and triggering non-blocking asynchronous backchannel logout propagations strictly to active apps.
func (s *OAuthService) ProcessLogoutRequest(ctx context.Context, cmd port.LogoutRequestCommand) (*port.LogoutExecutionResult, error) {
	tenant, err := s.storage.ResolveTenantByUUID(ctx, cmd.TenantID)
	if err != nil {
		return nil, fmt.Errorf("oauth_service: tenant unresolvable: %w", err)
	}

	// 1. Establish the Session Invalidation Lookup Hierarchy
	var targetSessionID = cmd.ActiveSessionID // Default fallback to cookie session context

	// OIDC Spec Compliance: Prioritize id_token_hint parsing if present
	if cmd.IDTokenHint != "" {
		if verifiedClaims, err := s.crypto.VerifyToken(cmd.IDTokenHint); err == nil {
			if tokenSID, ok := verifiedClaims["sid"].(string); ok && tokenSID != "" {
				targetSessionID = tokenSID
			} else if tokenSUB, ok := verifiedClaims["sub"].(string); ok && tokenSUB != "" {
				// Secondary Track: Fallback to subject verification if sid is omitted statelessly
				targetSessionID = tokenSUB
			}
		}
	}

	var subjectID string
	var partitionID int64

	// 2. Unpack tracking claims to locate the parent profile and partition lineage
	if targetSessionID != "" {
		parts := strings.Split(targetSessionID, ":")
		if len(parts) >= 2 {
			subjectID = parts[0]
			if pID, parseErr := strconv.ParseInt(parts[1], 10, 64); parseErr == nil {
				partitionID = pID
			}
		}
	}

	var frontChannelURIs []string

	// 3. Perform targeted session teardown and trigger out-of-band fan-outs if session attributes are valid
	if subjectID != "" && targetSessionID != "" {
		// Clean out native transactional repository sessions
		_ = s.storage.RevokeSession(ctx, cmd.TenantID, subjectID, targetSessionID)

		// Targetted client sessions lookup: Fetch only client applications used during this specific lifecycle
		applications, err := s.storage.GetApplicationsLogoutContextBySession(ctx, cmd.TenantID, targetSessionID)
		if err == nil {
			now := s.clock.Now()
			for _, app := range applications {
				// Back-channel single sign-out: Dispatch concurrent out-of-band requests asynchronously
				if app.BackChannelLogoutURI != "" {
					logoutToken, err := s.crypto.SignLogoutToken(ctx, model.LogoutTokenClaims{
						TokenID:   uuid.NewString(),
						Issuer:    tenant.GetBaseURI(),
						Subject:   subjectID,
						Audience:  app.ClientID,
						IssuedAt:  now.Unix(),
						SessionID: targetSessionID,
					}, app.SigningAlgorithm)

					if err == nil && s.notifier != nil {
						// Non-blocking asynchronous routine isolates thread execution times
						go func(uri, token string) {
							_ = s.notifier.SendBackChannelLogout(context.Background(), uri, token)
						}(app.BackChannelLogoutURI, logoutToken)
					}
				}

				// Front-channel single sign-out: Harvest iframe targets for delivery projection
				if app.FrontChannelLogoutURI != "" {
					frontChannelURIs = append(frontChannelURIs, app.FrontChannelLogoutURI)
				}
			}
		}
	}

	// 4. Calculate spec-compliant post-logout landing target destination URI
	targetURL := cmd.PostLogoutRedirectURI
	if targetURL == "" {
		targetURL = tenant.Config.DefaultRedirectURI
	}
	if targetURL == "" {
		targetURL = "/"
	}

	if cmd.State != "" && targetURL != "/" {
		if strings.Contains(targetURL, "?") {
			targetURL += "&state=" + url.QueryEscape(cmd.State)
		} else {
			targetURL += "?state=" + url.QueryEscape(cmd.State)
		}
	}

	// 5. Delegate cookie removal calculations entirely to the ssoUseCase port boundary
	cookieIntent, err := s.ssoUseCase.BuildSessionCookie(ctx, port.CookieIntentCommand{
		TenantID:       cmd.TenantID,
		PartitionID:    partitionID,
		LifecycleStage: "clear",
		RequestHost:    cmd.RequestHost,
	})
	if err != nil {
		return nil, fmt.Errorf("oauth_service: cookie clearance allocation failed: %w", err)
	}

	return &port.LogoutExecutionResult{
		PostLogoutRedirectURI:  targetURL,
		FrontChannelLogoutURIs: frontChannelURIs,
		HasCookieIntent:        true,
		CookieName:             cookieIntent.CookieName,
		CookieValue:            cookieIntent.CookieValue,
		CookieMaxAge:           cookieIntent.MaxAge,
		CookieSecure:           cookieIntent.Secure,
	}, nil
}

// ProcessPushedAuthorization executes standard RFC 9126 parameters harvesting, whitelisting,
// and commits short-lived allocation markers back to transactional caching stores.
func (s *OAuthService) ProcessPushedAuthorization(ctx context.Context, cmd port.PushedAuthCommand) (*port.PushedAuthResponse, error) {
	// 1. Enforce strict confidential client authentication gating per RFC 9126 Section 2
	if !cmd.IsClientAuthenticated {
		return nil, fmt.Errorf("%w: pushed authorization requests mandate client authentication", port.ErrInvalidClient)
	}

	tenant, err := s.storage.ResolveTenantByUUID(ctx, cmd.TenantID)
	if err != nil {
		return nil, fmt.Errorf("oauth_service: tenant unresolvable: %w", err)
	}

	app, profile, group, err := s.storage.GetApplicationByClientID(ctx, cmd.TenantID, cmd.ClientID)
	if err != nil {
		return nil, fmt.Errorf("%w: target application unresolvable: %w", port.ErrInvalidClient, err)
	}
	if app == nil || !app.IsEnabled {
		return nil, fmt.Errorf("%s: target application is disabled", port.ErrInvalidClient)
	}
	if group == nil || !group.IsEnabled {
		return nil, fmt.Errorf("%s: target application group is disabled", port.ErrInvalidClient)
	}
	if profile == nil || !profile.IsEnabled {
		return nil, fmt.Errorf("%s: target application profile is disabled", port.ErrInvalidClient)
	}

	// 2. Resolve optional redirect_uri fallbacks via pre-registered application groups
	redirectURI := cmd.RedirectURI
	if redirectURI == "" && group != nil {
		if group.RedirectURI != "" {
			redirectURI = group.RedirectURI
		} else if len(group.RedirectURIs) > 0 {
			redirectURI = group.RedirectURIs[0]
		}
	}

	if redirectURI == "" {
		return nil, fmt.Errorf("%w: redirect_uri parameter missing and no pre-registered defaults exist", port.ErrInvalidRequest)
	}

	if err := s.validator.ValidateRedirect(ctx, tenant, group, redirectURI); err != nil {
		return nil, fmt.Errorf("%w: redirect_uri is not white-listed: %w", port.ErrInvalidRequest, err)
	}

	if err := s.validator.ValidateScopes(ctx, tenant, group, cmd.Scopes); err != nil {
		return nil, fmt.Errorf("%w: requested scopes deviate from whitelists: %w", port.ErrInvalidRequest, err)
	}

	// 3. Centralized Client Identity Provider Router to bind the target partition context early
	activeProvider, truePartitionID, err := s.resolveClientRouting(ctx, cmd.TenantID, group, cmd.IDPHint)
	if err != nil {
		return nil, fmt.Errorf("%w: structural routing calculation failed: %w", port.ErrInvalidRequest, err)
	}

	// 4. Generate high-entropy single-use request token handle strings
	requestUUID := uuid.New().String()
	requestURI := model.URIPrefixPAR + requestUUID
	lifespan := 5 * time.Minute
	expirationWindow := s.clock.Now().Add(lifespan)

	parRecord := model.PushedAuthorizationRequest{
		RequestURI:            requestURI,
		TenantID:              cmd.TenantID,
		PartitionID:           truePartitionID,
		ClientID:              cmd.ClientID,
		RedirectURI:           redirectURI,
		CodeChallenge:         cmd.CodeChallenge,
		ChallengeMethod:       cmd.ChallengeMethod,
		Scopes:                cmd.Scopes,
		State:                 cmd.State,
		Nonce:                 cmd.Nonce,
		IDPHint:               cmd.IDPHint,
		ACRValues:             cmd.ACRValues,
		ExpiresAt:             expirationWindow,
		IdentityProviderID:    activeProvider.ID,
		IdentityProviderAlias: activeProvider.Alias,
	}

	// Route write state operation natively through your unexported helper
	if err := s.savePAR(ctx, parRecord); err != nil {
		return nil, fmt.Errorf("oauth_service: failed to commit pushed authorization markers: %w", err)
	}

	return &port.PushedAuthResponse{
		RequestURI: requestURI,
		ExpiresIn:  int64(lifespan.Seconds()),
	}, nil
}

// ProcessUserInfoRequest completely orchestrates specification-driven OIDC UserInfo evaluations,
// verifying token activity, performing sender-constrained DPoP proofs, and filtering claims down to authorized scopes.
func (s *OAuthService) ProcessUserInfoRequest(ctx context.Context, cmd port.UserInfoRequestCommand) (*model.OIDCTokenClaims, error) {
	if cmd.AuthorizationHeader == "" {
		return nil, fmt.Errorf("%w: missing authorization header credentials", port.ErrInvalidGrant)
	}

	var tokenStr string
	var isDPoPHeaderProvided bool

	switch {
	case strings.HasPrefix(cmd.AuthorizationHeader, "Bearer "):
		tokenStr = strings.TrimPrefix(cmd.AuthorizationHeader, "Bearer ")
	case strings.HasPrefix(cmd.AuthorizationHeader, "DPoP "):
		tokenStr = strings.TrimPrefix(cmd.AuthorizationHeader, "DPoP ")
		isDPoPHeaderProvided = true
	default:
		return nil, fmt.Errorf("%w: unsupported token authorization scheme", port.ErrInvalidGrant)
	}

	if tokenStr == "" {
		return nil, fmt.Errorf("%w: empty token payload context", port.ErrInvalidGrant)
	}

	// 1. Evaluate token activity state and real-time blacklists
	introspection, err := s.IntrospectToken(ctx, cmd.TenantID, "", tokenStr)
	if err != nil || !introspection.Active {
		return nil, fmt.Errorf("%w: target authorization token is inactive or revoked", port.ErrInvalidGrant)
	}

	// 2. Strict RFC 9449 Sender-Constrained Proof Verification
	if introspection.TokenType == "DPoP" {
		if !isDPoPHeaderProvided {
			return nil, fmt.Errorf("%w: dpop token presented via plain bearer transport", port.ErrInvalidGrant)
		}
		if cmd.DPoPProofHeader == "" {
			return nil, fmt.Errorf("%w: missing mandatory cryptographic dpop proof token", port.ErrInvalidGrant)
		}

		proofClaims, err := s.crypto.VerifyToken(cmd.DPoPProofHeader)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid dpop proof payload signature", port.ErrInvalidGrant)
		}

		htm, _ := proofClaims["htm"].(string)
		htu, _ := proofClaims["htu"].(string)
		jti, _ := proofClaims["jti"].(string)

		if !strings.EqualFold(htm, cmd.HTTPMethod) {
			return nil, fmt.Errorf("%w: htm parameters mismatch against network method", port.ErrInvalidRequest)
		}

		// Enforce single-use replay protection
		isUsed, replayErr := s.storage.IsDPoPProofUsed(ctx, jti)
		if replayErr != nil || isUsed {
			return nil, fmt.Errorf("%w: dpop token has already been consumed", port.ErrInvalidRequest)
		}

		// Track thumbprint confirmation values
		if introspection.Confirmation == nil || introspection.Confirmation.JKT != htu {
			return nil, fmt.Errorf("%w: sender cryptographic verification jkt confirmation mismatched", port.ErrInvalidGrant)
		}
	}

	// 3. Resolve user identity profile from isolated multi-tenant partition bounds
	parsedSubjectUUID, err := uuid.Parse(introspection.Subject)
	if err != nil {
		return nil, fmt.Errorf("%w: token subject field is malformed", port.ErrInvalidGrant)
	}

	userProfile, err := s.storage.GetUserProfileByIDAndPartitionAlias(ctx, cmd.TenantID, introspection.PartitionAlias, parsedSubjectUUID)
	if err != nil {
		return nil, fmt.Errorf("%w: target user record missing from context partition", port.ErrInvalidGrant)
	}

	// 4. Populate and filter claims dynamically using the model's pure Go logic
	grantedScopes := strings.Split(introspection.Scope, " ")

	userInfoClaims := model.OIDCTokenClaims{
		BaseTokenClaims: model.BaseTokenClaims{
			Subject: userProfile.ID.String(),
		},
	}

	hasScope := func(target string) bool {
		for _, sc := range grantedScopes {
			if sc == target {
				return true
			}
		}
		return false
	}

	if hasScope("profile") {
		userInfoClaims.Name = userProfile.DisplayName()
		userInfoClaims.GivenName = userProfile.FirstName
		userInfoClaims.FamilyName = userProfile.LastName
		userInfoClaims.PreferredUsername = userProfile.PreferredUsername
	}
	if hasScope("email") {
		userInfoClaims.Email = userProfile.Email
		userInfoClaims.EmailVerified = userProfile.EmailVerified
	}

	return &userInfoClaims, nil
}

// ProcessDynamicRegistration completely encapsulates the RFC 7591 dynamic onboarding pipeline,
// enforcing structural data sanitization, checking software statement signatures, and persisting app configurations.
func (s *OAuthService) ProcessDynamicRegistration(ctx context.Context, tenantID uuid.UUID, payload model.DynamicRegistrationPayload) (*port.DynamicRegistrationResult, error) {
	// 1. Enforce strict sanitization constraints across raw input fragments
	if err := s.SanitizeDynamicRegistrationPayload(&payload); err != nil {
		return nil, fmt.Errorf("%w: structural payload sanitation failed: %w", port.ErrInvalidRequest, err)
	}

	// 2. Delegate application provisioning directly down to the existing internal registration machine
	appRecord, plaintextSecret, err := s.RegisterDynamicApplication(ctx, tenantID, payload)
	if err != nil {
		return nil, fmt.Errorf("%w: registration request rejected by tenant policies: %w", port.ErrInvalidRequest, err)
	}

	return &port.DynamicRegistrationResult{
		Application:     appRecord,
		PlaintextSecret: plaintextSecret,
	}, nil
}

// ProcessTokenRevocation completely encapsulates the RFC 7009 token invalidation pipeline,
// verifying client ownership, parsing structural token identifiers, and blacklisting active states.
func (s *OAuthService) ProcessTokenRevocation(ctx context.Context, cmd port.RevokeTokenCommand) error {
	if cmd.TokenString == "" {
		return fmt.Errorf("%w: missing mandatory token parameter", port.ErrInvalidRequest)
	}

	// 1. Parse the incoming token unverified to safely extract its inner client context mapping parameters
	parser := jwt.NewParser()
	unverifiedToken, _, err := parser.ParseUnverified(cmd.TokenString, jwt.MapClaims{})
	if err != nil {
		return nil // Spec Compliance: Return success if the token structure is completely unparseable
	}

	unverifiedClaims, ok := unverifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil
	}

	// 2. Spec Compliance Section 2.1: Enforce client ownership boundaries
	tokenClientID, _ := unverifiedClaims["client_id"].(string)
	if tokenClientID == "" {
		tokenClientID, _ = unverifiedClaims["azp"].(string) // Fallback check to authorized party claim
	}

	if tokenClientID != "" && tokenClientID != cmd.ClientID {
		return fmt.Errorf("%w: client ownership validation mismatch", port.ErrInvalidClient)
	}

	// 3. Delegate directly down to the existing internal unexported revocation worker mechanics
	return s.storage.RevokeToken(ctx, cmd.TokenString, s.clock.Now().Add(24*time.Hour))
}

// ResolveClientRouting handles the identity provider evaluation within precise partition constraints
func (s *OAuthService) resolveClientRouting(
	ctx context.Context,
	tenantID uuid.UUID,
	group *model.ApplicationGroup,
	idpHint string,
) (*model.IdentityProvider, int64, error) {
	if len(group.AllowedIDPIDs) == 0 {
		return nil, 0, errors.New("routing: client group configuration has no permitted identity providers mapped")
	}

	// Fetches target configurations using the type-safe uuid slice
	permittedIDPs, err := s.storage.GetIdentityProvidersByUUIDs(ctx, tenantID, group.AllowedIDPIDs)
	if err != nil {
		return nil, 0, fmt.Errorf("routing: failed to resolve identity provider configurations: %w", err)
	}
	if len(permittedIDPs) == 0 {
		return nil, 0, errors.New("routing: no active identity provider configurations could be loaded for this group")
	}

	var selectedIDP *model.IdentityProvider

	if len(permittedIDPs) == 1 {
		selectedIDP = &permittedIDPs[0]
	} else {
		// If an outbound login request forwards an explicit idp_hint string alias (e.g., ?idp_hint=okta)
		if idpHint != "" {
			for i := range permittedIDPs {
				if permittedIDPs[i].Enabled && permittedIDPs[i].Alias == idpHint {
					selectedIDP = &permittedIDPs[i]
					break
				}
			}
		}

		// Falls back to checking group.DefaultIDPID matching the uuid pointer field
		if selectedIDP == nil && group.DefaultIDPID != nil {
			for i := range permittedIDPs {
				if permittedIDPs[i].Enabled && permittedIDPs[i].ID == *group.DefaultIDPID {
					selectedIDP = &permittedIDPs[i]
					break
				}
			}
		}
	}

	if selectedIDP == nil || !selectedIDP.Enabled {
		return nil, 0, errors.New("routing: unable to determine an active target identity provider route for this client group")
	}

	if selectedIDP.PartitionID == 0 {
		return nil, 0, fmt.Errorf("routing: target identity provider %s is missing its mandatory structural partition assignment", selectedIDP.Alias)
	}

	return selectedIDP, selectedIDP.PartitionID, nil
}

// ============================================================================
// IDENTITY PROVIDER MATCHERS & PARTITIONED IDENTITY LINKING
// ============================================================================

func (s *OAuthService) matchIdentityProvider(ctx context.Context, tenantID uuid.UUID, iss string, email string) (*model.IdentityProvider, error) {
	// 1. Fetch active providers strictly within the boundaries of the isolated tenant space
	providers, err := s.storage.GetEnabledIdentityProviders(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("get enabled identity providers: %w", err)
	}

	// 2. Evaluate exact configuration issuer URL mappings
	if p := matchExactIssuer(providers, iss); p != nil {
		return p, nil
	}

	// 3. Fall back to evaluating domain suffix whitelist aliases (e.g., corporate routing)
	if p := matchDomainAlias(providers, email); p != nil {
		return p, nil
	}

	// 4. Ultimate fallback to standard federated channels if no specialized route matches
	if p := fallbackNonPasswordProvider(providers); p != nil {
		return p, nil
	}

	return nil, errors.New("no matching identity provider found")
}

func matchExactIssuer(providers []model.IdentityProvider, iss string) *model.IdentityProvider {
	for i := range providers {
		if providers[i].Issuer != "" && providers[i].Issuer == iss {
			return &providers[i]
		}
	}
	return nil
}

func matchDomainAlias(providers []model.IdentityProvider, email string) *model.IdentityProvider {
	if email == "" || !strings.Contains(email, "@") {
		return nil
	}
	parts := strings.Split(email, "@")
	emailDomain := strings.ToLower(parts[len(parts)-1])
	for i := range providers {
		for _, alias := range providers[i].Config.DomainAliases {
			if strings.ToLower(alias) == emailDomain {
				return &providers[i]
			}
		}
	}
	return nil
}

func fallbackNonPasswordProvider(providers []model.IdentityProvider) *model.IdentityProvider {
	for i := range providers {
		if providers[i].IDPType != model.UsernamePasswordIDPType {
			return &providers[i]
		}
	}
	// Fixed Compilation Bug: Returns a safe pointer reference instead of the root slice object
	if len(providers) > 0 {
		return &providers[0]
	}
	return nil
}

func (s *OAuthService) findUserProfile(ctx context.Context, tenantID uuid.UUID, provider *model.IdentityProvider, externalSub, email string, emailVerified bool) (*model.UserProfile, error) {
	slog.Debug("findUserProfile: starting profile search", "tenant_id", tenantID, "provider_partition_id", provider.PartitionID, "provider_id", provider.ID, "external_sub", externalSub, "email", email, "email_verified", emailVerified)

	// 1. DIRECT ONE-TRIP IDENTITY LOOKUP: Query row matching provider ID and foreign subject index
	identity, err := s.storage.GetUserIdentityByProviderAndExternalID(ctx, tenantID, provider.PartitionID, provider.ID, externalSub)
	if err == nil && identity != nil {
		slog.Debug("findUserProfile: coupled identity found, resolving user profile", "user_profile_id", identity.UserProfileID)
		// Load the global parent profile using the verified identity context mapping pointer
		profile, err := s.storage.GetUserProfileByID(ctx, tenantID, provider.PartitionID, identity.UserProfileID)
		if err == nil && profile != nil {
			slog.Debug("findUserProfile: user profile resolved successfully via direct coupling", "user_id", profile.ID)
			return profile, nil
		}
		slog.Warn("findUserProfile: coupled identity exists but failed loading user profile", "err", err)
	} else {
		slog.Debug("findUserProfile: direct identity coupling not found, falling back to email", "err", err)
	}

	// 2. VERIFIED EMAIL AUTOLINK FALLBACK
	if !emailVerified {
		slog.Warn("findUserProfile: email is unverified, blocking autolink and JIT provisioning")
		return nil, port.ErrExternalEmailNotVerified
	}

	if email != "" {
		// Query the clean, single-index partitioned profile tracker
		slog.Debug("findUserProfile: looking up profile by email", "partition_id", provider.PartitionID, "email", email)
		profile, err := s.storage.FindProfileByEmail(ctx, provider.PartitionID, email)
		if err != nil {
			slog.Debug("findUserProfile: profile not found by email", "partition_id", provider.PartitionID, "email", email, "err", err)
			if provider.Config.AutoProvisionUser {
				now := s.clock.Now()
				isEmailVerified := provider.Config.AutoVerifyEmail && emailVerified

				// Create a generic JIT user profile
				profile = &model.UserProfile{
					ID:                uuid.New(),
					TenantID:          tenantID,
					PartitionID:       provider.PartitionID,
					Email:             email,
					EmailVerified:     isEmailVerified,
					PreferredUsername: email,
					Name:              email,
					LifecycleState:    model.LifecycleActivated,
					CreatedAt:         now,
					UpdatedAt:         now,
				}

				slog.Debug("findUserProfile: JIT provisioning user profile", "user_id", profile.ID, "partition_id", provider.PartitionID, "email", email)
				if errSave := s.storage.SaveUserProfile(ctx, tenantID, provider.PartitionID, *profile); errSave != nil {
					slog.Error("findUserProfile: failed to JIT provision user profile", "err", errSave)
					return nil, fmt.Errorf("failed to JIT provision user profile in oauth_service: %w", errSave)
				}
				err = nil
			} else {
				slog.Warn("findUserProfile: JIT auto-provisioning is disabled for this provider")
			}
		}

		if err == nil && profile != nil {
			// Multi-Tenant Guard: Confirm data containment properties hold true
			if profile.TenantID != tenantID {
				slog.Error("findUserProfile: multi-tenant guard breach detected", "profile_tenant_id", profile.TenantID, "request_tenant_id", tenantID)
				return nil, errors.New("federation error: target user identity belongs to an isolated external tenant boundary")
			}

			// Link generation: Initialize an identity mapping slot under strict multi-tenant context
			newIdentity := model.UserIdentity{
				ID:                 uuid.New(),
				UserProfileID:      profile.ID,
				IdentityProviderID: provider.ID,
				ExternalIdentityID: externalSub,
				CoupledAt:          s.clock.Now(),
			}

			slog.Debug("findUserProfile: auto-linking external sub to user profile", "user_id", profile.ID, "external_sub", externalSub)
			// Commit link safely into database indexes
			if err := s.storage.UpsertUserIdentity(ctx, tenantID, provider.PartitionID, newIdentity); err != nil {
				slog.Error("findUserProfile: failed auto-linking identity record", "err", err)
				return nil, fmt.Errorf("failed auto-linking identity record: %w", err)
			}
			return profile, nil
		}
	}

	slog.Warn("findUserProfile: user profile resolution failed entirely")
	return nil, errors.New("user profile not found")
}

//nolint:unused
func (s *OAuthService) coupleUserIdentity(ctx context.Context, tenantID uuid.UUID, partitionID int64, profileID uuid.UUID, providerID uuid.UUID, externalSub string, now time.Time) error {
	// Query current link status safely passing complete partition keys
	identity, err := s.storage.GetUserIdentityByProviderAndExternalID(ctx, tenantID, partitionID, providerID, externalSub)
	if err != nil {
		// Link trace doesn't exist yet; build it fresh
		newIdentity := model.UserIdentity{
			ID:                 uuid.New(),
			UserProfileID:      profileID,
			IdentityProviderID: providerID,
			ExternalIdentityID: externalSub,
			CoupledAt:          now,
			LoginCount:         1,
			LastLoginAt:        &now,
		}
		return s.storage.UpsertUserIdentity(ctx, tenantID, partitionID, newIdentity)
	}

	// Increment access metric track parameters under strict isolation constraints
	_ = s.storage.IncrementUserIdentityLoginTracker(ctx, tenantID, partitionID, identity.ID, now)
	return nil
}

// ============================================================================
// INTROSPECTION, REVOCATION & SEAMLESS BACK-CHANNEL LOGOUT
// ============================================================================

// ProcessTokenIntrospection completely encapsulates the RFC 7662 token analysis pipeline,
// enforcing strict client profile verification, validating signatures, and checking active blacklist tables.
func (s *OAuthService) ProcessTokenIntrospection(ctx context.Context, cmd port.IntrospectTokenCommand) (*model.IntrospectionResponse, error) {
	// 1. Enforce strict confidential client authentication gating per RFC 7662 Section 2
	if !cmd.IsClientAuthenticated {
		return nil, fmt.Errorf("%w: introspection requests mandate client authentication", port.ErrInvalidClient)
	}

	if cmd.TargetTokenString == "" {
		return nil, fmt.Errorf("%w: missing mandatory token parameter", port.ErrInvalidRequest)
	}

	// 2. Cryptographically verify signature parameters against the shared engine key cache
	claims, err := s.crypto.VerifyToken(cmd.TargetTokenString)
	if err != nil {
		return &model.IntrospectionResponse{Active: false}, nil
	}

	tokenID, _ := claims["jti"].(string)
	expVal, _ := claims["exp"].(float64)

	// 3. Check Real-time Blacklists: Verify if the unique token ID has been revoked
	if tokenID != "" {
		revoked, err := s.storage.IsTokenRevoked(ctx, tokenID)
		if err == nil && revoked {
			return &model.IntrospectionResponse{Active: false}, nil
		}
	}

	// 4. Verify structural temporal validation boundaries
	exp := time.Unix(int64(expVal), 0)
	if s.clock.Now().After(exp) {
		return &model.IntrospectionResponse{Active: false}, nil
	}

	scope, _ := claims["scope"].(string)
	tokenClientID, _ := claims["client_id"].(string)
	sub, _ := claims["sub"].(string)
	iss, _ := claims["iss"].(string)
	tid, _ := claims["tid"].(string)
	iatVal, _ := claims["iat"].(float64)

	var cnf *model.Confirmation
	var tokenType = "Bearer"
	if cnfVal, ok := claims["cnf"].(map[string]any); ok {
		if jktVal, ok := cnfVal["jkt"].(string); ok {
			cnf = &model.Confirmation{JKT: jktVal}
			tokenType = "DPoP"
		}
	}

	return &model.IntrospectionResponse{
		Active:       true,
		Scope:        scope,
		ClientID:     tokenClientID,
		Subject:      sub,
		ExpiresAt:    int64(expVal),
		IssuedAt:     int64(iatVal),
		Issuer:       iss,
		TokenType:    tokenType,
		TenantID:     tid,
		Confirmation: cnf,
	}, nil
}

// Introspection: Verifies token validity and extracts authorization properties for downstream resource servers
func (s *OAuthService) IntrospectToken(ctx context.Context, tenantID uuid.UUID, clientID string, tokenStr string) (*model.IntrospectionResponse, error) {
	// 1. Cryptographically verify signature parameters against the shared engine key cache
	claims, err := s.crypto.VerifyToken(tokenStr)
	if err != nil {
		return &model.IntrospectionResponse{Active: false}, nil
	}

	// 2. Extract standard token tracking claims
	tokenID, _ := claims["jti"].(string)
	expVal, _ := claims["exp"].(float64)

	// 3. Check Real-time Blacklists: Verify if the unique token ID has been revoked
	if tokenID != "" {
		revoked, err := s.storage.IsTokenRevoked(ctx, tokenID)
		if err == nil && revoked {
			return &model.IntrospectionResponse{Active: false}, nil
		}
	}

	// 4. Verify structural temporal validation boundaries
	exp := time.Unix(int64(expVal), 0)
	if s.clock.Now().After(exp) {
		return &model.IntrospectionResponse{Active: false}, nil
	}

	scope, _ := claims["scope"].(string)
	tokenClientID, _ := claims["client_id"].(string)
	sub, _ := claims["sub"].(string)
	iss, _ := claims["iss"].(string)
	tid, _ := claims["tid"].(string)
	iatVal, _ := claims["iat"].(float64)

	// 5. Populate DPoP cryptographic proof binding parameters if present under the "cnf" thumbprint key
	var cnf *model.Confirmation
	var tokenType = "Bearer"
	if cnfVal, ok := claims["cnf"].(map[string]any); ok {
		if jktVal, ok := cnfVal["jkt"].(string); ok {
			cnf = &model.Confirmation{JKT: jktVal}
			tokenType = "DPoP"
		}
	}

	return &model.IntrospectionResponse{
		Active:       true,
		Scope:        scope,
		ClientID:     tokenClientID,
		Subject:      sub,
		ExpiresAt:    int64(expVal),
		IssuedAt:     int64(iatVal),
		Issuer:       iss,
		TokenType:    tokenType,
		TenantID:     tid,
		Confirmation: cnf,
	}, nil
}

// RevokeToken extracts tracking identifiers from a token string unverified and registers them in the revocation blacklist
func (s *OAuthService) RevokeToken(ctx context.Context, tenantID uuid.UUID, clientID string, tokenStr string) error {
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil // Graceful exit on completely unparseable string inputs
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil
	}

	tokenID, _ := claims["jti"].(string)
	if tokenID == "" {
		return nil
	}

	var expiresAt time.Time
	if expVal, ok := claims["exp"].(float64); ok {
		expiresAt = time.Unix(int64(expVal), 0)
	} else {
		expiresAt = s.clock.Now().Add(24 * time.Hour) // Safe fallback boundary ceiling
	}

	return s.storage.RevokeToken(ctx, tokenID, expiresAt)
}

// ============================================================================
// DYNAMIC CLIENT REGISTRATION
// ============================================================================

func (s *OAuthService) SanitizeDynamicRegistrationPayload(payload *model.DynamicRegistrationPayload) error {
	payload.ApplicationName = strings.TrimSpace(payload.ApplicationName)

	if len(payload.ApplicationName) > 128 {
		return errors.New("registration: application name parameter length limits exceeded")
	}

	if strings.ContainsAny(payload.ApplicationName, "<>/\\") {
		return errors.New("registration: application name contains illegal character scripts")
	}

	payload.AllowedScopes = strings.TrimSpace(payload.AllowedScopes)
	if len(payload.AllowedScopes) > 512 {
		return errors.New("registration: scope descriptor block size limits exceeded")
	}
	if payload.AllowedScopes != "" && !strictScopeSyntaxFilter.MatchString(payload.AllowedScopes) {
		return errors.New("registration: scope string contains illegal characters")
	}

	return nil
}

// ValidateSoftwareStatement processes incoming dynamic tracking tokens, performing cryptographic signature matches
// and validating structural payload field invariants before downstream processing runs.
func (s *OAuthService) ValidateSoftwareStatement(ctx context.Context, ssa string) (*model.SoftwareStatementClaims, error) {
	if ssa == "" {
		return nil, errors.New("software_statement: raw token string parameter is missing")
	}

	var claims model.SoftwareStatementClaims
	_, err := jwt.ParseWithClaims(ssa, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected dynamic registration signature method: %v", t.Header["alg"])
		}

		pubKey, err := s.crypto.GetMasterRegistrationPublicKey()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve verification key: %w", err)
		}
		return pubKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("software statement validation failed: %w", err)
	}

	return &claims, nil
}

func (s *OAuthService) RegisterDynamicApplication(
	ctx context.Context,
	tenantID uuid.UUID,
	payload model.DynamicRegistrationPayload,
) (*model.Application, string, error) {
	tenant, err := s.storage.ResolveTenantByUUID(ctx, tenantID)
	if err != nil {
		return nil, "", fmt.Errorf("dynamic_registration: failed to resolve tenant profile context: %w", err)
	}

	if tenant.Config.DCRMode == model.DCRModeOff || tenant.Config.DCRMode == "" {
		return nil, "", errors.New("dynamic_registration: registration is disabled for this tenant context")
	}

	var targetSSA string
	var applicationName string

	switch tenant.Config.DCRMode {
	case model.DCRModeSoftwareStatement:
		if payload.SoftwareStatement == "" {
			return nil, "", errors.New("dynamic_registration: software_statement parameter is mandatory under statement-driven modes")
		}

		claims, err := s.ValidateSoftwareStatement(ctx, payload.SoftwareStatement)
		if err != nil {
			return nil, "", fmt.Errorf("dynamic_registration: software statement signature validation failed: %w", err)
		}

		targetSSA = claims.SoftwareID
		applicationName = claims.ClientName
		if applicationName == "" {
			if payload.ApplicationName == "" {
				return nil, "", errors.New("dynamic_registration: client_name is mandatory under standard onboarding rules")
			}
			applicationName = payload.ApplicationName
		}

	case model.DCRModePublic, model.DCRModeAuthenticated:
		if payload.ApplicationName == "" {
			return nil, "", errors.New("dynamic_registration: client_name is mandatory under standard onboarding rules")
		}
		applicationName = payload.ApplicationName

		if payload.TokenEndpointAuthMethod == "none" || tenant.Config.DCRMode == model.DCRModePublic {
			if tenant.Config.PublicSoftwareStatement == "" {
				return nil, "", errors.New("dynamic_registration: tenant public software statement anchor is unconfigured")
			}
			targetSSA = tenant.Config.PublicSoftwareStatement
		} else {
			if tenant.Config.AuthenticatedSoftwareStatement == "" {
				return nil, "", errors.New("dynamic_registration: tenant authenticated software statement anchor is unconfigured")
			}
			targetSSA = tenant.Config.AuthenticatedSoftwareStatement
		}

	default:
		return nil, "", fmt.Errorf("dynamic_registration: unsupported tenant deployment mode: %v", tenant.Config.DCRMode)
	}

	parts := strings.Split(targetSSA, ";")
	if len(parts) != 2 {
		return nil, "", fmt.Errorf("dynamic_registration: malformed software_id format '%s', must match 'profile_name;group_name'", targetSSA)
	}

	profileLookupName := parts[0]
	groupLookupName := parts[1]

	resolvedProfile, err := s.storage.GetProfileByName(ctx, tenantID, profileLookupName)
	if err != nil {
		return nil, "", fmt.Errorf("dynamic_registration: unrecognized application profile '%s': %w", profileLookupName, err)
	}

	resolvedGroup, err := s.storage.GetGroupByName(ctx, tenantID, groupLookupName)
	if err != nil {
		return nil, "", fmt.Errorf("dynamic_registration: unrecognized application group '%s': %w", groupLookupName, err)
	}

	if !resolvedProfile.IsEnabled || !resolvedGroup.IsEnabled {
		return nil, "", errors.New("dynamic_registration: target profile or group is deactivated")
	}

	if payload.TokenEndpointAuthMethod == "none" && resolvedProfile.TokenEndpointAuthMethod != "none" {
		return nil, "", errors.New("dynamic_registration: security breach: public client linked to a confidential application profile")
	}

	if len(payload.RedirectURIs) == 0 {
		payload.RedirectURIs = resolvedGroup.RedirectURIs
	} else {
		for _, reqURI := range payload.RedirectURIs {
			matched := false
			for _, allowedURI := range resolvedGroup.RedirectURIs {
				if reqURI == allowedURI {
					matched = true
					break
				}
			}
			if !matched {
				return nil, "", fmt.Errorf("dynamic_registration: requested redirect_uri %s deviates from group whitelists", reqURI)
			}
		}
	}

	authMethod := resolvedProfile.TokenEndpointAuthMethod
	var plaintextSecret string
	var hashedSecret *string

	if authMethod != "none" {
		secretBytes := make([]byte, 32)
		_, _ = rand.Read(secretBytes)
		plaintextSecret = base64.RawURLEncoding.EncodeToString(secretBytes)

		hashStr, _ := s.crypto.HashCredential(plaintextSecret)
		hashedSecret = &hashStr
	}

	now := s.clock.Now()
	appRecord := model.Application{
		ID:               uuid.New(),
		TenantID:         tenantID,
		ProfileID:        resolvedProfile.ID,
		GroupID:          resolvedGroup.ID,
		ApplicationName:  applicationName,
		ClientID:         "dyn_" + uuid.NewString(),
		ClientSecretHash: hashedSecret,
		IsEnabled:        true,
		IsDynamic:        true,
		CreatedAt:        now,
		UpdatedAt:        now,
		LastUsedAt:       now,
	}

	if err := s.storage.RegisterApplication(ctx, appRecord); err != nil {
		return nil, "", fmt.Errorf("failed to persist dynamic application entry: %w", err)
	}

	return &appRecord, plaintextSecret, nil
}
