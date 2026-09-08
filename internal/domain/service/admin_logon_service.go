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

// Compile-time assertion checking to guarantee strict primary port interface compliance
var _ port.AdminLogonUseCase = (*AdminLogonService)(nil)

// AdminLogonService orchestrates multi-tenant administrative federation loops.
type AdminLogonService struct {
	storage          port.Storage
	adminStorage     port.AdminStorage
	oauthService     port.AuthUseCase
	crypto           port.Crypto
	federationClient port.FederationClient // Unified platform network client interface contract
	federationLogin  port.FederatedLoginUseCase
	clock            port.Clock
	appEnv           string
	adminDomain      string
}

// NewAdminLogonService binds domain port contracts cleanly into a unified use-case worker.
func NewAdminLogonService(
	s port.Storage,
	as port.AdminStorage,
	auth port.AuthUseCase,
	c port.Crypto,
	fc port.FederationClient, // Bound directly to your driven network port interface
	fl port.FederatedLoginUseCase,
	cl port.Clock,
	appEnv string,
	adminDomain string,
) *AdminLogonService {
	return &AdminLogonService{
		storage:          s,
		adminStorage:     as,
		oauthService:     auth,
		crypto:           c,
		federationClient: fc,
		federationLogin:  fl,
		clock:            cl,
		appEnv:           appEnv,
		adminDomain:      adminDomain,
	}
}

// InitiateAdminLogon evaluates localized setup configuration fields and triggers automated DCR workflows if needed.
func (s *AdminLogonService) InitiateAdminLogon(ctx context.Context, localTenantID uuid.UUID, callbackURI string, targetAdminUI string) (*port.InitiateFederatedLoginResponse, error) {
	providers, err := s.storage.GetIdentityProviders(ctx, localTenantID)
	if err != nil {
		return nil, fmt.Errorf("admin_logon: failed loading tenant provider maps: %w", err)
	}

	var adminOidcProvider *model.IdentityProvider
	for _, p := range providers {
		if p.IDPType == model.OpenIDConnectIDPType && p.Alias == "admin-sso" { // TODO Maybe fetch directly via alias from storage
			adminOidcProvider = &p
			break
		}
	}

	if adminOidcProvider == nil {
		return nil, port.ErrIdentityProviderNotFound
	}

	// 1. On-Demand Automated DCR Trigger
	if adminOidcProvider.Config.ClientID == "" {
		if err := s.provisionViaSoftwareStatement(ctx, localTenantID, adminOidcProvider, callbackURI); err != nil {
			return nil, fmt.Errorf("admin_logon: dynamic platform client onboarding failed: %w", err)
		}
	}

	// 2. Metadata Discovery Hook: Hydrate execution targets dynamically via the network port if blank
	if adminOidcProvider.Config.AuthorizationEndpoint == "" || adminOidcProvider.Config.TokenEndpoint == "" {
		metadata, err := s.federationClient.FetchOIDCDiscoveryMetadata(ctx, adminOidcProvider.Config.DiscoveryEndpoint)
		if err != nil {
			return nil, fmt.Errorf("admin_logon: upstream meta-discovery handshake failed: %w", err)
		}

		adminOidcProvider.Config.AuthorizationEndpoint = metadata.AuthorizationEndpoint
		adminOidcProvider.Config.TokenEndpoint = metadata.TokenEndpoint
		adminOidcProvider.Config.JwksURI = metadata.JwksURI

		// Persist the discovered metadata permanently to the database so callbacks can load them
		err = s.adminStorage.CreateIdentityProvider(ctx, localTenantID, *adminOidcProvider)
		if err != nil {
			return nil, fmt.Errorf("admin_logon: failed persisting discovered admin sso metadata endpoints: %w", err)
		}
	}

	// Invoke core FederationService engine directly using standard models [1.14]
	return s.federationLogin.InitiateFederatedLogin(ctx, port.InitiateFederatedLoginCommand{
		TenantID:           localTenantID,
		IdentityProviderID: adminOidcProvider.ID,
		ClientID:           "admin_ui", // Hardcoded target administrative interface client ID anchor
		RequestedScopes:    []string{"openid", "profile", "email"},
		LocalCallbackURI:   callbackURI,
		FinalTargetURI:     targetAdminUI,
	})
}

// CompleteAdminLogon consumes transient transaction handshakes and completes cross-tenant profile exchanges.
func (s *AdminLogonService) CompleteAdminLogon(ctx context.Context, localTenantID uuid.UUID, incomingState string, incomingCode string) (*model.TokenSetResponse, string, error) {
	// Fetch and consume short-lived handshake states to block cross-site replays.
	handshake, err := s.storage.GetAndConsumeOutboundHandshake(ctx, localTenantID, incomingState)
	if err != nil {
		return nil, "", fmt.Errorf("admin_logon: stateless handshake lookup verification denied: %w", err)
	}
	if handshake == nil {
		return nil, "", errors.New("admin_logon: active tracking transaction state has expired or is invalid")
	}

	providers, err := s.storage.GetIdentityProviders(ctx, localTenantID)
	if err != nil {
		return nil, "", fmt.Errorf("admin_logon: failed loading provider mapping catalog: %w", err)
	}

	var matchedProvider *model.IdentityProvider
	for _, p := range providers {
		if p.ID == handshake.IdentityProviderID {
			matchedProvider = &p
			break
		}
	}

	if matchedProvider == nil || matchedProvider.Config.TokenEndpoint == "" {
		return nil, "", errors.New("admin_logon: matching administrative upstream provider not active in this space")
	}

	// Pass localTenantID to accurately look up the local callback transaction parameters [5.7]
	upstreamTokens, err := s.oauthService.ExchangeCodeForTokens(ctx, port.ExchangeCodeForTokensCommand{
		TenantID:     localTenantID,
		ClientID:     matchedProvider.Config.ClientID,
		Code:         incomingCode,
		CodeVerifier: handshake.CodeVerifier,
	})
	if err != nil {
		return nil, "", fmt.Errorf("admin_logon: back-channel token trade rejected by upstream idp: %w", err)
	}

	// Invokes the native ExchangeExternalToken method cleanly exactly as intended by your blueprint [source: 21, 5.7]
	localTokens, err := s.oauthService.ExchangeExternalToken(
		ctx,
		localTenantID,
		handshake.ClientID,
		upstreamTokens.IDToken,
		"urn:ietf:params:oauth:token-type:id_token",
	)
	if err != nil {
		return nil, "", fmt.Errorf("admin_logon: profile mapping and federation link denied: %w", err)
	}

	redirectURL := handshake.TargetURI
	if redirectURL == "" {
		tenant, err := s.storage.ResolveTenantByUUID(ctx, localTenantID)
		if err == nil && tenant.Config.DefaultRedirectURI != "" {
			redirectURL = tenant.Config.DefaultRedirectURI
		} else {
			redirectURL = port.RouteAdmin
		}
	}

	return localTokens, redirectURL, nil
}

// provisionViaSoftwareStatement generates short-lived platform tokens and executes direct DCR on-demand registrations.
func (s *AdminLogonService) provisionViaSoftwareStatement(ctx context.Context, localTenantID uuid.UUID, idp *model.IdentityProvider, callbackURI string) error {
	adminTenant, err := s.storage.ResolveTenantByDomain(ctx, s.adminDomain)
	if err != nil {
		return fmt.Errorf("failed resolving baseline platform control domain context: %w", err)
	}

	scheme := model.SchemeHttps
	if s.appEnv == "local" {
		scheme = model.SchemeHttp
	}
	centralAdminIssuer := scheme + "://" + s.adminDomain

	now := s.clock.Now()

	statementClaims := model.SoftwareStatementClaims{
		SoftwareID:   model.AdminUIProfileName + ";" + model.LocalAdminUIGroupName,
		ClientName:   fmt.Sprintf("Sprezz Admin Client [%s]", localTenantID.String()),
		RedirectURIs: []string{callbackURI},
		Scopes:       []string{"openid", "profile", "email"},
	}

	signedStatementToken, err := s.crypto.SignSoftwareStatement(ctx, s.adminDomain, centralAdminIssuer, statementClaims, now, now.Add(5*time.Minute))
	if err != nil {
		return fmt.Errorf("failed minting software statement assertion via crypto port: %w", err)
	}

	payload := model.DynamicRegistrationPayload{
		ApplicationName:         fmt.Sprintf("Administrative UI Client for Tenant Partition: %s", localTenantID.String()),
		TokenEndpointAuthMethod: model.AuthMethodNone,
		GrantTypes:              []model.GrantType{model.GrantTypeAuthorizationCode, model.GrantTypeRefreshToken},
		ResponseTypes:           []model.ResponseType{model.ResponseTypeCode},
		AllowedScopes:           "openid profile email",
		RedirectURIs:            []string{callbackURI},
		SoftwareStatement:       signedStatementToken,
	}

	registeredApp, plaintextSecret, err := s.oauthService.RegisterDynamicApplication(ctx, adminTenant.ID, payload)
	if err != nil {
		return fmt.Errorf("central registration endpoint rejected statement validation assertions: %w", err)
	}

	idp.Config.ClientID = registeredApp.ClientID
	idp.Config.ClientSecret = plaintextSecret
	idp.UpdatedAt = now

	err = s.adminStorage.CreateIdentityProvider(ctx, localTenantID, *idp)
	if err != nil {
		return fmt.Errorf("failed modifying provider records inside administrative metadata store: %w", err)
	}
	return nil
}
