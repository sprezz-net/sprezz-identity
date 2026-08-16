package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type OAuthService struct {
	storage  port.Storage
	crypto   port.Crypto
	event    port.Event
	notifier port.LogoutNotifier
	clock    port.Clock
}

func NewOAuthService(s port.Storage, c port.Crypto, e port.Event, n port.LogoutNotifier, cl port.Clock) *OAuthService {
	return &OAuthService{storage: s, crypto: c, event: e, notifier: n, clock: cl}
}

func (s *OAuthService) InitiateAuthorize(ctx context.Context, session model.AuthorizationCodeSession) error {
	if session.Code == "" {
		return errors.New("authorize code must not be empty")
	}
	if session.RedirectURI == "" {
		return errors.New("redirect_uri must not be empty")
	}
	return s.storage.SaveAuthSession(ctx, session)
}

func (s *OAuthService) SavePAR(ctx context.Context, req model.PushedAuthorizationRequest) error {
	return s.storage.SavePAR(ctx, req)
}

func (s *OAuthService) GetAndConsumePAR(ctx context.Context, tenantID uuid.UUID, requestURI string) (*model.PushedAuthorizationRequest, error) {
	return s.storage.GetAndConsumePAR(ctx, tenantID, requestURI)
}

func (s *OAuthService) ExchangeCodeForTokens(ctx context.Context, tenantID uuid.UUID, clientID string, code string, codeVerifier string, dpopJKT string) (*model.TokenSetResponse, error) {
	client, err := s.storage.GetClient(ctx, tenantID, clientID)
	if err != nil {
		return nil, fmt.Errorf("get client for token exchange: %w", err)
	}

	tenant, err := s.storage.ResolveTenantByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant identity for token exchange: %w", err)
	}

	authSession, err := s.storage.GetAndConsumeAuthSession(ctx, tenantID, code)
	if err != nil {
		return nil, fmt.Errorf("consume authorization code: %w", err)
	}

	if authSession.CodeChallenge != "" {
		sum := sha256.Sum256([]byte(codeVerifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		if challenge != authSession.CodeChallenge {
			return nil, errors.New("invalid PKCE verifier")
		}
	}

	issuer := tenant.GetBaseURL()
	now := s.clock.Now()
	accessToken, err := s.crypto.SignAccessToken(ctx, model.TokenClaims{
		TokenID:   uuid.NewString(),
		Issuer:    issuer,
		TenantID:  tenantID.String(),
		Subject:   authSession.Subject,
		ClientID:  clientID,
		Scopes:    authSession.Scopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(client.AccessTokenLifetime),
		Audiences: client.AllowedAudiences,
		DPoPHash:  dpopJKT,
		ACR:       authSession.ACRValues,
	}, client.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("mint access token: %w", err)
	}

	var parsedNonce string
	if authSession.Nonce != "" {
		parsedNonce = authSession.Nonce
	} else {
		parsedNonce = uuid.NewString()
	}

	idToken, err := s.crypto.SignIDToken(ctx, model.OIDCTokenClaims{
		TokenID:   uuid.NewString(),
		Issuer:    issuer,
		Subject:   authSession.Subject,
		Audience:  clientID,
		TenantID:  tenantID.String(),
		IssuedAt:  now,
		ExpiresAt: now.Add(client.IDTokenLifetime),
		AuthTime:  now,
		Nonce:     parsedNonce,
		SessionID: authSession.SessionID,
		ACR:       authSession.ACRValues,
	}, client.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("mint id token: %w", err)
	}

	tokenType := "Bearer"
	if dpopJKT != "" {
		tokenType = "DPoP"
	}

	refreshTokenVal := uuid.NewString()
	if client.EnforceRTR {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err == nil {
			refreshTokenVal = base64.RawURLEncoding.EncodeToString(bytes)
		}
		familyID := uuid.NewString()
		_ = s.storage.SaveRefreshToken(ctx, model.RefreshToken{
			TokenID:       refreshTokenVal,
			TenantID:      tenantID,
			ClientID:      clientID,
			Subject:       authSession.Subject,
			Scopes:        authSession.Scopes,
			TokenFamilyID: familyID,
			IsUsed:        false,
			ExpiresAt:     now.Add(client.RefreshTokenLifetime),
			CreatedAt:     now,
		})
	}

	return &model.TokenSetResponse{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: refreshTokenVal,
		TokenType:    tokenType,
		ExpiresIn:    int64(client.AccessTokenLifetime / time.Second),
	}, nil
}

func (s *OAuthService) ExchangeRefreshTokenForTokens(ctx context.Context, tenantID uuid.UUID, clientID string, refreshTokenStr string, dpopJKT string) (*model.TokenSetResponse, error) {
	client, err := s.storage.GetClient(ctx, tenantID, clientID)
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}

	tenant, err := s.storage.ResolveTenantByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant: %w", err)
	}

	if !client.EnforceRTR {
		now := s.clock.Now()
		accessToken, err := s.crypto.SignAccessToken(ctx, model.TokenClaims{
			TokenID:   uuid.NewString(),
			Issuer:    tenant.GetBaseURL(),
			TenantID:  tenantID.String(),
			Subject:   client.ClientID,
			ClientID:  clientID,
			Scopes:    client.DefaultScopes,
			IssuedAt:  now,
			ExpiresAt: now.Add(client.AccessTokenLifetime),
			Audiences: client.AllowedAudiences,
			DPoPHash:  dpopJKT,
		}, client.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("sign access token: %w", err)
		}
		tokenType := "Bearer"
		if dpopJKT != "" {
			tokenType = "DPoP"
		}
		return &model.TokenSetResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshTokenStr,
			TokenType:    tokenType,
			ExpiresIn:    int64(client.AccessTokenLifetime / time.Second),
		}, nil
	}

	token, err := s.storage.GetRefreshToken(ctx, refreshTokenStr)
	if err != nil {
		return nil, errors.New(model.ErrInvalidGrant)
	}

	if token.ExpiresAt.Before(s.clock.Now()) {
		return nil, errors.New(model.ErrInvalidGrant)
	}

	if token.IsUsed {
		_ = s.storage.RevokeRefreshTokenFamily(ctx, token.TokenFamilyID)
		return nil, errors.New(model.ErrInvalidGrant)
	}

	if err := s.storage.MarkRefreshTokenUsed(ctx, token.TokenID); err != nil {
		return nil, fmt.Errorf("mark token used: %w", err)
	}

	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("generate secure random bytes: %w", err)
	}
	newRefreshTokenStr := base64.RawURLEncoding.EncodeToString(bytes)

	now := s.clock.Now()
	newRefreshToken := model.RefreshToken{
		TokenID:       newRefreshTokenStr,
		TenantID:      tenantID,
		ClientID:      clientID,
		Subject:       token.Subject,
		Scopes:        token.Scopes,
		TokenFamilyID: token.TokenFamilyID,
		IsUsed:        false,
		ExpiresAt:     now.Add(client.RefreshTokenLifetime),
		CreatedAt:     now,
	}

	if err := s.storage.SaveRefreshToken(ctx, newRefreshToken); err != nil {
		return nil, fmt.Errorf("save new refresh token: %w", err)
	}

	accessToken, err := s.crypto.SignAccessToken(ctx, model.TokenClaims{
		TokenID:   uuid.NewString(),
		Issuer:    tenant.GetBaseURL(),
		TenantID:  tenantID.String(),
		Subject:   token.Subject,
		ClientID:  clientID,
		Scopes:    token.Scopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(client.AccessTokenLifetime),
		Audiences: client.AllowedAudiences,
		DPoPHash:  dpopJKT,
	}, client.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	tokenType := "Bearer"
	if dpopJKT != "" {
		tokenType = "DPoP"
	}

	return &model.TokenSetResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshTokenStr,
		TokenType:    tokenType,
		ExpiresIn:    int64(client.AccessTokenLifetime / time.Second),
	}, nil
}

func (s *OAuthService) ExchangeExternalToken(ctx context.Context, tenantID uuid.UUID, clientID string, subjectToken string, subjectTokenType string, dpopJKT string) (*model.TokenSetResponse, error) {
	client, err := s.storage.GetClient(ctx, tenantID, clientID)
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}

	tenant, err := s.storage.ResolveTenantByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant: %w", err)
	}

	externalSub, iss, email, _, _, emailVerified, err := s.parseExternalToken(subjectToken, subjectTokenType)
	if err != nil {
		return nil, err
	}

	matchedProvider, err := s.matchIdentityProvider(ctx, tenantID, iss, email)
	if err != nil {
		return nil, err
	}

	now := s.clock.Now()

	profile, err := s.findUserProfile(ctx, tenantID, matchedProvider, externalSub, email, emailVerified)
	if err != nil {
		if errors.Is(err, port.ErrExternalEmailNotVerified) {
			return nil, errors.New(model.ErrInvalidGrant)
		}
		return nil, fmt.Errorf("token exchange denied: %w", err)
	}

	if err := s.coupleUserIdentity(ctx, profile.ID, matchedProvider.ID, externalSub, now); err != nil {
		return nil, fmt.Errorf("couple user identity: %w", err)
	}

	return s.mintTokensForExchangedUser(ctx, tenant, client, profile.ID.String(), dpopJKT, now)
}

func parseJWTClaims(subjectToken string) (jwt.MapClaims, error) {
	parser := new(jwt.Parser)
	token, _, err := parser.ParseUnverified(subjectToken, jwt.MapClaims{})
	if err != nil {
		return nil, errors.New("invalid external token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid external claims")
	}
	return claims, nil
}

func parseJWTToken(subjectToken string) (string, string, string, string, string, bool, error) {
	claims, err := parseJWTClaims(subjectToken)
	if err != nil {
		return "", "", "", "", "", false, err
	}

	externalSub, _ := claims["sub"].(string)
	iss, _ := claims["iss"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	preferredUsername, _ := claims["preferred_username"].(string)
	if preferredUsername == "" {
		preferredUsername, _ = claims["username"].(string)
	}
	var emailVerified bool
	if ev, ok := claims["email_verified"].(bool); ok {
		emailVerified = ev
	} else if evStr, ok := claims["email_verified"].(string); ok {
		emailVerified = evStr == "true"
	}
	return externalSub, iss, email, name, preferredUsername, emailVerified, nil
}

func (s *OAuthService) parseExternalToken(subjectToken string, subjectTokenType string) (string, string, string, string, string, bool, error) {
	var externalSub, iss, email, name, preferredUsername string
	var emailVerified bool
	var err error

	if subjectTokenType == "urn:ietf:params:oauth:token-type:jwt" || subjectTokenType == "urn:ietf:params:oauth:token-type:id_token" {
		externalSub, iss, email, name, preferredUsername, emailVerified, err = parseJWTToken(subjectToken)
		if err != nil {
			return "", "", "", "", "", false, err
		}
	} else if strings.HasPrefix(subjectToken, "legacy-token:") {
		parts := strings.Split(subjectToken, ":")
		if len(parts) >= 4 {
			email = parts[1]
			preferredUsername = parts[2]
			externalSub = parts[3]
			iss = "legacy-system"
			emailVerified = true
		} else {
			return "", "", "", "", "", false, errors.New("invalid legacy token format")
		}
	} else {
		return "", "", "", "", "", false, errors.New("unsupported subject token type")
	}

	if externalSub == "" {
		return "", "", "", "", "", false, errors.New("external subject must not be empty")
	}

	return externalSub, iss, email, name, preferredUsername, emailVerified, nil
}

func matchExactIssuer(providers []model.IdentityProvider, iss string) *model.IdentityProvider {
	for _, p := range providers {
		if p.IssuerURL != "" && p.IssuerURL == iss {
			return &p
		}
		if p.Alias != "" && p.Alias == iss {
			return &p
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
	for _, p := range providers {
		for _, alias := range p.Config.DomainAliases {
			if strings.ToLower(alias) == emailDomain {
				return &p
			}
		}
	}
	return nil
}

func fallbackNonPasswordProvider(providers []model.IdentityProvider) *model.IdentityProvider {
	for _, p := range providers {
		if p.IDPType != model.UsernamePasswordIDPType {
			return &p
		}
	}
	if len(providers) > 0 {
		return &providers[0]
	}
	return nil
}

func (s *OAuthService) matchIdentityProvider(ctx context.Context, tenantID uuid.UUID, iss string, email string) (*model.IdentityProvider, error) {
	providers, err := s.storage.GetEnabledIdentityProviders(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("get enabled identity providers: %w", err)
	}

	if p := matchExactIssuer(providers, iss); p != nil {
		return p, nil
	}

	if p := matchDomainAlias(providers, email); p != nil {
		return p, nil
	}

	if p := fallbackNonPasswordProvider(providers); p != nil {
		return p, nil
	}

	return nil, errors.New("no matching identity provider found")
}

func (s *OAuthService) findUserProfile(ctx context.Context, tenantID uuid.UUID, provider *model.IdentityProvider, externalSub, email string, emailVerified bool) (*model.UserProfile, error) {
	// 1. Identity External ID Match (UserIdentifierClaim)
	identity, err := s.storage.GetIdentityByProviderAndExternalID(ctx, provider.ID, externalSub)
	if err == nil && identity != nil {
		profile, err := s.storage.GetUserProfileByID(ctx, tenantID, identity.UserProfileID)
		if err == nil && profile != nil {
			return profile, nil
		}
	}

	// 2. Verified Email Matching Fallback & Auto-Link
	if !emailVerified {
		return nil, port.ErrExternalEmailNotVerified
	}

	if email != "" {
		profile, err := s.storage.FindProfileByEmail(ctx, provider.PartitionID, email)
		if err == nil && profile != nil {
			// Auto-link: immediately persist link in identities table
			newIdentity := model.UserIdentity{
				ID:                 uuid.New(),
				UserProfileID:      profile.ID,
				IdentityProviderID: provider.ID,
				ExternalIdentityID: externalSub,
				CoupledAt:          s.clock.Now(),
			}
			_ = s.storage.UpsertIdentity(ctx, newIdentity)
			return profile, nil
		}
	}

	return nil, errors.New("user profile not found")
}

func (s *OAuthService) coupleUserIdentity(ctx context.Context, profileID uuid.UUID, providerID uuid.UUID, externalSub string, now time.Time) error {
	identity, err := s.storage.GetIdentityByProfileAndProvider(ctx, profileID, providerID)
	if err != nil || identity == nil {
		newIdentity := model.UserIdentity{
			ID:                 uuid.New(),
			UserProfileID:      profileID,
			IdentityProviderID: providerID,
			ExternalIdentityID: externalSub,
			CoupledAt:          now,
			LoginCount:         1,
			LastLoginAt:        now,
		}
		return s.storage.UpsertIdentity(ctx, newIdentity)
	}

	identity.LoginCount++
	identity.LastLoginAt = now
	return s.storage.UpsertIdentity(ctx, *identity)
}

func (s *OAuthService) mintTokensForExchangedUser(ctx context.Context, tenant *model.Tenant, client *model.ClientApplication, profileID string, dpopJKT string, now time.Time) (*model.TokenSetResponse, error) {
	issuer := tenant.GetBaseURL()
	accessToken, err := s.crypto.SignAccessToken(ctx, model.TokenClaims{
		TokenID:   uuid.NewString(),
		Issuer:    issuer,
		TenantID:  tenant.ID.String(),
		Subject:   profileID,
		ClientID:  client.ClientID,
		Scopes:    client.DefaultScopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(client.AccessTokenLifetime),
		Audiences: client.AllowedAudiences,
		DPoPHash:  dpopJKT,
	}, client.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("mint exchanged access token: %w", err)
	}

	idToken, err := s.crypto.SignIDToken(ctx, model.OIDCTokenClaims{
		TokenID:   uuid.NewString(),
		Issuer:    issuer,
		Subject:   profileID,
		Audience:  client.ClientID,
		TenantID:  tenant.ID.String(),
		IssuedAt:  now,
		ExpiresAt: now.Add(client.IDTokenLifetime),
		AuthTime:  now,
		Nonce:     uuid.NewString(),
	}, client.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("mint exchanged id token: %w", err)
	}

	tokenType := "Bearer"
	if dpopJKT != "" {
		tokenType = "DPoP"
	}

	refreshTokenVal := ""
	if client.EnforceRTR {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err == nil {
			refreshTokenVal = base64.RawURLEncoding.EncodeToString(bytes)
		}
		_ = s.storage.SaveRefreshToken(ctx, model.RefreshToken{
			TokenID:       refreshTokenVal,
			TenantID:      tenant.ID,
			ClientID:      client.ClientID,
			Subject:       profileID,
			Scopes:        client.DefaultScopes,
			TokenFamilyID: uuid.NewString(),
			IsUsed:        false,
			ExpiresAt:     now.Add(client.RefreshTokenLifetime),
			CreatedAt:     now,
		})
	}

	return &model.TokenSetResponse{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: refreshTokenVal,
		TokenType:    tokenType,
		ExpiresIn:    int64(client.AccessTokenLifetime / time.Second),
	}, nil
}

func (s *OAuthService) ProcessLogout(ctx context.Context, tenantID uuid.UUID, subject string, clientID string) ([]string, error) {
	_ = s.storage.RevokeSession(ctx, tenantID, subject, clientID)

	tenant, err := s.storage.ResolveTenantByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant: %w", err)
	}

	clients, err := s.storage.GetClientsByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("retrieve tenant clients for logout: %w", err)
	}

	var frontChannelURIs []string
	now := s.clock.Now()

	for _, client := range clients {
		if client.BackChannelLogoutURI != "" {
			logoutToken, err := s.crypto.SignLogoutToken(ctx, model.LogoutTokenClaims{
				TokenID:  uuid.NewString(),
				Issuer:   tenant.GetBaseURL(),
				Subject:  subject,
				Audience: client.ClientID,
				IssuedAt: now,
			}, client.Algorithm)
			if err == nil && s.notifier != nil {
				go func(uri, token string) {
					_ = s.notifier.SendBackChannelLogout(context.Background(), uri, token)
				}(client.BackChannelLogoutURI, logoutToken)
			}
		}

		if client.FrontChannelLogoutURI != "" {
			frontChannelURIs = append(frontChannelURIs, client.FrontChannelLogoutURI)
		}
	}

	return frontChannelURIs, nil
}

func (s *OAuthService) RevokeToken(ctx context.Context, tenantID uuid.UUID, clientID string, tokenStr string) error {
	parser := new(jwt.Parser)
	token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil
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
		expiresAt = s.clock.Now().Add(24 * time.Hour)
	}

	return s.storage.RevokeToken(ctx, tokenID, expiresAt)
}

func (s *OAuthService) IntrospectToken(ctx context.Context, tenantID uuid.UUID, clientID string, tokenStr string) (*model.IntrospectionResponse, error) {
	claims, err := s.crypto.VerifyToken(tokenStr)
	if err != nil {
		return &model.IntrospectionResponse{Active: false}, nil
	}

	tokenID, _ := claims["jti"].(string)
	expVal, _ := claims["exp"].(float64)
	if tokenID != "" {
		revoked, err := s.storage.IsTokenRevoked(ctx, tokenID)
		if err == nil && revoked {
			return &model.IntrospectionResponse{Active: false}, nil
		}
	}

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
