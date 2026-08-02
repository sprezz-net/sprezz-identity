package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
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
}

func NewOAuthService(s port.Storage, c port.Crypto, e port.Event, n port.LogoutNotifier) *OAuthService {
	return &OAuthService{storage: s, crypto: c, event: e, notifier: n}
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

func (s *OAuthService) ExchangeCodeForTokens(ctx context.Context, tenantID uuid.UUID, clientID string, code string, codeVerifier string) (*model.TokenSetResponse, error) {
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

	issuer := "https://" + tenant.Domain
	now := time.Now().UTC()
	accessToken, err := s.crypto.SignAccessToken(model.TokenClaims{
		TokenID:   uuid.NewString(),
		Issuer:    issuer,
		TenantID:  tenantID.String(),
		Subject:   authSession.Subject,
		ClientID:  clientID,
		Scopes:    authSession.Scopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(client.AccessTokenLifetime),
	}, client.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("mint access token: %w", err)
	}

	idToken, err := s.crypto.SignIDToken(model.OIDCTokenClaims{
		TokenID:   uuid.NewString(),
		Issuer:    issuer,
		Subject:   authSession.Subject,
		Audience:  clientID,
		TenantID:  tenantID.String(),
		IssuedAt:  now,
		ExpiresAt: now.Add(client.IDTokenLifetime),
		AuthTime:  now,
		Nonce:     uuid.NewString(),
		SessionID: authSession.Code,
	}, client.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("mint id token: %w", err)
	}

	return &model.TokenSetResponse{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: uuid.NewString(),
		TokenType:    "Bearer",
		ExpiresIn:    int64(client.AccessTokenLifetime / time.Second),
	}, nil
}

func (s *OAuthService) ProcessLogout(ctx context.Context, tenantID uuid.UUID, subject string, clientID string) ([]string, error) {
	_ = s.storage.RevokeSession(ctx, tenantID, subject, clientID)

	clients, err := s.storage.GetClientsByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("retrieve tenant clients for logout: %w", err)
	}

	var frontChannelURIs []string
	now := time.Now().UTC()

	for _, client := range clients {
		if client.BackChannelLogoutURI != "" {
			logoutToken, err := s.crypto.SignLogoutToken(model.LogoutTokenClaims{
				TokenID:  uuid.NewString(),
				Issuer:   "https://" + client.TenantID.String(),
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
		expiresAt = time.Now().Add(24 * time.Hour)
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
	if time.Now().After(exp) {
		return &model.IntrospectionResponse{Active: false}, nil
	}

	scope, _ := claims["scope"].(string)
	tokenClientID, _ := claims["client_id"].(string)
	sub, _ := claims["sub"].(string)
	iss, _ := claims["iss"].(string)
	tid, _ := claims["tid"].(string)
	iatVal, _ := claims["iat"].(float64)

	return &model.IntrospectionResponse{
		Active:    true,
		Scope:     scope,
		ClientID:  tokenClientID,
		Subject:   sub,
		ExpiresAt: int64(expVal),
		IssuedAt:  int64(iatVal),
		Issuer:    iss,
		TokenType: "Bearer",
		TenantID:  tid,
	}, nil
}
