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

	"github.com/google/uuid"
)

type OAuthService struct {
	storage port.Storage
	crypto  port.Crypto
	event   port.Event
}

func NewOAuthService(s port.Storage, c port.Crypto, e port.Event) *OAuthService {
	return &OAuthService{storage: s, crypto: c, event: e}
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

func (s *OAuthService) ProcessLogout(ctx context.Context, tenantID uuid.UUID, subject string, clientID string, tokenJTI string) error {
	return s.storage.RevokeSession(ctx, tenantID, subject, clientID)
}
