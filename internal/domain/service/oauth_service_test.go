package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestOAuthService_InitiateAuthorizePersistsSession(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := port.NewStorageMock(ctrl)
	crypto := port.NewCryptoMock(ctrl)
	service := NewOAuthService(storage, crypto, nil)

	session := model.AuthorizationCodeSession{
		Code:            uuid.NewString(),
		TenantID:        uuid.NewString(),
		ClientID:        "client-id",
		Subject:         "subject-1",
		RedirectURI:     "https://example.com/callback",
		CodeChallenge:   "challenge",
		ChallengeMethod: "S256",
		Scopes:          []string{"openid", "profile"},
		ExpiresAt:       time.Now().UTC().Add(10 * time.Minute),
	}

	storage.SaveAuthSessionMock.Expect(context.Background(), session).Return(nil)

	if err := service.InitiateAuthorize(context.Background(), session); err != nil {
		t.Fatalf("InitiateAuthorize returned error: %v", err)
	}
}

func TestOAuthService_ExchangeCodeForTokensMintsTokens(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := port.NewStorageMock(ctrl)
	crypto := port.NewCryptoMock(ctrl)
	service := NewOAuthService(storage, crypto, nil)

	tenantID := uuid.New()
	clientID := "client-id"
	code := uuid.NewString()
	codeVerifier := "verifier-value"
	codeChallenge := pkceChallenge(codeVerifier)
	client := &model.ClientApplication{
		ID:                   uuid.NewString(),
		TenantID:             tenantID,
		ClientID:             clientID,
		ClientName:           "test-client",
		RedirectURIs:         []string{"https://example.com/callback"},
		Algorithm:            model.AlgRS256,
		AccessTokenLifetime:  time.Hour,
		IDTokenLifetime:      time.Minute,
		RefreshTokenLifetime: 24 * time.Hour,
		DefaultScopes:        []string{"openid", "profile"},
	}
	authSession := &model.AuthorizationCodeSession{
		Code:            code,
		TenantID:        tenantID.String(),
		ClientID:        clientID,
		Subject:         "subject-1",
		CodeChallenge:   codeChallenge,
		ChallengeMethod: "S256",
		RedirectURI:     "https://example.com/callback",
		Scopes:          client.DefaultScopes,
		ExpiresAt:       time.Now().UTC().Add(5 * time.Minute),
	}

	storage.GetClientMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, gotClientID string) (*model.ClientApplication, error) {
		if gotTenantID != tenantID {
			t.Fatalf("unexpected tenant ID %s", gotTenantID)
		}
		if gotClientID != clientID {
			t.Fatalf("unexpected client ID %s", gotClientID)
		}
		return client, nil
	})
	storage.GetAndConsumeAuthSessionMock.Set(func(ctx context.Context, gotTenantID uuid.UUID, gotCode string) (*model.AuthorizationCodeSession, error) {
		if gotTenantID != tenantID {
			t.Fatalf("unexpected tenant ID %s", gotTenantID)
		}
		if gotCode != code {
			t.Fatalf("unexpected code %s", gotCode)
		}
		return authSession, nil
	})
	crypto.SignAccessTokenMock.Set(func(claims model.TokenClaims, alg model.SignatureAlgorithm) (string, error) {
		if alg != model.AlgRS256 {
			t.Fatalf("unexpected signing algorithm %s", alg)
		}
		return "access-token", nil
	})
	crypto.SignIDTokenMock.Set(func(claims model.OIDCTokenClaims, alg model.SignatureAlgorithm) (string, error) {
		if alg != model.AlgRS256 {
			t.Fatalf("unexpected signing algorithm %s", alg)
		}
		return "id-token", nil
	})

	tokens, err := service.ExchangeCodeForTokens(context.Background(), tenantID, clientID, code, codeVerifier)
	if err != nil {
		t.Fatalf("ExchangeCodeForTokens returned error: %v", err)
	}
	if tokens.AccessToken != "access-token" {
		t.Fatalf("expected access token to be returned, got %q", tokens.AccessToken)
	}
	if tokens.IDToken != "id-token" {
		t.Fatalf("expected id token to be returned, got %q", tokens.IDToken)
	}
	if tokens.TokenType != "Bearer" {
		t.Fatalf("expected bearer token type, got %q", tokens.TokenType)
	}
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
