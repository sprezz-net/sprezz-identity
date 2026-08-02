package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestOAuthService_InitiateAuthorizePersistsSession(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
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
	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	service := NewOAuthService(storage, crypto, nil)

	tenantID := uuid.New()
	tenant := &model.Tenant{
		ID:     tenantID,
		Domain: "example.com",
	}
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

	storage.ResolveTenantByIDMock.Expect(context.Background(), tenantID).Return(tenant, nil)
	storage.GetClientMock.Expect(context.Background(), tenantID, clientID).Return(client, nil)
	storage.GetAndConsumeAuthSessionMock.Expect(context.Background(), tenantID, code).Return(authSession, nil)
	crypto.SignAccessTokenMock.Set(func(claims model.TokenClaims, alg model.SignatureAlgorithm) (string, error) {
		return "access-token", nil
	})
	crypto.SignIDTokenMock.Set(func(claims model.OIDCTokenClaims, alg model.SignatureAlgorithm) (string, error) {
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

func TestOAuthService_RevokeToken_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	service := NewOAuthService(storage, nil, nil)

	tenantID := uuid.New()
	clientID := "test-client"
	tokenID := uuid.NewString()
	exp := time.Now().Add(time.Hour).Truncate(time.Second)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"jti": tokenID,
		"exp": exp.Unix(),
	})
	tokenString, err := token.SignedString([]byte("mock-signing-key"))
	if err != nil {
		t.Fatalf("failed to create JWT token: %v", err)
	}

	storage.RevokeTokenMock.Set(func(ctx context.Context, gotTokenID string, gotExpiresAt time.Time) error {
		if gotTokenID != tokenID {
			t.Errorf("expected TokenID %s, got %s", tokenID, gotTokenID)
		}
		if gotExpiresAt.Unix() != exp.Unix() {
			t.Errorf("expected ExpiresAt %v, got %v", exp, gotExpiresAt)
		}
		return nil
	})

	err = service.RevokeToken(context.Background(), tenantID, clientID, tokenString)
	if err != nil {
		t.Fatalf("unexpected error during token revocation: %v", err)
	}
}
