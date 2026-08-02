package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
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
	service := NewOAuthService(storage, crypto, nil, nil)

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
	service := NewOAuthService(storage, crypto, nil, nil)

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
	service := NewOAuthService(storage, nil, nil, nil)

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

func TestOAuthService_IntrospectToken_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	service := NewOAuthService(storage, crypto, nil, nil)

	tenantID := uuid.New()
	clientID := "test-client"
	tokenStr := "active-token"
	tokenID := "jti-value"
	exp := time.Now().Add(time.Hour)

	claims := map[string]any{
		"jti":       tokenID,
		"exp":       float64(exp.Unix()),
		"scope":     "openid profile",
		"client_id": clientID,
		"sub":       "user-123",
		"iss":       "https://idp.com",
		"tid":       tenantID.String(),
		"iat":       float64(time.Now().Unix()),
	}

	crypto.VerifyTokenMock.Expect(tokenStr).Return(claims, nil)
	storage.IsTokenRevokedMock.Expect(context.Background(), tokenID).Return(false, nil)

	res, err := service.IntrospectToken(context.Background(), tenantID, clientID, tokenStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !res.Active {
		t.Error("expected token to be active")
	}
	if res.ClientID != clientID {
		t.Errorf("expected client_id %s, got %s", clientID, res.ClientID)
	}
}

func TestOAuthService_IntrospectToken_Revoked(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	service := NewOAuthService(storage, crypto, nil, nil)

	tenantID := uuid.New()
	clientID := "test-client"
	tokenStr := "revoked-token"
	tokenID := "jti-value"

	claims := map[string]any{
		"jti": tokenID,
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}

	crypto.VerifyTokenMock.Expect(tokenStr).Return(claims, nil)
	storage.IsTokenRevokedMock.Expect(context.Background(), tokenID).Return(true, nil)

	res, err := service.IntrospectToken(context.Background(), tenantID, clientID, tokenStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Active {
		t.Error("expected token to be inactive")
	}
}

func TestOAuthService_InitiateAuthorize_ValidationErrors(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	service := NewOAuthService(storage, nil, nil, nil)

	// Empty Code
	sessionEmptyCode := model.AuthorizationCodeSession{
		RedirectURI: "https://example.com/callback",
	}
	if err := service.InitiateAuthorize(context.Background(), sessionEmptyCode); err == nil || err.Error() != "authorize code must not be empty" {
		t.Errorf("expected empty code error, got %v", err)
	}

	// Empty RedirectURI
	sessionEmptyRedirect := model.AuthorizationCodeSession{
		Code: "code",
	}
	if err := service.InitiateAuthorize(context.Background(), sessionEmptyRedirect); err == nil || err.Error() != "redirect_uri must not be empty" {
		t.Errorf("expected empty redirect_uri error, got %v", err)
	}
}

func TestOAuthService_ExchangeCodeForTokens_Errors(t *testing.T) {
	tenantID := uuid.New()
	clientID := "client-id"
	code := "some-code"

	// 1. GetClient returns error
	{
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		service := NewOAuthService(storage, nil, nil, nil)
		storage.GetClientMock.Expect(context.Background(), tenantID, clientID).Return(nil, errors.New("client lookup failed"))

		_, err := service.ExchangeCodeForTokens(context.Background(), tenantID, clientID, code, "verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	}

	// 2. ResolveTenantByID returns error
	{
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		service := NewOAuthService(storage, nil, nil, nil)
		storage.GetClientMock.Expect(context.Background(), tenantID, clientID).Return(&model.ClientApplication{}, nil)
		storage.ResolveTenantByIDMock.Expect(context.Background(), tenantID).Return(nil, errors.New("tenant lookup failed"))

		_, err := service.ExchangeCodeForTokens(context.Background(), tenantID, clientID, code, "verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	}

	// 3. GetAndConsumeAuthSession returns error
	{
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		service := NewOAuthService(storage, nil, nil, nil)
		storage.GetClientMock.Expect(context.Background(), tenantID, clientID).Return(&model.ClientApplication{}, nil)
		storage.ResolveTenantByIDMock.Expect(context.Background(), tenantID).Return(&model.Tenant{}, nil)
		storage.GetAndConsumeAuthSessionMock.Expect(context.Background(), tenantID, code).Return(nil, errors.New("session not found"))

		_, err := service.ExchangeCodeForTokens(context.Background(), tenantID, clientID, code, "verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	}

	// 4. Invalid PKCE verifier
	{
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		service := NewOAuthService(storage, nil, nil, nil)
		storage.GetClientMock.Expect(context.Background(), tenantID, clientID).Return(&model.ClientApplication{}, nil)
		storage.ResolveTenantByIDMock.Expect(context.Background(), tenantID).Return(&model.Tenant{Domain: "example.com"}, nil)
		storage.GetAndConsumeAuthSessionMock.Expect(context.Background(), tenantID, code).Return(&model.AuthorizationCodeSession{
			CodeChallenge: "expected-challenge",
		}, nil)

		_, err := service.ExchangeCodeForTokens(context.Background(), tenantID, clientID, code, "invalid-verifier")
		if err == nil || err.Error() != "invalid PKCE verifier" {
			t.Errorf("expected PKCE validation error, got %v", err)
		}
	}

	// 5. SignAccessToken error
	{
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		crypto := portmock.NewCryptoMock(ctrl)
		service := NewOAuthService(storage, crypto, nil, nil)

		storage.GetClientMock.Expect(context.Background(), tenantID, clientID).Return(&model.ClientApplication{Algorithm: model.AlgRS256}, nil)
		storage.ResolveTenantByIDMock.Expect(context.Background(), tenantID).Return(&model.Tenant{Domain: "example.com"}, nil)
		storage.GetAndConsumeAuthSessionMock.Expect(context.Background(), tenantID, code).Return(&model.AuthorizationCodeSession{}, nil)
		crypto.SignAccessTokenMock.Set(func(claims model.TokenClaims, alg model.SignatureAlgorithm) (string, error) {
			return "", errors.New("sign error")
		})

		_, err := service.ExchangeCodeForTokens(context.Background(), tenantID, clientID, code, "verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	}

	// 6. SignIDToken error
	{
		ctrl := minimock.NewController(t)
		storage := portmock.NewStorageMock(ctrl)
		crypto := portmock.NewCryptoMock(ctrl)
		service := NewOAuthService(storage, crypto, nil, nil)

		storage.GetClientMock.Expect(context.Background(), tenantID, clientID).Return(&model.ClientApplication{Algorithm: model.AlgRS256}, nil)
		storage.ResolveTenantByIDMock.Expect(context.Background(), tenantID).Return(&model.Tenant{Domain: "example.com"}, nil)
		storage.GetAndConsumeAuthSessionMock.Expect(context.Background(), tenantID, code).Return(&model.AuthorizationCodeSession{}, nil)
		crypto.SignAccessTokenMock.Set(func(claims model.TokenClaims, alg model.SignatureAlgorithm) (string, error) {
			return "access-token", nil
		})
		crypto.SignIDTokenMock.Set(func(claims model.OIDCTokenClaims, alg model.SignatureAlgorithm) (string, error) {
			return "", errors.New("sign error")
		})

		_, err := service.ExchangeCodeForTokens(context.Background(), tenantID, clientID, code, "verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	}
}

func TestOAuthService_ProcessLogout(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	notifier := portmock.NewLogoutNotifierMock(ctrl)
	crypto := portmock.NewCryptoMock(ctrl)
	service := NewOAuthService(storage, crypto, nil, notifier)

	tenantID := uuid.New()
	subject := "sub"
	clientID := "client-id"

	client := model.ClientApplication{
		ID:                    uuid.NewString(),
		TenantID:              tenantID,
		ClientID:              clientID,
		FrontChannelLogoutURI: "https://example.com/front",
		BackChannelLogoutURI:  "https://example.com/back",
		Algorithm:             model.AlgRS256,
	}

	storage.RevokeSessionMock.Expect(context.Background(), tenantID, subject, clientID).Return(nil)
	storage.GetClientsByTenantMock.Expect(context.Background(), tenantID).Return([]model.ClientApplication{client}, nil)
	crypto.SignLogoutTokenMock.Set(func(claims model.LogoutTokenClaims, alg model.SignatureAlgorithm) (string, error) {
		return "logout-token", nil
	})
	notifier.SendBackChannelLogoutMock.Set(func(ctx context.Context, logoutURI string, logoutToken string) error {
		return nil
	})

	frontURIs, err := service.ProcessLogout(context.Background(), tenantID, subject, clientID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	if len(frontURIs) != 1 || frontURIs[0] != "https://example.com/front" {
		t.Errorf("unexpected front-channel URIs: %v", frontURIs)
	}
}

func TestOAuthService_RevokeToken_NoJTIOrClaims(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	service := NewOAuthService(storage, nil, nil, nil)

	// Revoking completely invalid string should not return error (fails silently)
	err := service.RevokeToken(context.Background(), uuid.New(), "client", "invalid-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Token with empty claims (or empty JTI) should also fail silently
	tokenNoJTI := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{})
	tokenString, _ := tokenNoJTI.SignedString([]byte("key"))
	err = service.RevokeToken(context.Background(), uuid.New(), "client", tokenString)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
