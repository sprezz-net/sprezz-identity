package service

import (
	"context"
	"strings"
	"testing"

	"sprezz-identity/internal/domain/model"
)

func TestOAuthValidatorService_ValidateRedirect(t *testing.T) {
	v := NewOAuthValidatorService()
	ctx := context.Background()

	tenant := &model.Tenant{
		Config: model.TenantConfig{
			RedirectWhitelist: []string{
				"https://example.com/callback",
				"https://*.example.com/*",
				"/^https:\\/\\/app-[0-9]+\\.example\\.com\\/auth$/",
			},
		},
	}

	client := &model.ClientApplication{
		RedirectURIs: []string{
			"https://example.com/callback",
			"https://app-123.example.com/auth",
			"https://sub.example.com/oauth",
			"https://unwhitelisted.com/callback",
		},
	}

	tests := []struct {
		name        string
		redirectURL string
		useClient   bool
		wantErr     error
	}{
		{
			name:        "Valid literal match, client allowed",
			redirectURL: "https://example.com/callback",
			useClient:   true,
			wantErr:     nil,
		},
		{
			name:        "Valid literal match, no client context",
			redirectURL: "https://example.com/callback",
			useClient:   false,
			wantErr:     nil,
		},
		{
			name:        "Valid glob match, client allowed",
			redirectURL: "https://sub.example.com/oauth",
			useClient:   true,
			wantErr:     nil,
		},
		{
			name:        "Valid regex match, client allowed",
			redirectURL: "https://app-123.example.com/auth",
			useClient:   true,
			wantErr:     nil,
		},
		{
			name:        "Client allowed but not whitelisted",
			redirectURL: "https://unwhitelisted.com/callback",
			useClient:   true,
			wantErr:     ErrRedirectNotAllowed,
		},
		{
			name:        "Whitelisted but client does not allow",
			redirectURL: "https://another.example.com/any",
			useClient:   true,
			wantErr:     ErrClientRedirectNotAllowed,
		},
		{
			name:        "Whitelisted, no client context",
			redirectURL: "https://another.example.com/any",
			useClient:   false,
			wantErr:     nil,
		},
		{
			name:        "Not whitelisted, no client context",
			redirectURL: "https://malicious.com",
			useClient:   false,
			wantErr:     ErrRedirectNotAllowed,
		},
		{
			name:        "Empty redirect URL",
			redirectURL: "",
			useClient:   false,
			wantErr:     ErrInvalidRedirectURI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cl *model.ClientApplication
			if tt.useClient {
				cl = client
			}
			err := v.ValidateRedirect(ctx, tenant, cl, tt.redirectURL)
			if err != tt.wantErr {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestOAuthValidatorService_ValidateScopes(t *testing.T) {
	v := NewOAuthValidatorService()
	ctx := context.Background()

	tenant := &model.Tenant{
		Config: model.TenantConfig{
			PredefinedScopes: []string{"openid", "profile", "email", "offline_access", "custom-scope"},
		},
	}

	client := &model.ClientApplication{
		AllowedScopes: []string{"openid", "profile", "email"},
	}

	tests := []struct {
		name      string
		scopes    []string
		useClient bool
		wantErr   error
	}{
		{
			name:      "Valid scopes with client",
			scopes:    []string{"openid", "profile"},
			useClient: true,
			wantErr:   nil,
		},
		{
			name:      "Valid scopes without client",
			scopes:    []string{"openid", "profile", "custom-scope"},
			useClient: false,
			wantErr:   nil,
		},
		{
			name:      "Invalid client scope",
			scopes:    []string{"openid", "custom-scope"},
			useClient: true,
			wantErr:   ErrClientScopesNotAllowed,
		},
		{
			name:      "Invalid tenant scope",
			scopes:    []string{"openid", "malicious-scope"},
			useClient: false,
			wantErr:   ErrScopesNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cl *model.ClientApplication
			if tt.useClient {
				cl = client
			}
			err := v.ValidateScopes(ctx, tenant, cl, tt.scopes)
			if err != tt.wantErr {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestOAuthValidatorService_ValidateAudiences(t *testing.T) {
	v := NewOAuthValidatorService()
	ctx := context.Background()

	tenant := &model.Tenant{
		Config: model.TenantConfig{
			PredefinedAudiences: []string{"https://api.example.com", "https://api.internal"},
		},
	}

	client := &model.ClientApplication{
		AllowedAudiences: []string{"https://api.example.com"},
	}

	tests := []struct {
		name      string
		audiences []string
		useClient bool
		wantErr   error
	}{
		{
			name:      "Valid audience with client",
			audiences: []string{"https://api.example.com"},
			useClient: true,
			wantErr:   nil,
		},
		{
			name:      "Valid audience without client",
			audiences: []string{"https://api.example.com", "https://api.internal"},
			useClient: false,
			wantErr:   nil,
		},
		{
			name:      "Invalid client audience",
			audiences: []string{"https://api.internal"},
			useClient: true,
			wantErr:   ErrClientAudiencesNotAllowed,
		},
		{
			name:      "Invalid tenant audience",
			audiences: []string{"https://api.malicious.com"},
			useClient: false,
			wantErr:   ErrAudiencesNotAllowed,
		},
		{
			name:      "Empty audiences list is always valid",
			audiences: []string{},
			useClient: true,
			wantErr:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cl *model.ClientApplication
			if tt.useClient {
				cl = client
			}
			err := v.ValidateAudiences(ctx, tenant, cl, tt.audiences)
			if err != tt.wantErr {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestOAuthValidatorService_ValidateACR_Default(t *testing.T) {
	v := NewOAuthValidatorService()
	ctx := context.Background()

	tenant := &model.Tenant{
		Config: model.TenantConfig{
			ACREssential: false,
			ACRToLevels: map[string]model.Levels{
				"aal2": {AAL: 2},
				"aal3": {AAL: 3},
				"ial3": {IAL: 3},
			},
		},
	}

	provider := &model.IdentityProvider{
		Config: model.IdentityProviderConfig{
			IAL: 1,
			AAL: 2,
		},
	}

	reached, err := v.ValidateACR(ctx, tenant, provider, "aal3", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(reached, "aal2") {
		t.Fatalf("expected reached acr to contain aal2, got %q", reached)
	}
}

func TestOAuthValidatorService_ValidateACR_Essential_OR(t *testing.T) {
	v := NewOAuthValidatorService()
	ctx := context.Background()

	tenant := &model.Tenant{
		Config: model.TenantConfig{
			ACREssential: true,
			ACRToLevels: map[string]model.Levels{
				"aal2": {AAL: 2},
				"aal3": {AAL: 3},
				"ial3": {IAL: 3},
			},
		},
	}

	providerMet := &model.IdentityProvider{
		Config: model.IdentityProviderConfig{
			IAL: 1,
			AAL: 2,
		},
	}
	providerUnmet := &model.IdentityProvider{
		Config: model.IdentityProviderConfig{
			IAL: 1,
			AAL: 1,
		},
	}

	reached, err := v.ValidateACR(ctx, tenant, providerMet, "aal3 aal2", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(reached, "aal2") {
		t.Fatalf("expected reached acr to contain aal2, got %q", reached)
	}

	_, err = v.ValidateACR(ctx, tenant, providerUnmet, "aal3 aal2", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestOAuthValidatorService_ValidateACR_Essential_AND(t *testing.T) {
	v := NewOAuthValidatorService()
	ctx := context.Background()

	tenant := &model.Tenant{
		Config: model.TenantConfig{
			ACREssential: true,
			ACRToLevels: map[string]model.Levels{
				"aal2": {AAL: 2},
				"aal3": {AAL: 3},
				"ial3": {IAL: 3},
			},
		},
	}

	providerMet := &model.IdentityProvider{
		Config: model.IdentityProviderConfig{
			IAL: 3,
			AAL: 2,
		},
	}
	providerUnmet := &model.IdentityProvider{
		Config: model.IdentityProviderConfig{
			IAL: 1,
			AAL: 2,
		},
	}

	reached, err := v.ValidateACR(ctx, tenant, providerMet, "ial3-aal2", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(reached, "aal2") || !strings.Contains(reached, "ial3") {
		t.Fatalf("expected reached acr to contain aal2 and ial3, got %q", reached)
	}

	_, err = v.ValidateACR(ctx, tenant, providerUnmet, "ial3-aal2", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestOAuthValidatorService_ValidateACR_ClaimsJSON(t *testing.T) {
	v := NewOAuthValidatorService()
	ctx := context.Background()

	tenant := &model.Tenant{
		Config: model.TenantConfig{
			ACREssential: false,
			ACRToLevels: map[string]model.Levels{
				"aal2": {AAL: 2},
				"aal3": {AAL: 3},
				"ial3": {IAL: 3},
			},
		},
	}

	providerMet := &model.IdentityProvider{
		Config: model.IdentityProviderConfig{
			IAL: 1,
			AAL: 3,
		},
	}
	providerUnmet := &model.IdentityProvider{
		Config: model.IdentityProviderConfig{
			IAL: 1,
			AAL: 1,
		},
	}

	claims := `{"id_token":{"acr":{"essential":true,"values":["aal3","aal2"]}}}`

	reached, err := v.ValidateACR(ctx, tenant, providerMet, "", claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(reached, "aal2") || !strings.Contains(reached, "aal3") {
		t.Fatalf("expected reached acr to contain aal2 and aal3, got %q", reached)
	}

	_, err = v.ValidateACR(ctx, tenant, providerUnmet, "", claims)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
