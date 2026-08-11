package service

import (
	"context"
	"reflect"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/alexedwards/argon2id"
	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
)

func TestVerifyPassword_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	now := time.Now().Truncate(time.Second)
	clock := portmock.NewMockClock(now)
	service := NewIdentityProviderService(storage, clock)

	tenantID := uuid.New()
	userID := uuid.New()
	providerID := uuid.New()

	password := "MySecretPassword1"
	hash, _ := argon2id.CreateHash(password, argon2id.DefaultParams)

	identity := &model.UserIdentity{
		ID:                      uuid.New(),
		UserProfileID:           userID,
		IdentityProviderID:      providerID,
		Blocked:                 false,
		FailedVerificationCount: 2,
	}

	cred := &model.PasswordCredential{
		UserProfileID:      userID,
		IdentityProviderID: providerID,
		Argon2Hash:         hash,
	}

	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, userID).Return(&model.UserProfile{ID: userID, PartitionID: 1}, nil)
	storage.GetIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{
		{
			ID:          providerID,
			TenantID:    tenantID,
			IDPType:     model.UsernamePasswordIDPType,
			Enabled:     true,
			PartitionID: 1,
			Config: model.IdentityProviderConfig{
				MaxFailedVerificationCount: 3,
				PasswordBlockedTime:        60,
			},
		},
	}, nil)
	storage.GetIdentityByProfileAndProviderMock.Expect(context.Background(), userID, providerID).Return(identity, nil)
	storage.GetPasswordCredentialMock.Expect(context.Background(), userID, providerID).Return(cred, nil)

	storage.UpsertIdentityMock.Set(func(ctx context.Context, ident model.UserIdentity) error {
		if ident.FailedVerificationCount != 0 {
			t.Errorf("expected failed verification count to be reset to 0, got %d", ident.FailedVerificationCount)
		}
		if ident.LastVerificationAttemptAt.IsZero() {
			t.Error("expected LastVerificationAttemptAt to be set")
		}
		return nil
	})

	valid, err := service.VerifyPassword(context.Background(), tenantID, userID, password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected true, got false")
	}
}

func TestVerifyPassword_FailureAndBlocking(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	now := time.Now().Truncate(time.Second)
	clock := portmock.NewMockClock(now)
	service := NewIdentityProviderService(storage, clock)

	tenantID := uuid.New()
	userID := uuid.New()
	providerID := uuid.New()

	password := "MySecretPassword1"
	hash, _ := argon2id.CreateHash(password, argon2id.DefaultParams)

	identity := &model.UserIdentity{
		ID:                      uuid.New(),
		UserProfileID:           userID,
		IdentityProviderID:      providerID,
		Blocked:                 false,
		FailedVerificationCount: 2, // Next failure should block
	}

	cred := &model.PasswordCredential{
		UserProfileID:      userID,
		IdentityProviderID: providerID,
		Argon2Hash:         hash,
	}

	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, userID).Return(&model.UserProfile{ID: userID, PartitionID: 1}, nil)
	storage.GetIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{
		{
			ID:          providerID,
			TenantID:    tenantID,
			IDPType:     model.UsernamePasswordIDPType,
			Enabled:     true,
			PartitionID: 1,
			Config: model.IdentityProviderConfig{
				MaxFailedVerificationCount: 3,
				PasswordBlockedTime:        60,
			},
		},
	}, nil)
	storage.GetIdentityByProfileAndProviderMock.Expect(context.Background(), userID, providerID).Return(identity, nil)
	storage.GetPasswordCredentialMock.Expect(context.Background(), userID, providerID).Return(cred, nil)

	storage.UpsertIdentityMock.Set(func(ctx context.Context, ident model.UserIdentity) error {
		if ident.FailedVerificationCount != 3 {
			t.Errorf("expected failed verification count to be 3, got %d", ident.FailedVerificationCount)
		}
		if !ident.Blocked {
			t.Error("expected identity to be blocked")
		}
		return nil
	})

	valid, err := service.VerifyPassword(context.Background(), tenantID, userID, "WrongPassword")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected false, got true")
	}
}

func TestVerifyPassword_Blocked_RejectsWithinBlockedTime(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	now := time.Now().Truncate(time.Second)
	clock := portmock.NewMockClock(now)
	service := NewIdentityProviderService(storage, clock)

	tenantID := uuid.New()
	userID := uuid.New()
	providerID := uuid.New()

	identity := &model.UserIdentity{
		ID:                        uuid.New(),
		UserProfileID:             userID,
		IdentityProviderID:        providerID,
		Blocked:                   true,
		FailedVerificationCount:   3,
		LastVerificationAttemptAt: now.Add(-30 * time.Second), // 30s ago < 60s block time
	}

	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, userID).Return(&model.UserProfile{ID: userID, PartitionID: 1}, nil)
	storage.GetIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{
		{
			ID:          providerID,
			TenantID:    tenantID,
			IDPType:     model.UsernamePasswordIDPType,
			Enabled:     true,
			PartitionID: 1,
			Config: model.IdentityProviderConfig{
				MaxFailedVerificationCount: 3,
				PasswordBlockedTime:        60,
			},
		},
	}, nil)
	storage.GetIdentityByProfileAndProviderMock.Expect(context.Background(), userID, providerID).Return(identity, nil)

	storage.UpsertIdentityMock.Set(func(ctx context.Context, ident model.UserIdentity) error {
		if !ident.LastVerificationAttemptAt.Equal(now) {
			t.Error("expected LastVerificationAttemptAt to be updated to now")
		}
		return nil
	})

	valid, err := service.VerifyPassword(context.Background(), tenantID, userID, "MySecretPassword1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected false (blocked), got true")
	}
}

func TestVerifyPassword_Blocked_Expires_UnblocksWithCorrectPassword(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	now := time.Now().Truncate(time.Second)
	clock := portmock.NewMockClock(now)
	service := NewIdentityProviderService(storage, clock)

	tenantID := uuid.New()
	userID := uuid.New()
	providerID := uuid.New()

	password := "MySecretPassword1"
	hash, _ := argon2id.CreateHash(password, argon2id.DefaultParams)

	identity := &model.UserIdentity{
		ID:                        uuid.New(),
		UserProfileID:             userID,
		IdentityProviderID:        providerID,
		Blocked:                   true,
		FailedVerificationCount:   3,
		LastVerificationAttemptAt: now.Add(-90 * time.Second), // 90s ago > 60s block time
	}

	cred := &model.PasswordCredential{
		UserProfileID:      userID,
		IdentityProviderID: providerID,
		Argon2Hash:         hash,
	}

	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, userID).Return(&model.UserProfile{ID: userID, PartitionID: 1}, nil)
	storage.GetIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{
		{
			ID:          providerID,
			TenantID:    tenantID,
			IDPType:     model.UsernamePasswordIDPType,
			Enabled:     true,
			PartitionID: 1,
			Config: model.IdentityProviderConfig{
				MaxFailedVerificationCount: 3,
				PasswordBlockedTime:        60,
			},
		},
	}, nil)
	storage.GetIdentityByProfileAndProviderMock.Expect(context.Background(), userID, providerID).Return(identity, nil)
	storage.GetPasswordCredentialMock.Expect(context.Background(), userID, providerID).Return(cred, nil)

	storage.UpsertIdentityMock.Set(func(ctx context.Context, ident model.UserIdentity) error {
		if ident.Blocked {
			t.Error("expected identity to be unblocked")
		}
		if ident.FailedVerificationCount != 0 {
			t.Errorf("expected failed count to be reset to 0, got %d", ident.FailedVerificationCount)
		}
		return nil
	})

	valid, err := service.VerifyPassword(context.Background(), tenantID, userID, password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected true, got false")
	}
}

func TestIdentityProviderService_AuthenticateUsernamePassword_Success(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	now := time.Now().Truncate(time.Second)
	clock := portmock.NewMockClock(now)
	service := NewIdentityProviderService(storage, clock)

	tenantID := uuid.New()
	providerID := uuid.New()
	userProfileID := uuid.New()

	password := "SecretPass123!"
	hashedPassword, _ := argon2id.CreateHash(password, argon2id.DefaultParams)

	provider := model.IdentityProvider{
		ID:          providerID,
		TenantID:    tenantID,
		IDPType:     model.UsernamePasswordIDPType,
		Enabled:     true,
		Alias:       "username-password",
		PartitionID: 1,
		Config: model.IdentityProviderConfig{
			UsernameField:              "preferredUsername",
			MaxFailedVerificationCount: 5,
		},
	}

	profile := &model.UserProfile{
		ID:                userProfileID,
		PartitionID:       1,
		PreferredUsername: "john_doe",
	}

	cred := &model.PasswordCredential{
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		Argon2Hash:         hashedPassword,
	}

	identity := &model.UserIdentity{
		ID:                 uuid.New(),
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		LoginCount:         1,
	}

	var defaultPart int64 = 1
	storage.ResolveTenantByIDMock.Expect(context.Background(), tenantID).Return(&model.Tenant{ID: tenantID, DefaultPartition: &defaultPart}, nil)
	storage.GetEnabledIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{provider}, nil)
	storage.GetUserProfileByIdentifierMock.Expect(context.Background(), tenantID, int64(1), providerID, "john_doe").Return(profile, nil)
	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, userProfileID).Return(profile, nil)
	storage.GetIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{provider}, nil)
	storage.GetIdentityByProfileAndProviderMock.Expect(context.Background(), userProfileID, providerID).Return(identity, nil)
	storage.GetPasswordCredentialMock.Expect(context.Background(), userProfileID, providerID).Return(cred, nil)

	var upserted model.UserIdentity
	storage.UpsertIdentityMock.Set(func(ctx context.Context, ident model.UserIdentity) error {
		upserted = ident
		return nil
	})

	result, err := service.AuthenticateUsernamePassword(context.Background(), tenantID, 0, "john_doe", password)
	if err != nil {
		t.Fatalf("unexpected error during authentication: %v", err)
	}

	if result.UserProfile.ID != userProfileID {
		t.Errorf("expected user profile ID %s, got %s", userProfileID, result.UserProfile.ID)
	}

	if upserted.LoginCount != 2 {
		t.Errorf("expected login count to be incremented to 2, got %d", upserted.LoginCount)
	}
}

func TestIdentityProviderService_AuthenticateUsernamePassword_Failure(t *testing.T) {
	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	now := time.Now().Truncate(time.Second)
	clock := portmock.NewMockClock(now)
	service := NewIdentityProviderService(storage, clock)

	tenantID := uuid.New()
	providerID := uuid.New()
	userProfileID := uuid.New()

	hashedPassword, _ := argon2id.CreateHash("SecretPass123!", argon2id.DefaultParams)

	provider := model.IdentityProvider{
		ID:          providerID,
		TenantID:    tenantID,
		IDPType:     model.UsernamePasswordIDPType,
		Enabled:     true,
		Alias:       "username-password",
		PartitionID: 1,
		Config: model.IdentityProviderConfig{
			UsernameField:              "preferredUsername",
			MaxFailedVerificationCount: 5,
		},
	}

	profile := &model.UserProfile{
		ID:                userProfileID,
		PartitionID:       1,
		PreferredUsername: "john_doe",
	}

	cred := &model.PasswordCredential{
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		Argon2Hash:         hashedPassword,
	}

	identity := &model.UserIdentity{
		ID:                 uuid.New(),
		UserProfileID:      userProfileID,
		IdentityProviderID: providerID,
		LoginCount:         1,
	}

	var defaultPart int64 = 1
	storage.ResolveTenantByIDMock.Expect(context.Background(), tenantID).Return(&model.Tenant{ID: tenantID, DefaultPartition: &defaultPart}, nil)
	storage.GetEnabledIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{provider}, nil)
	storage.GetUserProfileByIdentifierMock.Expect(context.Background(), tenantID, int64(1), providerID, "john_doe").Return(profile, nil)
	storage.GetUserProfileByIDMock.Expect(context.Background(), tenantID, userProfileID).Return(profile, nil)
	storage.GetIdentityProvidersMock.Expect(context.Background(), tenantID).Return([]model.IdentityProvider{provider}, nil)
	storage.GetIdentityByProfileAndProviderMock.Expect(context.Background(), userProfileID, providerID).Return(identity, nil)
	storage.GetPasswordCredentialMock.Expect(context.Background(), userProfileID, providerID).Return(cred, nil)

	storage.UpsertIdentityMock.Return(nil)

	_, err := service.AuthenticateUsernamePassword(context.Background(), tenantID, 0, "john_doe", "WrongPass")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestNormalizeFederatedClaims(t *testing.T) {
	tests := []struct {
		name          string
		upstreamAMR   []string
		upstreamACR   string
		defaultAAL    int
		acrToTupleMap map[string]model.AcrTuple
		amrToAalMap   map[string]int
		want          SprezzAssuranceClaims
	}{
		{
			name:        "Fallback Baseline Single-Factor",
			upstreamAMR: []string{"pwd"},
			upstreamACR: "",
			defaultAAL:  1,
			want: SprezzAssuranceClaims{
				AMR: []string{"federated"},
				ACR: "urn:sprezz:assurance:aal1",
			},
		},
		{
			name:        "Dynamic Tuple Matrix match overrides default parameters",
			upstreamAMR: []string{"pwd"},
			upstreamACR: "urn:example:high_assurance",
			defaultAAL:  1,
			acrToTupleMap: map[string]model.AcrTuple{
				"urn:example:high_assurance": {AAL: 3, IAL: 2},
			},
			want: SprezzAssuranceClaims{
				AMR: []string{"federated", "hwk"},
				ACR: "urn:sprezz:assurance:aal3",
			},
		},
		{
			name:        "Level 0 inside Tuple defaults back to baseline",
			upstreamAMR: []string{"pwd"},
			upstreamACR: "urn:example:unmapped",
			defaultAAL:  2,
			acrToTupleMap: map[string]model.AcrTuple{
				"urn:example:unmapped": {AAL: 0, IAL: 1}, // AAL 0 means unmapped/none
			},
			want: SprezzAssuranceClaims{
				AMR: []string{"federated", "mfa"},
				ACR: "urn:sprezz:assurance:aal2",
			},
		},
		{
			name:        "Standard Entra ID MFA Auto-Detection Fallback Spec",
			upstreamAMR: []string{"pwd", "mfa"},
			upstreamACR: "",
			defaultAAL:  1,
			want: SprezzAssuranceClaims{
				AMR: []string{"federated", "mfa"},
				ACR: "urn:sprezz:assurance:aal2",
			},
		},
		{
			name:        "Custom Administrative AMR grid override takes precedent",
			upstreamAMR: []string{"pwd", "proprietary_code"},
			upstreamACR: "",
			defaultAAL:  1,
			amrToAalMap: map[string]int{"proprietary_code": 3},
			want: SprezzAssuranceClaims{
				AMR: []string{"federated", "hwk"},
				ACR: "urn:sprezz:assurance:aal3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeFederatedClaims(tt.upstreamAMR, tt.upstreamACR, tt.defaultAAL, tt.acrToTupleMap, tt.amrToAalMap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NormalizeFederatedClaims() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIdentityProviderService_ResolveFederatedLevels(t *testing.T) {
	tests := []struct {
		name         string
		config       model.IdentityProviderConfig
		externalAcr  string
		externalAmrs []string
		wantAAL      int
		wantIAL      int
	}{
		{
			name: "Perfect Match with AAL and IAL presence combined",
			config: model.IdentityProviderConfig{
				AAL: 1,
				IAL: 1,
				AcrToTuple: map[string]model.AcrTuple{
					"urn:example:secure": {AAL: 3, IAL: 2},
				},
			},
			externalAcr: "urn:example:secure",
			wantAAL:     3,
			wantIAL:     2,
		},
		{
			name: "Level 0 De-escalation triggers Fallback to IDP configuration defaults",
			config: model.IdentityProviderConfig{
				AAL: 2,
				IAL: 3,
				AcrToTuple: map[string]model.AcrTuple{
					"urn:example:unmapped": {AAL: 0, IAL: 0}, // 0 represents unmapped
				},
			},
			externalAcr: "urn:example:unmapped",
			wantAAL:     2, // falls back to config.AAL
			wantIAL:     3, // falls back to config.IAL
		},
		{
			name: "Partial Tuple Mapping leaves unmapped component as default",
			config: model.IdentityProviderConfig{
				AAL: 1,
				IAL: 2,
				AcrToTuple: map[string]model.AcrTuple{
					"urn:example:aalonly": {AAL: 3, IAL: 0},
				},
			},
			externalAcr: "urn:example:aalonly",
			wantAAL:     3, // Overridden by tuple map
			wantIAL:     2, // 0 leaves it as config.IAL
		},
		{
			name: "AMR evaluation overrides AAL baseline when higher",
			config: model.IdentityProviderConfig{
				AAL: 1,
				IAL: 1,
				AcrToTuple: map[string]model.AcrTuple{
					"urn:example:low": {AAL: 1, IAL: 1},
				},
				AmrToAAL: map[string]int{
					"mfa": 2,
				},
			},
			externalAcr:  "urn:example:low",
			externalAmrs: []string{"mfa"},
			wantAAL:      2, // Escalated by AMR check rule
			wantIAL:      1,
		},
	}

	ctrl := minimock.NewController(t)
	storage := portmock.NewStorageMock(ctrl)
	clock := portmock.NewMockClock(time.Now())
	service := NewIdentityProviderService(storage, clock)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAAL, gotIAL := service.ResolveFederatedLevels(tt.config, tt.externalAcr, tt.externalAmrs)
			if gotAAL != tt.wantAAL || gotIAL != tt.wantIAL {
				t.Errorf("ResolveFederatedLevels() = (aal: %d, ial: %d), want (aal: %d, ial: %d)", gotAAL, gotIAL, tt.wantAAL, tt.wantIAL)
			}
		})
	}
}
