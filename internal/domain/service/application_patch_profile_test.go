package service_test

import (
	"context"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func storedProfile() model.ApplicationProfile {
	return model.ApplicationProfile{
		ID:                      uuid.New(),
		ProfileName:             "web",
		IsEnabled:               true,
		TokenEndpointAuthMethod: model.AuthMethodClientSecretPost,
		GrantTypes:              []model.GrantType{model.GrantTypeAuthorizationCode},
		ResponseTypes:           []model.ResponseType{model.ResponseTypeCode},
		AccessTokenLifetime:     15 * time.Minute,
		IDTokenLifetime:         15 * time.Minute,
		RefreshTokenLifetime:    24 * time.Hour,
		SigningAlgorithm:        model.AlgRS256,
	}
}

func (f *appServiceFixture) stubStoredProfile(p model.ApplicationProfile) {
	f.admin.GetApplicationProfileByIDMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, id uuid.UUID) (*model.ApplicationProfile, error) {
		clone := p
		return &clone, nil
	})
}

func TestApplicationService_PatchProfile_Sections(t *testing.T) {
	tests := []struct {
		name  string
		patch port.PatchProfileCommand
		check func(t *testing.T, before, after model.ApplicationProfile)
	}{
		{
			name: "lifetimes",
			patch: port.PatchProfileCommand{
				Section: port.ProfileSectionLifetimes, AccessTokenLifetime: 5 * time.Minute,
				IDTokenLifetime: 10 * time.Minute, RefreshTokenLifetime: 48 * time.Hour,
			},
			check: func(t *testing.T, before, after model.ApplicationProfile) {
				assert.Equal(t, 5*time.Minute, after.AccessTokenLifetime)
				assert.Equal(t, 48*time.Hour, after.RefreshTokenLifetime)
				assert.Equal(t, before.TokenEndpointAuthMethod, after.TokenEndpointAuthMethod)
				assert.Equal(t, before.ProfileName, after.ProfileName)
			},
		},
		{
			name: "authentication",
			patch: port.PatchProfileCommand{
				Section: port.ProfileSectionAuthentication, TokenEndpointAuthMethod: model.AuthMethodNone,
				SigningAlgorithm: model.AlgES256, GrantTypes: []model.GrantType{model.GrantTypeAuthorizationCode},
			},
			check: func(t *testing.T, before, after model.ApplicationProfile) {
				assert.Equal(t, model.AuthMethodNone, after.TokenEndpointAuthMethod)
				assert.Equal(t, model.AlgES256, after.SigningAlgorithm)
				assert.True(t, after.EnforceRTR, "public clients always rotate refresh tokens")
				assert.Equal(t, before.AccessTokenLifetime, after.AccessTokenLifetime)
			},
		},
		{
			name:  "general",
			patch: port.PatchProfileCommand{Section: port.ProfileSectionGeneral, ProfileName: "  renamed ", IsEnabled: false},
			check: func(t *testing.T, before, after model.ApplicationProfile) {
				assert.Equal(t, "renamed", after.ProfileName)
				assert.False(t, after.IsEnabled)
				assert.Equal(t, before.AccessTokenLifetime, after.AccessTokenLifetime)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newAppServiceFixture(t)
			before := storedProfile()
			f.stubStoredProfile(before)
			var after model.ApplicationProfile
			f.admin.UpdateApplicationProfileMock.Set(func(ctx context.Context, tenantUUID uuid.UUID, p model.ApplicationProfile) error {
				after = p
				return nil
			})

			tt.patch.TenantID, tt.patch.ID = f.tenantID, before.ID
			require.NoError(t, f.svc.PatchProfile(context.Background(), tt.patch))
			tt.check(t, before, after)
		})
	}
}

func TestApplicationService_PatchProfile_Rejections(t *testing.T) {
	newFixture := func(t *testing.T, p model.ApplicationProfile) *appServiceFixture {
		f := newAppServiceFixture(t)
		f.stubStoredProfile(p)
		f.admin.UpdateApplicationProfileMock.Optional().Set(func(ctx context.Context, tenantUUID uuid.UUID, p model.ApplicationProfile) error {
			t.Error("an invalid profile must not be stored")
			return nil
		})
		return f
	}
	fieldsOf := func(t *testing.T, err error) map[string]string {
		var verr *port.ValidationError
		require.ErrorAs(t, err, &verr)
		return verr.Fields
	}

	t.Run("lifetime out of range", func(t *testing.T) {
		before := storedProfile()
		f := newFixture(t, before)
		err := f.svc.PatchProfile(context.Background(), port.PatchProfileCommand{
			TenantID: f.tenantID, ID: before.ID, Section: port.ProfileSectionLifetimes,
			AccessTokenLifetime: 30 * time.Second, IDTokenLifetime: 10 * time.Minute, RefreshTokenLifetime: 365 * 24 * time.Hour,
		})
		fields := fieldsOf(t, err)
		assert.Contains(t, fields, "access_token_lifetime")
		assert.Contains(t, fields, "refresh_token_lifetime")
	})

	t.Run("public client with client credentials", func(t *testing.T) {
		before := storedProfile()
		f := newFixture(t, before)
		err := f.svc.PatchProfile(context.Background(), port.PatchProfileCommand{
			TenantID: f.tenantID, ID: before.ID, Section: port.ProfileSectionAuthentication,
			TokenEndpointAuthMethod: model.AuthMethodNone, SigningAlgorithm: model.AlgRS256,
			GrantTypes: []model.GrantType{model.GrantTypeClientCredentials},
		})
		assert.Contains(t, fieldsOf(t, err), "grant_types")
	})

	t.Run("blank name", func(t *testing.T) {
		before := storedProfile()
		f := newFixture(t, before)
		err := f.svc.PatchProfile(context.Background(), port.PatchProfileCommand{
			TenantID: f.tenantID, ID: before.ID, Section: port.ProfileSectionGeneral, ProfileName: "   ",
		})
		assert.Contains(t, fieldsOf(t, err), "profile_name")
	})

	t.Run("system profile", func(t *testing.T) {
		before := storedProfile()
		before.IsSystem = true
		f := newFixture(t, before)
		err := f.svc.PatchProfile(context.Background(), port.PatchProfileCommand{
			TenantID: f.tenantID, ID: before.ID, Section: port.ProfileSectionGeneral, ProfileName: "x",
		})
		assert.ErrorIs(t, err, port.ErrSystemManaged)
	})
}
