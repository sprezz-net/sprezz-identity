package service

import (
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

const (
	minTokenLifetime        = 1 * time.Minute
	maxAccessTokenLifetime  = 24 * time.Hour
	maxIDTokenLifetime      = 24 * time.Hour
	maxRefreshTokenLifetime = 90 * 24 * time.Hour
)

// validateProfileUpdate checks the security policy of a profile. Every problem is collected so the form can show
// them all at once. The same rules protect full updates, section patches and creation.
func validateProfileUpdate(cmd port.UpdateProfileCommand) *port.ValidationError {
	return validateProfileFields(profileFields{
		name:         cmd.ProfileName,
		authMethod:   cmd.TokenEndpointAuthMethod,
		algorithm:    cmd.SigningAlgorithm,
		grantTypes:   cmd.GrantTypes,
		accessTTL:    cmd.AccessTokenLifetime,
		idTTL:        cmd.IDTokenLifetime,
		refreshTTL:   cmd.RefreshTokenLifetime,
		hasGrantList: true,
	})
}

func validateProfileCreate(cmd port.CreateProfileCommand) *port.ValidationError {
	return validateProfileFields(profileFields{
		name:         cmd.ProfileName,
		authMethod:   cmd.TokenEndpointAuthMethod,
		algorithm:    cmd.SigningAlgorithm,
		grantTypes:   cmd.GrantTypes,
		accessTTL:    cmd.AccessTokenLifetime,
		idTTL:        cmd.IDTokenLifetime,
		refreshTTL:   cmd.RefreshTokenLifetime,
		hasGrantList: true,
	})
}

type profileFields struct {
	name         string
	authMethod   model.TokenEndpointAuthMethod
	algorithm    model.SignatureAlgorithm
	grantTypes   []model.GrantType
	accessTTL    time.Duration
	idTTL        time.Duration
	refreshTTL   time.Duration
	hasGrantList bool
}

func validateProfileFields(f profileFields) *port.ValidationError {
	verr := port.NewValidationError()

	if strings.TrimSpace(f.name) == "" {
		verr.Add("profile_name", "a profile name is required")
	} else if len(strings.TrimSpace(f.name)) > 100 {
		verr.Add("profile_name", "the profile name must be at most 100 characters")
	}

	switch f.authMethod {
	case model.AuthMethodClientSecretPost, model.AuthMethodClientSecretBasic, model.AuthMethodNone:
	default:
		verr.Add("token_endpoint_auth_method", "choose one of the supported authentication methods")
	}

	switch f.algorithm {
	case model.AlgRS256, model.AlgES256, model.AlgEdDSA:
	default:
		verr.Add("signing_algorithm", "choose one of the supported signing algorithms")
	}

	checkLifetime(verr, "access_token_lifetime", f.accessTTL, maxAccessTokenLifetime)
	checkLifetime(verr, "id_token_lifetime", f.idTTL, maxIDTokenLifetime)
	checkLifetime(verr, "refresh_token_lifetime", f.refreshTTL, maxRefreshTokenLifetime)

	checkGrantTypes(verr, f)
	return verr
}

func checkLifetime(verr *port.ValidationError, field string, value, max time.Duration) {
	if value < minTokenLifetime {
		verr.Add(field, "the lifetime must be at least one minute")
		return
	}
	if value > max {
		verr.Add(field, "the lifetime exceeds the allowed maximum of "+max.String())
	}
}

// checkGrantTypes enforces the client-type rules: a public client has no secret, so it can neither use the
// client credentials grant nor go without refresh token rotation (enforced separately by the service).
func checkGrantTypes(verr *port.ValidationError, f profileFields) {
	if !f.hasGrantList {
		return
	}
	for _, gt := range f.grantTypes {
		switch gt {
		case model.GrantTypeAuthorizationCode, model.GrantTypeRefreshToken, model.GrantTypeClientCredentials, model.GrantTypeTokenExchange:
		default:
			verr.Add("grant_types", "unknown grant type "+string(gt))
			return
		}
		if f.authMethod == model.AuthMethodNone && gt == model.GrantTypeClientCredentials {
			verr.Add("grant_types", "a public client cannot use the client credentials grant")
			return
		}
	}
}
