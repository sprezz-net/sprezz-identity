package crypto

import (
	"time"

	"sprezz-identity/internal/domain/model"

	"github.com/golang-jwt/jwt/v5"
)

var _ jwt.Claims = (*accessTokenClaimsWrapper)(nil)
var _ jwt.Claims = (*oidcTokenClaimsWrapper)(nil)
var _ jwt.Claims = (*softwareStatementClaimsWrapper)(nil)

type accessTokenClaimsWrapper struct {
	model.TokenClaims
}

type oidcTokenClaimsWrapper struct {
	model.OIDCTokenClaims
}

type softwareStatementClaimsWrapper struct {
	model.SoftwareStatementClaims
}

// accessTokenClaimsWrapper

func (w accessTokenClaimsWrapper) GetExpirationTime() (*jwt.NumericDate, error) {
	if w.ExpiresAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(w.ExpiresAt, 0)), nil
}
func (w accessTokenClaimsWrapper) GetIssuedAt() (*jwt.NumericDate, error) {
	if w.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(w.IssuedAt, 0)), nil
}
func (w accessTokenClaimsWrapper) GetNotBefore() (*jwt.NumericDate, error) {
	if w.NotBefore == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(w.NotBefore, 0)), nil
}
func (w accessTokenClaimsWrapper) GetIssuer() (string, error)  { return w.Issuer, nil }
func (w accessTokenClaimsWrapper) GetSubject() (string, error) { return w.Subject, nil }
func (w accessTokenClaimsWrapper) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings(w.Audiences), nil
}

// oidcTokenClaimsWrapper

func (w oidcTokenClaimsWrapper) GetExpirationTime() (*jwt.NumericDate, error) {
	if w.ExpiresAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(w.ExpiresAt, 0)), nil
}
func (w oidcTokenClaimsWrapper) GetIssuedAt() (*jwt.NumericDate, error) {
	if w.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(w.IssuedAt, 0)), nil
}
func (w oidcTokenClaimsWrapper) GetNotBefore() (*jwt.NumericDate, error) {
	if w.NotBefore == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(w.NotBefore, 0)), nil
}
func (w oidcTokenClaimsWrapper) GetIssuer() (string, error)  { return w.Issuer, nil }
func (w oidcTokenClaimsWrapper) GetSubject() (string, error) { return w.Subject, nil }
func (w oidcTokenClaimsWrapper) GetAudience() (jwt.ClaimStrings, error) {
	if w.Audience == "" {
		return nil, nil
	}
	return jwt.ClaimStrings{w.Audience}, nil
}

// softwareStatementClaimsWrapper

func (w softwareStatementClaimsWrapper) GetExpirationTime() (*jwt.NumericDate, error) {
	if w.ExpiresAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(w.ExpiresAt, 0)), nil
}
func (w softwareStatementClaimsWrapper) GetIssuedAt() (*jwt.NumericDate, error) {
	if w.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(w.IssuedAt, 0)), nil
}
func (w softwareStatementClaimsWrapper) GetNotBefore() (*jwt.NumericDate, error) {
	if w.NotBefore == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(w.NotBefore, 0)), nil
}
func (w softwareStatementClaimsWrapper) GetIssuer() (string, error)  { return w.Issuer, nil }
func (w softwareStatementClaimsWrapper) GetSubject() (string, error) { return w.Subject, nil }
func (w softwareStatementClaimsWrapper) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings(w.Audience), nil
}
