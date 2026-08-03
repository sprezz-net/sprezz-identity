package service

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"sprezz-identity/internal/domain/model"
)

var (
	ErrRedirectNotAllowed       = errors.New("redirect URI is not allowed")
	ErrClientRedirectNotAllowed = errors.New("redirect_uri not allowed")
	ErrInvalidRedirectURI       = errors.New("invalid redirect URI format")
	ErrScopesNotAllowed         = errors.New("requested scopes are not predefined/allowed by the tenant")
	ErrClientScopesNotAllowed   = errors.New("requested scopes are not allowed for this client")
	ErrAudiencesNotAllowed       = errors.New("requested allowed_audiences are not predefined/allowed by the tenant")
	ErrClientAudiencesNotAllowed = errors.New("requested audiences are not allowed for this client")
)

type OAuthValidatorService struct{}

func NewOAuthValidatorService() *OAuthValidatorService {
	return &OAuthValidatorService{}
}

// ValidateRedirect checks if the redirectURL is allowed under the client and matches the tenant's redirect whitelist.
func (s *OAuthValidatorService) ValidateRedirect(ctx context.Context, tenant *model.Tenant, client *model.ClientApplication, redirectURL string) error {
	if redirectURL == "" {
		return ErrInvalidRedirectURI
	}

	_, err := url.Parse(redirectURL)
	if err != nil {
		return ErrInvalidRedirectURI
	}

	// 1. Client level validation (if client is provided)
	if client != nil {
		allowedByClient := false
		for _, u := range client.RedirectURIs {
			if u == redirectURL {
				allowedByClient = true
				break
			}
		}
		if !allowedByClient {
			return ErrClientRedirectNotAllowed
		}
	}

	// 2. Tenant level validation (whitelist matching)
	whitelist := tenant.Config.RedirectWhitelist
	if len(whitelist) == 0 {
		return ErrRedirectNotAllowed
	}

	matched := false
	for _, pattern := range whitelist {
		if s.matchPattern(redirectURL, pattern) {
			matched = true
			break
		}
	}

	if !matched {
		return ErrRedirectNotAllowed
	}

	return nil
}

// ValidateScopes checks if requested scopes are allowed by the client application (if provided) and predefined by the tenant.
func (s *OAuthValidatorService) ValidateScopes(ctx context.Context, tenant *model.Tenant, client *model.ClientApplication, scopes []string) error {
	// 1. Client level validation (if client is provided)
	if client != nil {
		if !s.isSubset(scopes, client.AllowedScopes) {
			return ErrClientScopesNotAllowed
		}
	}

	// 2. Tenant level validation
	predefined := tenant.Config.PredefinedScopes
	if len(predefined) == 0 {
		predefined = []string{"openid", "profile", "email", "offline_access"}
	}

	if !s.isSubset(scopes, predefined) {
		return ErrScopesNotAllowed
	}

	return nil
}

// ValidateAudiences checks if requested audiences are allowed by the client application (if provided) and predefined by the tenant.
func (s *OAuthValidatorService) ValidateAudiences(ctx context.Context, tenant *model.Tenant, client *model.ClientApplication, audiences []string) error {
	if len(audiences) == 0 {
		return nil
	}

	// 1. Client level validation (if client is provided)
	if client != nil {
		if !s.isSubset(audiences, client.AllowedAudiences) {
			return ErrClientAudiencesNotAllowed
		}
	}

	// 2. Tenant level validation
	if !s.isSubset(audiences, tenant.Config.PredefinedAudiences) {
		return ErrAudiencesNotAllowed
	}

	return nil
}

func (s *OAuthValidatorService) matchPattern(redirectURL, pattern string) bool {
	// 1. Regex match if starts and ends with '/'
	if len(pattern) >= 2 && strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") {
		regexStr := pattern[1 : len(pattern)-1]
		re, err := regexp.Compile(regexStr)
		if err != nil {
			return false
		}
		return re.MatchString(redirectURL)
	}

	// 2. Glob match if it contains '*'
	if strings.Contains(pattern, "*") {
		escaped := regexp.QuoteMeta(pattern)
		regexStr := "^" + strings.ReplaceAll(escaped, `\*`, `.*`) + "$"
		re, err := regexp.Compile(regexStr)
		if err != nil {
			return false
		}
		return re.MatchString(redirectURL)
	}

	// 3. Literal match
	return redirectURL == pattern
}

func (s *OAuthValidatorService) isSubset(subset, set []string) bool {
	setMap := make(map[string]struct{}, len(set))
	for _, item := range set {
		setMap[item] = struct{}{}
	}
	for _, item := range subset {
		if _, ok := setMap[item]; !ok {
			return false
		}
	}
	return true
}
