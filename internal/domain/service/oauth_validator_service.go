package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"sprezz-identity/internal/domain/model"
)

var (
	ErrRedirectNotAllowed        = errors.New("redirect URI is not allowed")
	ErrClientRedirectNotAllowed  = errors.New("redirect_uri not allowed")
	ErrInvalidRedirectURI        = errors.New("invalid redirect URI format")
	ErrScopesNotAllowed          = errors.New("requested scopes are not predefined/allowed by the tenant")
	ErrClientScopesNotAllowed    = errors.New("requested scopes are not allowed for this client")
	ErrAudiencesNotAllowed       = errors.New("requested allowed_audiences are not predefined/allowed by the tenant")
	ErrClientAudiencesNotAllowed = errors.New("requested audiences are not allowed for this client")
)

type OAuthValidatorService struct{}

func NewOAuthValidatorService() *OAuthValidatorService {
	return &OAuthValidatorService{}
}

// ValidateRedirect checks if the redirectURL is allowed under the client and matches the tenant's redirect whitelist.
func (s *OAuthValidatorService) ValidateRedirect(ctx context.Context, tenant *model.Tenant, group *model.ApplicationGroup, redirectURL string) error {
	if redirectURL == "" {
		return ErrInvalidRedirectURI
	}

	if strings.Contains(redirectURL, "/../") || strings.Contains(redirectURL, "..") || strings.Contains(redirectURL, "#") {
		return ErrInvalidRedirectURI
	}

	_, err := url.Parse(redirectURL)
	if err != nil {
		return ErrInvalidRedirectURI
	}

	if err := s.validateClientRedirect(group, redirectURL); err != nil {
		return err
	}

	return s.validateTenantRedirect(tenant, redirectURL)
}

// validateClientRedirect isolates white-listed redirection checks against application group configurations.
func (s *OAuthValidatorService) validateClientRedirect(group *model.ApplicationGroup, redirectURL string) error {
	if group == nil {
		return nil
	}
	for _, u := range group.RedirectURIs {
		if u == redirectURL {
			return nil
		}
	}
	return ErrClientRedirectNotAllowed
}

func (s *OAuthValidatorService) validateTenantRedirect(tenant *model.Tenant, redirectURL string) error {
	whitelist := tenant.Config.RedirectWhitelist
	if len(whitelist) == 0 {
		return ErrRedirectNotAllowed
	}

	for _, pattern := range whitelist {
		if s.matchPattern(redirectURL, pattern) {
			return nil
		}
	}

	return ErrRedirectNotAllowed
}

// ValidateScopes checks if requested scopes are allowed by the client application (if provided) and predefined by the tenant.
func (s *OAuthValidatorService) ValidateScopes(ctx context.Context, tenant *model.Tenant, group *model.ApplicationGroup, scopes []string) error {
	// 1. Client level validation (if application group parameters are provided)
	if group != nil {
		// Scope entitlement ceilings are maintained as constraints on the application group
		if !s.isSubset(scopes, group.AllowedScopes) {
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
func (s *OAuthValidatorService) ValidateAudiences(ctx context.Context, tenant *model.Tenant, group *model.ApplicationGroup, audiences []string) error {
	if len(audiences) == 0 {
		return nil
	}

	// 1. Client level validation (if client is provided)
	if group != nil {
		if !s.isSubset(audiences, group.AllowedAudiences) {
			return ErrClientAudiencesNotAllowed
		}
	}

	// 2. Tenant level validation
	if !s.isSubset(audiences, tenant.Config.PredefinedAudiences) {
		return ErrAudiencesNotAllowed
	}

	return nil
}

// ValidateState ensures that if a state parameter is present, it meets a strict minimum length
// requirement (minimum 16 characters), is not completely blank or trivial, and does not
// resemble a URL to prevent Open Redirects.
func (s *OAuthValidatorService) ValidateState(ctx context.Context, state string) error {
	if state == "" {
		return nil
	}
	if len(state) < 16 {
		return errors.New("state parameter must be at least 16 characters long")
	}

	// Check for trivial/repeated character strings
	unique := make(map[rune]struct{})
	for _, r := range state {
		unique[r] = struct{}{}
	}
	if len(unique) < 4 {
		return errors.New("state parameter is too trivial")
	}

	// Prevent State-Based Open Redirects by rejecting values that look like URLs or path traversal
	lower := strings.ToLower(state)
	if strings.Contains(lower, "://") ||
		strings.Contains(lower, "/") ||
		strings.Contains(lower, "\\") ||
		strings.Contains(lower, "%2f") ||
		strings.Contains(lower, "%5c") ||
		strings.Contains(lower, "%3a") {
		return errors.New("state parameter contains invalid characters or resembles a URL")
	}

	return nil
}

func (s *OAuthValidatorService) extractACRValues(values any) []string {
	if values == nil {
		return nil
	}
	var vals []string
	switch v := values.(type) {
	case string:
		vals = append(vals, strings.Split(v, " ")...)
	case []any:
		for _, item := range v {
			if str, ok := item.(string); ok {
				vals = append(vals, str)
			}
		}
	}
	return vals
}

// ParseClientACRClaims parses standard downstream client JSON claims parameters looking for ID Token ACR requirements
func (s *OAuthValidatorService) ParseClientACRClaims(claimsJSON string) (*model.ACRConstraint, error) {
	if claimsJSON == "" {
		return nil, nil
	}

	var claimsPayload struct {
		IDToken struct {
			ACR struct {
				Essential bool `json:"essential"`
				Value     any  `json:"value"`
				Values    any  `json:"values"`
			} `json:"acr"`
		} `json:"id_token"`
	}

	if err := json.Unmarshal([]byte(claimsJSON), &claimsPayload); err != nil {
		return nil, err
	}

	acr := claimsPayload.IDToken.ACR
	var vals []string

	if acr.Values != nil {
		vals = s.extractACRValues(acr.Values)
	} else if acr.Value != nil {
		if str, ok := acr.Value.(string); ok {
			vals = []string{str}
		}
	}

	if len(vals) == 0 {
		return nil, nil
	}

	return &model.ACRConstraint{
		Essential: acr.Essential,
		Values:    vals,
	}, nil
}

// CompileSessionAssuranceToClientACR gathers all predefined tenant-ACR profiles satisfied by the current IdP
func (s *OAuthValidatorService) CompileSessionAssuranceToClientACR(tenant *model.Tenant, provider *model.IdentityProvider, externalACR string, externalAMRs []string) string {
	assurance := s.TranslateIDPReachedLevels(provider, externalACR, externalAMRs)

	var satisfied []string
	for acr, req := range tenant.Config.ACRToLevels {
		reqIAL := req.IAL
		if reqIAL == 0 {
			reqIAL = 1
		}
		reqAAL := req.AAL
		if reqAAL == 0 {
			reqAAL = 1
		}
		if assurance.IAL >= reqIAL && assurance.AAL >= reqAAL {
			satisfied = append(satisfied, acr)
		}
	}
	return strings.Join(satisfied, " ")
}

// ValidateClientACR checks if the selected identity provider satisfies OIDC-compliant ACR request constraints (OR / AND / Essential rules)
func (s *OAuthValidatorService) ValidateClientACR(ctx context.Context, tenant *model.Tenant, provider *model.IdentityProvider, acrValues string, claimsJSON string, externalACR string, externalAMRs []string) (string, error) {
	constraint, err := s.ParseClientACRClaims(claimsJSON)
	if err != nil {
		return "", err
	}

	essential := tenant.Config.ACREssential
	var vals []string

	if constraint != nil {
		essential = constraint.Essential
		vals = constraint.Values
	} else if acrValues != "" {
		vals = strings.Split(acrValues, " ")
	}

	compiledClientACR := s.CompileSessionAssuranceToClientACR(tenant, provider, externalACR, externalAMRs)
	if len(vals) == 0 {
		return compiledClientACR, nil
	}

	satisfied := false
	for _, rawRequested := range vals {
		if s.CheckSessionAssuranceSatisfiesClientConstraints(tenant, provider, rawRequested, externalACR, externalAMRs) {
			satisfied = true
			break
		}
	}

	if !satisfied && essential {
		return "", errors.New("ACR essential condition not satisfied")
	}

	return compiledClientACR, nil
}

func (s *OAuthValidatorService) CheckSessionAssuranceSatisfiesClientConstraints(tenant *model.Tenant, provider *model.IdentityProvider, condition string, externalACR string, externalAMRs []string) bool {
	assurance := s.TranslateIDPReachedLevels(provider, externalACR, externalAMRs)

	parts := strings.Split(condition, "-")
	for _, acr := range parts {
		req, exists := tenant.Config.ACRToLevels[acr]
		if !exists {
			return false
		}
		reqIAL := req.IAL
		if reqIAL == 0 {
			reqIAL = 1
		}
		reqAAL := req.AAL
		if reqAAL == 0 {
			reqAAL = 1
		}
		if assurance.IAL < reqIAL || assurance.AAL < reqAAL {
			return false
		}
	}
	return true
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

// TranslateReachedLevels evaluates raw external ACR/AMR claims against an IdP's configuration maps.
func (s *OAuthValidatorService) TranslateIDPReachedLevels(
	provider *model.IdentityProvider,
	externalACR string,
	externalAMRs []string,
) model.ResolvedAssurance {

	// 1. Establish the baseline default assurance scores from the core provider record.
	// If a baseline is less than 1, clamp it to 1 as the minimum default secure floor.
	resolvedAAL := provider.Config.AAL
	if resolvedAAL < 1 {
		resolvedAAL = 1
	}

	resolvedIAL := provider.Config.IAL
	if resolvedIAL < 1 {
		resolvedIAL = 1
	}

	// 2. STAGE 1: Evaluate multi-dimensional ACR tuple mappings
	// Level 0 means "Unmapped", so we ONLY overwrite if the mapping is an explicit level (1, 2, or 3).
	if externalACR != "" && provider.Config.AcrToTuple != nil {
		if tuple, exists := provider.Config.AcrToTuple[externalACR]; exists {
			if tuple.AAL >= 1 && tuple.AAL <= 3 {
				resolvedAAL = tuple.AAL
			}
			if tuple.IAL >= 1 && tuple.IAL <= 3 {
				resolvedIAL = tuple.IAL
			}
		}
	}

	// 3. STAGE 2: Evaluate dynamic AMR authenticators array scaling checks
	// Level 0 means "Unmapped", so we filter those out. We find the HIGHEST valid level (1-3)
	// reported among all active factors to scale the final AAL score.
	if len(externalAMRs) > 0 && provider.Config.AmrToAAL != nil {
		highestAMRMappedAAL := 0

		for _, amr := range externalAMRs {
			cleanAMR := strings.ToLower(strings.TrimSpace(amr))
			if mappedLevel, exists := provider.Config.AmrToAAL[cleanAMR]; exists {
				if mappedLevel > highestAMRMappedAAL {
					highestAMRMappedAAL = mappedLevel
				}
			}
		}

		// Elevate the active AAL context ONLY if a verified factor score (1-3) outranks the baseline tier
		if highestAMRMappedAAL >= 1 && highestAMRMappedAAL <= 3 && highestAMRMappedAAL > resolvedAAL {
			resolvedAAL = highestAMRMappedAAL
		}
	}

	return model.ResolvedAssurance{
		AAL: resolvedAAL,
		IAL: resolvedIAL,
	}
}
