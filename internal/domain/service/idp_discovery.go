package service

import (
	"context"
	"encoding/json"
	"log/slog"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

// refreshDiscovery fetches the provider's metadata from its discovery endpoint and takes the issuer and the
// stored metadata snapshot from the response. The issuer is therefore never a value the browser supplied. It does
// nothing for local providers or when no federation client is wired (unit tests that do not exercise discovery).
func (s *IdentityProviderService) refreshDiscovery(ctx context.Context, p *model.IdentityProvider) *port.ValidationError {
	if p.IDPType != model.OpenIDConnectIDPType || s.federationClient == nil {
		return nil
	}
	if msg := checkHTTPSURL(p.Config.DiscoveryEndpoint); msg != "" {
		verr := port.NewValidationError()
		verr.Add("discovery_endpoint", msg)
		return verr
	}

	meta, err := s.federationClient.FetchOIDCDiscoveryMetadata(ctx, p.Config.DiscoveryEndpoint)
	if err != nil || meta == nil || meta.Issuer == "" {
		slog.Warn("oidc discovery failed", "endpoint", p.Config.DiscoveryEndpoint, "err", err)
		verr := port.NewValidationError()
		verr.Add("discovery_endpoint", "could not retrieve valid provider metadata from this endpoint")
		return verr
	}

	p.Issuer = meta.Issuer
	if raw, err := json.Marshal(meta); err == nil {
		p.Config.DiscoveryResult = string(raw)
	}
	return nil
}
