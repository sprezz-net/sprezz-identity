package service

import (
	"context"
	"errors"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

type AssuranceService struct {
	storage port.Storage
}

func NewAssuranceService(s port.Storage) *AssuranceService {
	return &AssuranceService{storage: s}
}

// AssertActionTrust evaluates structural dynamic session security tiers cleanly away from handlers [4.3]
func (s *AssuranceService) AssertActionTrust(ctx context.Context, cmd port.SecurityAccessAssertion) error {
	tenant, err := s.storage.ResolveTenantByUUID(ctx, cmd.TenantID)
	if err != nil {
		return port.ErrTenantNotFound
	}

	// Resolve the active identity provider from storage to read its authenticated verification trust scores
	providers, err := s.storage.GetIdentityProviders(ctx, cmd.TenantID)
	if err != nil {
		return err
	}

	var activeProvider *model.IdentityProvider
	for _, p := range providers {
		if p.ID == cmd.ProviderID {
			activeProvider = &p
			break
		}
	}
	if activeProvider == nil || !activeProvider.Enabled {
		return port.ErrIdentityProviderNotFound
	}

	// Apply safe default numeric constraints to guard levels mappings
	aal := activeProvider.Config.AAL
	if aal <= 0 {
		aal = 1
	}
	ial := activeProvider.Config.IAL
	if ial <= 0 {
		ial = 1
	}

	var requiredAAL int
	requiredIAL := tenant.Config.GetDefaultIAL() // Master assurance capability floor boundary [4.3]

	switch cmd.TargetAction {
	case "profile_view":
		requiredAAL = tenant.Config.GetProfileAAL()
	case "change_name":
		requiredAAL = tenant.Config.GetNameAAL()
	case "change_email":
		requiredAAL = tenant.Config.GetEmailAAL()
	case "change_password":
		requiredAAL = tenant.Config.GetPasswordAAL()
	default:
		return errors.New("assurance_service: unrecognized action profile handle")
	}

	// Cross-reference trust boundaries against tenant configuration baselines
	if aal < requiredAAL || ial < requiredIAL {
		return errors.New("assurance_service: security status criteria denied; authorization level insufficient")
	}

	return nil
}
