package service

import (
	"context"
	"testing"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/domain/port/portmock"

	"github.com/gojuno/minimock/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// inactiveEnv holds services built on a strict storage mock that knows exactly one thing: the tenant is inactive.
// Any other storage call fails the test, which proves the request was refused before it changed or read anything.
type inactiveEnv struct {
	tenantID uuid.UUID
	oauth    *OAuthService
	fed      *FederationService
	local    *LocalAuthService
	reg      *UserRegistrationService
	profiles *UserProfileService
	idp      *IdentityProviderService
	sso      *SSOSessionService
	assure   *AssuranceService
	adminLog *AdminLogonService
}

const inactivePartition = int64(1)

func newInactiveEnv(t *testing.T) *inactiveEnv {
	t.Helper()
	mc := minimock.NewController(t)
	storage := portmock.NewStorageMock(mc)
	admin := portmock.NewAdminStorageMock(mc)
	crypto := portmock.NewCryptoMock(mc)
	clock := portmock.NewMockClock(time.Now())

	e := &inactiveEnv{tenantID: uuid.New()}
	storage.ResolveTenantByUUIDMock.Optional().Set(func(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
		return &model.Tenant{ID: id, Domain: "off.example.com", IsActive: false}, nil
	})
	storage.ResolveTenantByDomainMock.Optional().Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return &model.Tenant{ID: e.tenantID, Domain: domain, IsActive: false}, nil
	})

	e.idp = NewIdentityProviderService(storage, admin, crypto, clock, nil)
	e.oauth = NewOAuthService(storage, nil, nil, nil, clock, nil, nil)
	e.oauth.crypto = crypto
	e.fed = NewFederationService(storage, nil, crypto, clock, e.idp, nil)
	e.local = NewLocalAuthService(storage, crypto, clock)
	e.profiles = NewUserProfileService(storage, admin, crypto, clock)
	e.reg = NewUserRegistrationService(storage, e.profiles, clock)
	e.sso = NewSSOSessionService(storage, "unittest")
	e.assure = NewAssuranceService(storage)
	e.adminLog = NewAdminLogonService(storage, admin, nil, crypto, nil, nil, clock, "unittest", "off.example.com")
	return e
}

// inactiveCase is one entry point and the call that exercises it.
type inactiveCase struct {
	name string
	call func(ctx context.Context, e *inactiveEnv) error
}

// Every entry point that signs somebody in, issues a token or a session, or serves protocol data must refuse an
// inactive tenant itself. The storage mock is strict, so a call that got past the gate would fail the test with an
// unexpected storage call instead of passing silently.
func TestInactiveTenant_EveryEntryPointRefuses(t *testing.T) {
	cases := append(inactiveOAuthCases(), inactiveSignInCases()...)
	cases = append(cases, inactiveAccountCases()...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newInactiveEnv(t)
			assert.ErrorIs(t, tc.call(context.Background(), e), port.ErrTenantInactive)
		})
	}
}
