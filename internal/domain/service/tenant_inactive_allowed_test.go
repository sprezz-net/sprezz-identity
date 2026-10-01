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
	"github.com/stretchr/testify/require"
)

func TestResolveTenantContext_RefusesInactiveTenants(t *testing.T) {
	mc := minimock.NewController(t)
	storage := portmock.NewStorageMock(mc)
	svc := NewTenantService(storage, portmock.NewAdminStorageMock(mc), portmock.NewMockClock(time.Now()), nil, "unittest", "admin.example.com")

	storage.ResolveTenantByDomainMock.Set(func(ctx context.Context, domain string) (*model.Tenant, error) {
		return &model.Tenant{ID: uuid.New(), Domain: domain, IsActive: domain == "on.example.com"}, nil
	})

	tenant, err := svc.ResolveTenantContext(context.Background(), "on.example.com")
	require.NoError(t, err)
	assert.Equal(t, "on.example.com", tenant.Domain)

	_, err = svc.ResolveTenantContext(context.Background(), "off.example.com")
	assert.ErrorIs(t, err, port.ErrTenantInactive, "the HTTP middleware gets the refusal from the domain, not from its own check")
}

// Signing out only reduces access, so it must keep working when a tenant is switched off: people whose sessions
// were just ended still have cookies to clear.
func TestSSOSession_ClearingACookieWorksForAnInactiveTenant(t *testing.T) {
	mc := minimock.NewController(t)
	storage := portmock.NewStorageMock(mc) // strict: no tenant or partition lookup is allowed
	svc := NewSSOSessionService(storage, "unittest")
	storage.GetPartitionByIDMock.Optional().Return(&model.Partition{ID: 1, AliasName: "default"}, nil)

	resp, err := svc.BuildSessionCookie(context.Background(), port.CookieIntentCommand{
		TenantID: uuid.New(), PartitionID: 1, LifecycleStage: "clear", RequestHost: "off.example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, -1, resp.MaxAge)
}

func TestIntrospection_ReportsATokenOfAnInactiveTenantAsInactive(t *testing.T) {
	mc := minimock.NewController(t)
	storage := portmock.NewStorageMock(mc)
	crypto := portmock.NewCryptoMock(mc)
	tenantID := uuid.New()
	svc := NewOAuthService(storage, nil, nil, nil, portmock.NewMockClock(time.Now()), nil, nil)
	svc.crypto = crypto

	crypto.VerifyTokenMock.Return(map[string]any{"tid": tenantID.String(), "jti": "j", "sub": "u", "scope": "openid"}, nil)
	storage.ResolveTenantByUUIDMock.Return(&model.Tenant{ID: tenantID, IsActive: false}, nil)
	// IsTokenRevoked is intentionally not stubbed: the answer is given before the revocation list is consulted.

	resp, err := svc.IntrospectToken(context.Background(), tenantID, "", "jwt")
	require.NoError(t, err, "RFC 7662: an unusable token is an answer, not an error")
	assert.False(t, resp.Active)
	assert.Empty(t, resp.Subject, "nothing about the token is revealed")
}

func TestUserInfo_IsRefusedForATokenOfAnInactiveTenant(t *testing.T) {
	mc := minimock.NewController(t)
	storage := portmock.NewStorageMock(mc)
	crypto := portmock.NewCryptoMock(mc)
	tenantID := uuid.New()
	svc := NewOAuthService(storage, nil, nil, nil, portmock.NewMockClock(time.Now()), nil, nil)
	svc.crypto = crypto

	crypto.VerifyTokenMock.Return(map[string]any{"tid": tenantID.String(), "jti": "j", "sub": "u"}, nil)
	storage.ResolveTenantByUUIDMock.Return(&model.Tenant{ID: tenantID, IsActive: false}, nil)

	_, err := svc.ProcessUserInfoRequest(context.Background(), port.UserInfoRequestCommand{TenantID: tenantID, AuthorizationHeader: "Bearer jwt"})
	assert.ErrorIs(t, err, port.ErrInvalidGrant)
}

func TestTenantGate_FailsClosed(t *testing.T) {
	assert.ErrorIs(t, requireActiveTenant(nil), port.ErrTenantInactive, "a missing tenant is refused")
	assert.ErrorIs(t, requireActiveTenant(&model.Tenant{}), port.ErrTenantInactive, "the zero value is not active")
	assert.NoError(t, requireActiveTenant(&model.Tenant{IsActive: true}))

	supplied := &model.Tenant{ID: uuid.New(), IsActive: false}
	_, err := activeTenantFor(context.Background(), nil, supplied, supplied.ID)
	assert.ErrorIs(t, err, port.ErrTenantInactive, "a tenant carried in a command is checked too, not trusted")
}
