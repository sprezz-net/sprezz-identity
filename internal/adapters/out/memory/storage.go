package memory

import (
	"context"
	"fmt"
	"sync"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

type Storage struct {
	mu       sync.RWMutex
	tenants  map[string]*model.Tenant
	clients  map[string]map[string]model.ClientApplication
	sessions map[string]model.AuthorizationCodeSession
}

func NewStorage() *Storage {
	return &Storage{
		tenants:  make(map[string]*model.Tenant),
		clients:  make(map[string]map[string]model.ClientApplication),
		sessions: make(map[string]model.AuthorizationCodeSession),
	}
}

func (s *Storage) ResolveTenantByID(ctx context.Context, tenantID uuid.UUID) (*model.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, tenant := range s.tenants {
		if tenant.ID == tenantID {
			clone := *tenant
			return &clone, nil
		}
	}
	return nil, port.ErrTenantNotFound
}

func (s *Storage) SaveClient(ctx context.Context, client model.ClientApplication) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.clients[client.TenantID.String()]; !ok {
		s.clients[client.TenantID.String()] = make(map[string]model.ClientApplication)
	}
	s.clients[client.TenantID.String()][client.ClientID] = client
	return nil
}

func (s *Storage) GetClient(ctx context.Context, tenantID uuid.UUID, clientID string) (*model.ClientApplication, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenantClients, ok := s.clients[tenantID.String()]
	if !ok {
		return nil, fmt.Errorf("client %s for tenant %s: %w", clientID, tenantID, port.ErrTenantNotFound)
	}

	client, ok := tenantClients[clientID]
	if !ok {
		return nil, fmt.Errorf("client %s for tenant %s: %w", clientID, tenantID, port.ErrTenantNotFound)
	}
	return &client, nil
}

func (s *Storage) SaveAuthSession(ctx context.Context, session model.AuthorizationCodeSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.Code] = session
	return nil
}

func (s *Storage) GetAndConsumeAuthSession(ctx context.Context, tenantID uuid.UUID, code string) (*model.AuthorizationCodeSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[code]
	if !ok {
		return nil, fmt.Errorf("session %s: %w", code, port.ErrTenantNotFound)
	}
	if session.TenantID != tenantID.String() {
		return nil, fmt.Errorf("session tenant mismatch: %w", port.ErrTenantNotFound)
	}
	delete(s.sessions, code)
	return &session, nil
}

func (s *Storage) ResolveTenantByDomain(ctx context.Context, domain string) (*model.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenant, ok := s.tenants[domain]
	if !ok {
		return nil, port.ErrTenantNotFound
	}
	clone := *tenant
	return &clone, nil
}

func (s *Storage) CreateTenant(ctx context.Context, tenant model.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenants[tenant.Domain] = &tenant
	return nil
}

func (s *Storage) RevokeSession(ctx context.Context, tenantID uuid.UUID, subject string, clientID string) error {
	return nil
}
