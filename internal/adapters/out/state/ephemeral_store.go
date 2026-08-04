package state

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

type EphemeralStore struct {
	mu     sync.RWMutex
	secret string
}

func NewEphemeralStore() (*EphemeralStore, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return &EphemeralStore{
		secret: hex.EncodeToString(bytes),
	}, nil
}

func NewEphemeralStoreWithSecret(secret string) *EphemeralStore {
	return &EphemeralStore{
		secret: secret,
	}
}

func (s *EphemeralStore) GetEphemeralSecret() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.secret
}
