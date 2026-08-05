package state

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
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

func deriveKey(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}

func EncryptAESGCM(plaintext string, passphrase string) (string, error) {
	key := deriveKey(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesgcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptAESGCM(ciphertextBase64 string, passphrase string) (string, error) {
	key := deriveKey(passphrase)
	data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aesgcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
