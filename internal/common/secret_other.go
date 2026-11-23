//go:build !windows

package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const aeadPrefix = "aead:"

func loadOrCreateKey(dataDir string) ([]byte, error) {
	keyPath := filepath.Join(dataDir, ".secret.key")
	if b, err := os.ReadFile(keyPath); err == nil && len(b) == 32 {
		return b, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := WriteFileAtomic(keyPath, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// ProtectSecret encrypts plaintext with AES-256-GCM using a 0600 local key.
func ProtectSecret(dataDir, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	key, err := loadOrCreateKey(dataDir)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return aeadPrefix + base64.StdEncoding.EncodeToString(ct), nil
}

// UnprotectSecret decrypts an AES-256-GCM protected secret.
func UnprotectSecret(dataDir, encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	if !strings.HasPrefix(encoded, aeadPrefix) {
		return "", errors.New("unsupported secret format (expected aead: prefix)")
	}
	key, err := loadOrCreateKey(dataDir)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encoded, aeadPrefix))
	if err != nil {
		return "", fmt.Errorf("decode secret base64: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
