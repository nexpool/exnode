package conf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// encMagic prefixes an encrypted config blob so the loader can tell an
// AES-encrypted file from a plaintext YAML one. The blob after the prefix is
// base64(salt[16] || nonce[12] || ciphertext+tag).
const encMagic = "EXNODE-ENC1:"

// scrypt KDF parameters. N must be a power of two; these give a ~tens-of-ms
// derivation on commodity hardware — strong enough for an at-rest secret while
// staying cheap at the single startup call.
const (
	scryptN      = 1 << 15 // 32768
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32 // AES-256
	saltLen      = 16
)

// IsEncrypted reports whether data is an exnode AES-encrypted config blob.
func IsEncrypted(data []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(data)), encMagic)
}

// Encrypt seals plaintext YAML under passphrase, returning a textual blob
// (encMagic + base64) safe to store in a file or the EXNODE_CONFIG env var.
func Encrypt(plaintext []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("empty passphrase")
	}
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	blob := make([]byte, 0, saltLen+len(nonce)+len(ciphertext))
	blob = append(blob, salt...)
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)
	return []byte(encMagic + base64.StdEncoding.EncodeToString(blob)), nil
}

// Decrypt opens a blob produced by Encrypt using passphrase.
func Decrypt(data []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("config is encrypted but no passphrase was provided (set EXNODE_KEY or -k)")
	}
	body := strings.TrimSpace(string(data))
	body = strings.TrimPrefix(body, encMagic)
	blob, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted config: %w", err)
	}
	if len(blob) < saltLen+12 { // 12 = GCM standard nonce size
		return nil, errors.New("encrypted config too short")
	}
	salt := blob[:saltLen]
	rest := blob[saltLen:]
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := g.NonceSize()
	if len(rest) < ns {
		return nil, errors.New("encrypted config too short")
	}
	nonce, ciphertext := rest[:ns], rest[ns:]
	plaintext, err := g.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decrypt failed: wrong passphrase or corrupt config")
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
