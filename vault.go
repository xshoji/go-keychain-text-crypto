package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"gopkg.in/yaml.v3"
)

type vaultEnvelope struct {
	Version   int             `yaml:"version"`
	Type      string          `yaml:"type"`
	KeyID     string          `yaml:"key_id"`
	CreatedAt string          `yaml:"created_at"`
	UpdatedAt string          `yaml:"updated_at"`
	Cipher    envelopeCipher  `yaml:"cipher"`
	Payload   envelopePayload `yaml:"payload"`
}

type envelopeCipher struct {
	Algorithm string `yaml:"algorithm"`
	Nonce     string `yaml:"nonce"`
}

type envelopePayload struct {
	Encoding   string `yaml:"encoding"`
	Ciphertext string `yaml:"ciphertext"`
}

type recoveryFile struct {
	Version   int          `yaml:"version"`
	Type      string       `yaml:"type"`
	KeyID     string       `yaml:"key_id"`
	CreatedAt string       `yaml:"created_at"`
	KDF       recoveryKDF  `yaml:"kdf"`
	Wrap      recoveryWrap `yaml:"wrap"`
}

type recoveryKDF struct {
	Algorithm string `yaml:"algorithm"`
	Time      uint32 `yaml:"time"`
	MemoryKiB uint32 `yaml:"memory_kib"`
	Threads   uint8  `yaml:"threads"`
	Salt      string `yaml:"salt"`
}

type recoveryWrap struct {
	Algorithm  string `yaml:"algorithm"`
	Nonce      string `yaml:"nonce"`
	Ciphertext string `yaml:"ciphertext"`
}

func readVaultEnvelope(path string) (*vaultEnvelope, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env vaultEnvelope
	if err := yaml.Unmarshal(content, &env); err != nil {
		return nil, fmt.Errorf("parse vault envelope: %w", err)
	}
	if env.Version != 1 {
		return nil, fmt.Errorf("unsupported vault version %d", env.Version)
	}
	if env.Type != "secrets-file" {
		return nil, fmt.Errorf("unexpected vault type %q", env.Type)
	}
	if strings.TrimSpace(env.KeyID) == "" {
		return nil, fmt.Errorf("vault key_id is missing")
	}
	return &env, nil
}

func loadVaultPlaintext(path string, key []byte) ([]byte, *vaultEnvelope, error) {
	env, err := readVaultEnvelope(path)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := decryptVaultPlaintext(env, key)
	if err != nil {
		return nil, nil, err
	}
	return plaintext, env, nil
}

func encryptVaultPlaintext(plaintext []byte, env *vaultEnvelope, key []byte, now time.Time) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("unexpected key length %d", len(key))
	}
	nonce, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, vaultAAD(env))

	env.Version = 1
	env.Type = "secrets-file"
	env.UpdatedAt = now.Format(time.RFC3339)
	env.Cipher = envelopeCipher{
		Algorithm: "xchacha20poly1305",
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
	}
	env.Payload = envelopePayload{
		Encoding:   "base64",
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	encoded, err := yaml.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal vault envelope: %w", err)
	}
	return encoded, nil
}

func decryptVaultPlaintext(env *vaultEnvelope, key []byte) ([]byte, error) {
	if env.Cipher.Algorithm != "xchacha20poly1305" {
		return nil, fmt.Errorf("unsupported cipher %q", env.Cipher.Algorithm)
	}
	if env.Payload.Encoding != "base64" {
		return nil, fmt.Errorf("unsupported payload encoding %q", env.Payload.Encoding)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Cipher.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Payload.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, vaultAAD(env))
	if err != nil {
		return nil, fmt.Errorf("decrypt vault: %w", err)
	}
	return plaintext, nil
}

func newRecoveryFile(keyID string, key []byte, passphrase []byte, now time.Time) (*recoveryFile, error) {
	salt, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	params := recoveryKDF{
		Algorithm: "argon2id",
		Time:      3,
		MemoryKiB: 64 * 1024,
		Threads:   4,
		Salt:      base64.StdEncoding.EncodeToString(salt),
	}
	wrapKey := deriveRecoveryWrapKey(passphrase, salt, params)
	defer zeroBytes(wrapKey)

	nonce, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, err
	}
	associatedData := []byte("go-keychain-text-crypto|recovery-key|" + keyID)
	ciphertext := aead.Seal(nil, nonce, key, associatedData)

	return &recoveryFile{
		Version:   1,
		Type:      "recovery-key",
		KeyID:     keyID,
		CreatedAt: now.Format(time.RFC3339),
		KDF:       params,
		Wrap: recoveryWrap{
			Algorithm:  "xchacha20poly1305",
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		},
	}, nil
}

func unwrapRecoveryKey(file *recoveryFile, passphrase []byte) ([]byte, error) {
	if file.Version != 1 {
		return nil, fmt.Errorf("unsupported recovery file version %d", file.Version)
	}
	if file.Type != "recovery-key" {
		return nil, fmt.Errorf("unexpected recovery file type %q", file.Type)
	}
	if file.KDF.Algorithm != "argon2id" {
		return nil, fmt.Errorf("unsupported recovery KDF %q", file.KDF.Algorithm)
	}
	if file.Wrap.Algorithm != "xchacha20poly1305" {
		return nil, fmt.Errorf("unsupported recovery cipher %q", file.Wrap.Algorithm)
	}
	salt, err := base64.StdEncoding.DecodeString(file.KDF.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode recovery salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(file.Wrap.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode recovery nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(file.Wrap.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode recovery ciphertext: %w", err)
	}
	wrapKey := deriveRecoveryWrapKey(passphrase, salt, file.KDF)
	defer zeroBytes(wrapKey)
	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, err
	}
	associatedData := []byte("go-keychain-text-crypto|recovery-key|" + file.KeyID)
	key, err := aead.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("unwrap recovery key: %w", err)
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("unexpected recovered key length %d", len(key))
	}
	return key, nil
}

func deriveRecoveryWrapKey(passphrase []byte, salt []byte, params recoveryKDF) []byte {
	return argon2.IDKey(passphrase, salt, params.Time, params.MemoryKiB, params.Threads, uint32(chacha20poly1305.KeySize))
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".go-keychain-text-crypto-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func randomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func randomID() (string, error) {
	b, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func vaultAAD(env *vaultEnvelope) []byte {
	return []byte(fmt.Sprintf("go-keychain-text-crypto|vault|%d|%s|%s", env.Version, env.Type, env.KeyID))
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func hashPath(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:16])
}
