// Package crypto implements envelope encryption for the private key material
// Certio stores in SQLite. Plaintext keys never touch the database.
//
// Every sealed value is AES-256-GCM with a per-value random nonce and a
// per-value random salt. The content key is derived with HKDF-SHA256 from the
// master key; when a passphrase is supplied it is stretched with Argon2id and
// folded into the same derivation, so a passphrase-protected CA cannot be
// unsealed with the master key alone.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	// MasterKeySize is the required length of the raw master key.
	MasterKeySize = 32
	nonceSize     = 12
	saltSize      = 16

	// Argon2id parameters for passphrase stretching. Tuned for an interactive
	// signing operation on modest hardware (~64 MiB, ~100ms).
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32

	hkdfInfo = "certio/envelope/v1"
)

// ErrPassphraseRequired is returned when a sealed value needs a passphrase that
// was not supplied — or when the supplied one is wrong. The two cases are
// deliberately indistinguishable to a caller.
var ErrPassphraseRequired = errors.New("certio: incorrect or missing passphrase")

// Envelope is a sealed value as persisted: ciphertext plus the public
// parameters needed to re-derive the content key.
type Envelope struct {
	Ciphertext []byte
	Nonce      []byte
	Salt       []byte
}

// IsZero reports whether the envelope holds no sealed data.
func (e Envelope) IsZero() bool { return len(e.Ciphertext) == 0 }

// Keyring seals and opens envelopes with a single master key.
type Keyring struct {
	master []byte
}

// NewKeyring validates the master key and returns a Keyring.
func NewKeyring(master []byte) (*Keyring, error) {
	if len(master) != MasterKeySize {
		return nil, fmt.Errorf("certio: master key must be %d bytes, got %d", MasterKeySize, len(master))
	}
	k := make([]byte, MasterKeySize)
	copy(k, master)
	return &Keyring{master: k}, nil
}

// Seal encrypts plaintext. A non-empty passphrase binds the result to that
// passphrase in addition to the master key.
func (k *Keyring) Seal(plaintext []byte, passphrase string) (Envelope, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return Envelope{}, fmt.Errorf("certio: generate salt: %w", err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Envelope{}, fmt.Errorf("certio: generate nonce: %w", err)
	}

	aead, err := k.aead(salt, passphrase)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Ciphertext: aead.Seal(nil, nonce, plaintext, nil),
		Nonce:      nonce,
		Salt:       salt,
	}, nil
}

// Open decrypts an envelope. A wrong or missing passphrase surfaces as
// ErrPassphraseRequired rather than a raw AEAD failure.
func (k *Keyring) Open(env Envelope, passphrase string) ([]byte, error) {
	if env.IsZero() {
		return nil, errors.New("certio: envelope is empty")
	}
	if len(env.Nonce) != nonceSize {
		return nil, fmt.Errorf("certio: envelope nonce must be %d bytes", nonceSize)
	}
	aead, err := k.aead(env.Salt, passphrase)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, env.Nonce, env.Ciphertext, nil)
	if err != nil {
		return nil, ErrPassphraseRequired
	}
	return plaintext, nil
}

// SealString is a convenience wrapper for textual secrets such as SMTP
// passwords and webhook tokens.
func (k *Keyring) SealString(s, passphrase string) (Envelope, error) {
	return k.Seal([]byte(s), passphrase)
}

// OpenString is the inverse of SealString.
func (k *Keyring) OpenString(env Envelope, passphrase string) (string, error) {
	b, err := k.Open(env, passphrase)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// aead derives the content key and returns a ready GCM cipher.
func (k *Keyring) aead(salt []byte, passphrase string) (cipher.AEAD, error) {
	ikm := k.master
	if passphrase != "" {
		// Stretch the passphrase, then concatenate so both factors are
		// required. Argon2id needs a salt of its own; the envelope salt serves
		// both it and HKDF, which is safe because they use different labels.
		stretched := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
		ikm = append(append([]byte{}, k.master...), stretched...)
	}

	key, err := hkdf.Key(sha256.New, ikm, salt, hkdfInfo, MasterKeySize)
	if err != nil {
		return nil, fmt.Errorf("certio: derive content key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("certio: new cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// GenerateMasterKey returns a fresh random master key.
func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, MasterKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// ParseMasterKey accepts a master key as 64 hex characters, standard base64, or
// exactly 32 raw bytes.
func ParseMasterKey(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("certio: master key is empty")
	}
	if len(s) == hex.EncodedLen(MasterKeySize) {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == MasterKeySize {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == MasterKeySize {
		return b, nil
	}
	if len(s) == MasterKeySize {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("certio: master key must be %d bytes as hex, base64 or raw text", MasterKeySize)
}

// FormatMasterKey renders a master key for display, using the hex form that
// ParseMasterKey reads back.
func FormatMasterKey(key []byte) string { return hex.EncodeToString(key) }

// ConstantTimeEqual compares two byte slices without leaking timing.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
