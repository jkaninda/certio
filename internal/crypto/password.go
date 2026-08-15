package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrInvalidHash is returned when a stored password hash cannot be parsed.
var ErrInvalidHash = errors.New("certio: malformed password hash")

// ErrMismatchedPassword is returned when a password does not match its hash.
var ErrMismatchedPassword = errors.New("certio: password does not match")

// passwordParams are the Argon2id parameters used for new password hashes.
// They are encoded into the hash string so they can be raised later without
// invalidating existing credentials.
var passwordParams = struct {
	time, memory uint32
	threads      uint8
	keyLen       uint32
	saltLen      int
}{time: 3, memory: 64 * 1024, threads: 4, keyLen: 32, saltLen: 16}

// maxDigestLen bounds the key length read out of a stored hash. Well above the
// 32 bytes this package writes, and far below anything worth allocating for.
const maxDigestLen = 1024

// HashPassword returns a PHC-formatted Argon2id hash:
// $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("certio: password is empty")
	}
	salt := make([]byte, passwordParams.saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("certio: generate salt: %w", err)
	}
	digest := argon2.IDKey([]byte(password), salt,
		passwordParams.time, passwordParams.memory, passwordParams.threads, passwordParams.keyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, passwordParams.memory, passwordParams.time, passwordParams.threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}

// VerifyPassword checks a password against a PHC-formatted Argon2id hash.
func VerifyPassword(password, encoded string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return ErrInvalidHash
	}
	if version != argon2.Version {
		return fmt.Errorf("%w: unsupported argon2 version %d", ErrInvalidHash, version)
	}

	var memory, timeCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return ErrInvalidHash
	}
	want, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return ErrInvalidHash
	}
	// A stored digest is a fixed width; anything else is a corrupt or crafted
	// record rather than something to hand to argon2 as a key length.
	if len(want) == 0 || len(want) > maxDigestLen {
		return ErrInvalidHash
	}

	//nolint:gosec // G115: len(want) is bounded by maxDigestLen just above
	got := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(want)))
	if !ConstantTimeEqual(got, want) {
		return ErrMismatchedPassword
	}
	return nil
}

// GenerateAPIToken returns a new opaque API token and its storage hash. The
// plaintext is shown to the user exactly once; only the hash is persisted.
func GenerateAPIToken() (token, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", "", fmt.Errorf("certio: generate token: %w", err)
	}
	token = "certio_" + base64.RawURLEncoding.EncodeToString(raw)
	return token, HashAPIToken(token), nil
}

// HashAPIToken hashes an API token for storage and lookup. SHA-256 is
// appropriate here — unlike a password, the token is full-entropy random, so
// there is nothing for a slow KDF to protect against.
func HashAPIToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// RandomString returns a URL-safe random string with n bytes of entropy.
func RandomString(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
