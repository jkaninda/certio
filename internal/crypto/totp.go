package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	// HMAC-SHA1 is what RFC 6238 specifies and what every authenticator app
	// implements. It is not a choice Certio gets to make.
	"crypto/sha1" //nolint:gosec // G505: RFC 6238 fixes HMAC-SHA1 for TOTP
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters. RFC 6238 leaves the period, digit count and hash function
// open, but every mainstream authenticator app assumes SHA-1 / 6 digits / 30
// seconds and several silently ignore the otpauth parameters that say
// otherwise. Interoperability wins here: these are not knobs.
const (
	// TOTPPeriod is the time step, in seconds.
	TOTPPeriod = 30
	// TOTPDigits is the length of a generated code.
	TOTPDigits = 6
	// TOTPSkew is how many time steps either side of "now" are accepted, to
	// absorb clock drift between the server and the authenticator.
	TOTPSkew = 1

	// totpSecretSize is the shared secret length in bytes. RFC 4226 requires at
	// least 128 bits and recommends 160 — the width of the HMAC-SHA1 output.
	totpSecretSize = 20

	// recoveryCodeCount is how many single-use codes are issued at a time.
	recoveryCodeCount = 10
	// recoveryCodeBytes is the entropy per recovery code, before encoding.
	recoveryCodeBytes = 8
)

// ErrInvalidTOTPSecret is returned when a stored secret cannot be decoded.
var ErrInvalidTOTPSecret = errors.New("certio: malformed TOTP secret")

// base32NoPad is the alphabet authenticator apps expect: uppercase RFC 4648
// base32 with the padding stripped.
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a fresh shared secret, base32-encoded for display
// and for the otpauth URI.
func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, totpSecretSize)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("certio: generate TOTP secret: %w", err)
	}
	return base32NoPad.EncodeToString(raw), nil
}

// TOTPCode computes the code for a secret at an instant. It is exported so the
// CLI and the tests can derive a code without reimplementing the algorithm.
func TOTPCode(secret string, at time.Time) (string, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	counter := at.UTC().Unix() / TOTPPeriod
	if counter < 0 {
		// Only reachable with a clock set before 1970, where the counter is
		// meaningless anyway.
		return "", fmt.Errorf("%w: the clock is before the TOTP epoch", ErrInvalidTOTPSecret)
	}
	return hotp(key, uint64(counter)), nil
}

// VerifyTOTP reports whether a code is valid for a secret at an instant,
// accepting TOTPSkew steps either side.
func VerifyTOTP(secret, code string, at time.Time) bool {
	_, ok := VerifyTOTPStep(secret, code, at)
	return ok
}

// VerifyTOTPStep verifies a code and reports which time step it belongs to.
// The caller persists that step and refuses anything at or below it, which is
// what stops an observed code being replayed for the rest of its window.
//
// The comparison is constant-time and every candidate step is checked even
// after a match, so verification takes the same time whichever step matched.
func VerifyTOTPStep(secret, code string, at time.Time) (int64, bool) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return 0, false
	}
	code = NormalizeTOTPCode(code)
	if len(code) != TOTPDigits {
		return 0, false
	}

	counter := at.UTC().Unix() / TOTPPeriod
	matched, matchedStep := false, int64(0)

	for offset := int64(-TOTPSkew); offset <= TOTPSkew; offset++ {
		candidate := counter + offset
		if candidate < 0 {
			continue
		}
		if ConstantTimeEqual([]byte(hotp(key, uint64(candidate))), []byte(code)) {
			matched, matchedStep = true, candidate
		}
	}
	return matchedStep, matched
}

// NormalizeTOTPCode strips the spaces and dashes authenticator apps display
// codes with, so "123 456" is accepted as typed.
func NormalizeTOTPCode(code string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, code)
}

// TOTPProvisioningURI builds the otpauth:// URI an authenticator app scans.
// The issuer appears both as a label prefix and as a parameter — older apps
// read one, newer ones the other.
func TOTPProvisioningURI(issuer, account, secret string) string {
	if issuer == "" {
		issuer = "Certio"
	}
	label := url.PathEscape(issuer + ":" + account)

	query := url.Values{}
	query.Set("secret", secret)
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", fmt.Sprint(TOTPDigits))
	query.Set("period", fmt.Sprint(TOTPPeriod))

	return "otpauth://totp/" + label + "?" + query.Encode()
}

// FormatTOTPSecret groups a secret into four-character blocks, which is how
// authenticator apps present it for manual entry.
func FormatTOTPSecret(secret string) string {
	var b strings.Builder
	for i, r := range secret {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// decodeTOTPSecret accepts a secret as displayed — any case, with or without
// the spacing FormatTOTPSecret adds.
func decodeTOTPSecret(secret string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(secret))
	if cleaned == "" {
		return nil, ErrInvalidTOTPSecret
	}
	key, err := base32NoPad.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidTOTPSecret, err)
	}
	return key, nil
}

// hotp is the RFC 4226 counter-based one-time password that TOTP is built on.
func hotp(key []byte, counter uint64) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(message[:])
	sum := mac.Sum(nil)

	// Dynamic truncation: the low nibble of the last byte picks the offset of
	// the 4-byte window to read, and the top bit is masked off so the result is
	// positive on every platform.
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	return fmt.Sprintf("%0*d", TOTPDigits, value%pow10(TOTPDigits))
}

func pow10(n int) uint32 {
	result := uint32(1)
	for range n {
		result *= 10
	}
	return result
}

// GenerateRecoveryCodes returns a fresh set of single-use codes together with
// the digests to persist. As with API tokens the codes are full-entropy
// random, so SHA-256 is the right hash: there is no low-entropy guess for a
// slow KDF to defend against.
func GenerateRecoveryCodes() (codes, hashes []string, err error) {
	codes = make([]string, 0, recoveryCodeCount)
	hashes = make([]string, 0, recoveryCodeCount)

	for range recoveryCodeCount {
		raw := make([]byte, recoveryCodeBytes)
		if _, err := io.ReadFull(rand.Reader, raw); err != nil {
			return nil, nil, fmt.Errorf("certio: generate recovery code: %w", err)
		}
		// Crockford-style base32 without padding, split in two blocks: short
		// enough to type from a printout, unambiguous enough to read aloud.
		encoded := strings.ToLower(base32NoPad.EncodeToString(raw))
		code := encoded[:6] + "-" + encoded[6:12]

		codes = append(codes, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return codes, hashes, nil
}

// HashRecoveryCode hashes a recovery code for storage and lookup, normalising
// the case and separators a user might type.
func HashRecoveryCode(code string) string {
	normalized := strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte("certio/recovery/v1:" + normalized))
	return hex.EncodeToString(sum[:])
}
