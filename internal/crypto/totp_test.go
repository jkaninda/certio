package crypto

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// rfcSecret is the shared secret every RFC 4226 and RFC 6238 test vector uses,
// base32-encoded the way an authenticator app would receive it.
var rfcSecret = base32.StdEncoding.WithPadding(base32.NoPadding).
	EncodeToString([]byte("12345678901234567890"))

// TestTOTPCodeRFC6238 checks the SHA-1 vectors from RFC 6238 appendix B. The
// RFC prints eight digits; Certio issues six, which are the low six of the
// same value.
func TestTOTPCodeRFC6238(t *testing.T) {
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}

	for _, tc := range cases {
		got, err := TOTPCode(rfcSecret, time.Unix(tc.unix, 0).UTC())
		if err != nil {
			t.Fatalf("TOTPCode at %d: %v", tc.unix, err)
		}
		if got != tc.want {
			t.Errorf("TOTPCode at %d = %s, want %s", tc.unix, got, tc.want)
		}
	}
}

// TestHOTPRFC4226 checks the counter-based vectors from RFC 4226 appendix D,
// which is what the time step ultimately feeds.
func TestHOTPRFC4226(t *testing.T) {
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	key := []byte("12345678901234567890")

	for counter, expected := range want {
		if got := hotp(key, uint64(counter)); got != expected {
			t.Errorf("hotp(counter=%d) = %s, want %s", counter, got, expected)
		}
	}
}

func TestVerifyTOTPAcceptsDrift(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	now := time.Now()

	code, err := TOTPCode(secret, now)
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}

	// One step of drift either way is tolerated; two is not.
	for _, offset := range []time.Duration{0, TOTPPeriod * time.Second, -TOTPPeriod * time.Second} {
		if !VerifyTOTP(secret, code, now.Add(offset)) {
			t.Errorf("code rejected at drift %s, want accepted", offset)
		}
	}
	for _, offset := range []time.Duration{2 * TOTPPeriod * time.Second, -2 * TOTPPeriod * time.Second} {
		if VerifyTOTP(secret, code, now.Add(offset)) {
			t.Errorf("code accepted at drift %s, want rejected", offset)
		}
	}
}

func TestVerifyTOTPRejectsBadInput(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	now := time.Now()

	cases := map[string]struct{ secret, code string }{
		"wrong code":     {secret, "000000"},
		"short code":     {secret, "12345"},
		"empty code":     {secret, ""},
		"non-numeric":    {secret, "abcdef"},
		"empty secret":   {"", "123456"},
		"invalid base32": {"not-base32!", "123456"},
	}

	for name, tc := range cases {
		if VerifyTOTP(tc.secret, tc.code, now) {
			t.Errorf("%s: VerifyTOTP accepted, want rejected", name)
		}
	}
}

// TestVerifyTOTPNormalisesInput covers codes pasted with the spacing
// authenticator apps display.
func TestVerifyTOTPNormalisesInput(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	now := time.Now()

	code, err := TOTPCode(secret, now)
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	spaced := code[:3] + " " + code[3:]

	if !VerifyTOTP(secret, spaced, now) {
		t.Errorf("VerifyTOTP(%q) rejected a spaced code", spaced)
	}
	// A secret displayed for manual entry must verify as well.
	if !VerifyTOTP(FormatTOTPSecret(strings.ToLower(secret)), code, now) {
		t.Error("VerifyTOTP rejected a formatted, lowercased secret")
	}
}

func TestGenerateTOTPSecretIsUnique(t *testing.T) {
	seen := make(map[string]bool, 32)
	for range 32 {
		secret, err := GenerateTOTPSecret()
		if err != nil {
			t.Fatalf("GenerateTOTPSecret: %v", err)
		}
		if len(secret) != 32 {
			t.Errorf("secret length = %d, want 32 base32 characters for 160 bits", len(secret))
		}
		if seen[secret] {
			t.Fatalf("GenerateTOTPSecret repeated %q", secret)
		}
		seen[secret] = true
	}
}

func TestTOTPProvisioningURI(t *testing.T) {
	uri := TOTPProvisioningURI("Certio", "admin@example.com", "ABCD")

	for _, want := range []string{
		"otpauth://totp/Certio:admin@example.com?",
		"secret=ABCD",
		"issuer=Certio",
		"algorithm=SHA1",
		"digits=6",
		"period=30",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI %q is missing %q", uri, want)
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(codes) != recoveryCodeCount || len(hashes) != recoveryCodeCount {
		t.Fatalf("got %d codes and %d hashes, want %d of each", len(codes), len(hashes), recoveryCodeCount)
	}

	seen := make(map[string]bool, len(codes))
	for i, code := range codes {
		if seen[code] {
			t.Fatalf("recovery code %q was issued twice", code)
		}
		seen[code] = true

		if HashRecoveryCode(code) != hashes[i] {
			t.Errorf("hash mismatch for code %d", i)
		}
		// A user retyping a code will not reproduce the dash or the case.
		if HashRecoveryCode(strings.ToUpper(strings.ReplaceAll(code, "-", " "))) != hashes[i] {
			t.Errorf("HashRecoveryCode did not normalise %q", code)
		}
	}
}
