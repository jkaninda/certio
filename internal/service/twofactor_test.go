package service

import (
	"errors"
	"strings"
	"testing"
	"time"

	certiocrypto "github.com/jkaninda/certio/internal/crypto"
	"github.com/jkaninda/certio/internal/store"
)

const twoFactorPassword = "a-long-enough-password"

// enrolTwoFactor runs a user through the whole enrolment and returns the raw
// secret and the recovery codes, which is what most of these tests need before
// they can assert anything interesting.
func enrolTwoFactor(t *testing.T, s *Service, userID string) (secret string, recovery []string) {
	t.Helper()

	enrollment, err := s.BeginTOTPEnrollment(userID)
	if err != nil {
		t.Fatalf("BeginTOTPEnrollment: %v", err)
	}
	secret = strings.ReplaceAll(enrollment.Secret, " ", "")

	code, err := certiocrypto.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	recovery, err = s.ConfirmTOTPEnrollment(testActor(), userID, code)
	if err != nil {
		t.Fatalf("ConfirmTOTPEnrollment: %v", err)
	}
	return secret, recovery
}

func newTwoFactorUser(t *testing.T, s *Service) *store.User {
	t.Helper()
	user, err := s.CreateUser(testActor(), CreateUserInput{
		Email: "totp@jkaninda.dev", Password: twoFactorPassword, Role: store.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return user
}

func TestTwoFactorEnrollment(t *testing.T) {
	s := newTestService(t)
	user := newTwoFactorUser(t, s)

	status, err := s.TwoFactorStatusOf(user.ID)
	if err != nil {
		t.Fatalf("TwoFactorStatusOf: %v", err)
	}
	if status.Enabled || status.Pending {
		t.Fatalf("a fresh account reports %+v, want neither enabled nor pending", status)
	}

	enrollment, err := s.BeginTOTPEnrollment(user.ID)
	if err != nil {
		t.Fatalf("BeginTOTPEnrollment: %v", err)
	}
	if !strings.HasPrefix(enrollment.QRCode, "data:image/png;base64,") {
		t.Errorf("QR code = %.32q…, want a PNG data URI", enrollment.QRCode)
	}
	if !strings.Contains(enrollment.URI, "otpauth://totp/") {
		t.Errorf("URI = %q, want an otpauth URL", enrollment.URI)
	}

	// A pending enrolment must not be enforced: half a setup cannot lock an
	// account out.
	status, err = s.TwoFactorStatusOf(user.ID)
	if err != nil {
		t.Fatalf("TwoFactorStatusOf: %v", err)
	}
	if status.Enabled || !status.Pending {
		t.Fatalf("after setup: %+v, want pending and not enabled", status)
	}

	// A wrong code must not confirm it.
	if _, err := s.ConfirmTOTPEnrollment(testActor(), user.ID, "000000"); !errors.Is(err, ErrInvalidTwoFactorCode) {
		t.Errorf("ConfirmTOTPEnrollment with a bad code = %v, want ErrInvalidTwoFactorCode", err)
	}

	secret := strings.ReplaceAll(enrollment.Secret, " ", "")
	code, err := certiocrypto.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	codes, err := s.ConfirmTOTPEnrollment(testActor(), user.ID, code)
	if err != nil {
		t.Fatalf("ConfirmTOTPEnrollment: %v", err)
	}
	if len(codes) == 0 {
		t.Fatal("confirming enrolment returned no recovery codes")
	}

	status, err = s.TwoFactorStatusOf(user.ID)
	if err != nil {
		t.Fatalf("TwoFactorStatusOf: %v", err)
	}
	if !status.Enabled || status.Pending || status.RecoveryCodesRemaining != len(codes) {
		t.Fatalf("after confirmation: %+v, want enabled with %d recovery codes", status, len(codes))
	}
}

func TestLoginRequiresSecondFactor(t *testing.T) {
	s := newTestService(t)
	auth := NewAuthenticator([]byte("test-signing-secret-value"), "certio", time.Minute, time.Hour)
	user := newTwoFactorUser(t, s)
	secret, _ := enrolTwoFactor(t, s, user.ID)

	// The password alone yields a challenge, never a session.
	result, err := s.Login(testActor(), auth, LoginInput{Email: user.Email, Password: twoFactorPassword})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !result.TwoFactorRequired {
		t.Fatal("Login issued a session without the second factor")
	}
	if result.Tokens != nil {
		t.Fatal("Login returned tokens alongside a challenge")
	}
	if result.Challenge == "" {
		t.Fatal("Login returned an empty challenge")
	}

	// A challenge token must not be usable as an access token.
	claims, err := auth.Parse(result.Challenge)
	if err != nil {
		t.Fatalf("Parse(challenge): %v", err)
	}
	if _, err := PrincipalFromClaims(claims); err == nil {
		t.Error("a two-factor challenge authorised a request")
	}

	// A wrong code must not complete it.
	if _, err := s.CompleteTwoFactorLogin(testActor(), auth, result.Challenge, "000000"); !errors.Is(err, ErrInvalidTwoFactorCode) {
		t.Errorf("CompleteTwoFactorLogin with a bad code = %v, want ErrInvalidTwoFactorCode", err)
	}

	// A step later than the one enrolment already spent — the replay guard
	// refuses to reuse a step, which TestLoginRejectsReplayedCode covers.
	code, err := certiocrypto.TOTPCode(secret, time.Now().Add(certiocrypto.TOTPPeriod*time.Second))
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	completed, err := s.CompleteTwoFactorLogin(testActor(), auth, result.Challenge, code)
	if err != nil {
		t.Fatalf("CompleteTwoFactorLogin: %v", err)
	}
	if completed.Tokens == nil || completed.Tokens.AccessToken == "" {
		t.Fatal("completing the challenge returned no session")
	}
	if completed.UsedRecoveryCode {
		t.Error("a TOTP code was reported as a recovery code")
	}
}

// TestLoginRejectsReplayedCode covers the window a code stays valid for: an
// observed code must not open a second session.
func TestLoginRejectsReplayedCode(t *testing.T) {
	s := newTestService(t)
	auth := NewAuthenticator([]byte("test-signing-secret-value"), "certio", time.Minute, time.Hour)
	user := newTwoFactorUser(t, s)
	secret, _ := enrolTwoFactor(t, s, user.ID)

	code, err := certiocrypto.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}

	// The enrolment above already spent this step, so the very same code must
	// not be accepted again.
	if _, err := s.Login(testActor(), auth, LoginInput{
		Email: user.Email, Password: twoFactorPassword, TOTPCode: code,
	}); !errors.Is(err, ErrInvalidTwoFactorCode) {
		t.Fatalf("replayed code = %v, want ErrInvalidTwoFactorCode", err)
	}

	// A code from the next step is fine.
	next, err := certiocrypto.TOTPCode(secret, time.Now().Add(certiocrypto.TOTPPeriod*time.Second))
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	if _, err := s.Login(testActor(), auth, LoginInput{
		Email: user.Email, Password: twoFactorPassword, TOTPCode: next,
	}); err != nil {
		t.Fatalf("Login with a fresh code: %v", err)
	}
}

func TestRecoveryCodeIsSingleUse(t *testing.T) {
	s := newTestService(t)
	auth := NewAuthenticator([]byte("test-signing-secret-value"), "certio", time.Minute, time.Hour)
	user := newTwoFactorUser(t, s)
	_, recovery := enrolTwoFactor(t, s, user.ID)

	result, err := s.Login(testActor(), auth, LoginInput{
		Email: user.Email, Password: twoFactorPassword, TOTPCode: recovery[0],
	})
	if err != nil {
		t.Fatalf("Login with a recovery code: %v", err)
	}
	if !result.UsedRecoveryCode {
		t.Error("a recovery code login was not reported as one")
	}
	if result.RecoveryCodesRemaining != len(recovery)-1 {
		t.Errorf("remaining = %d, want %d", result.RecoveryCodesRemaining, len(recovery)-1)
	}

	// Spending it twice must fail.
	if _, err := s.Login(testActor(), auth, LoginInput{
		Email: user.Email, Password: twoFactorPassword, TOTPCode: recovery[0],
	}); !errors.Is(err, ErrInvalidTwoFactorCode) {
		t.Errorf("reused recovery code = %v, want ErrInvalidTwoFactorCode", err)
	}

	// Regenerating voids every previously issued code.
	fresh, err := s.RegenerateRecoveryCodes(testActor(), user.ID, recovery[1])
	if err != nil {
		t.Fatalf("RegenerateRecoveryCodes: %v", err)
	}
	if len(fresh) != len(recovery) {
		t.Errorf("got %d fresh codes, want %d", len(fresh), len(recovery))
	}
	if _, err := s.Login(testActor(), auth, LoginInput{
		Email: user.Email, Password: twoFactorPassword, TOTPCode: recovery[2],
	}); !errors.Is(err, ErrInvalidTwoFactorCode) {
		t.Error("a code from the previous set still worked after regeneration")
	}
}

func TestDisableTwoFactor(t *testing.T) {
	s := newTestService(t)
	user := newTwoFactorUser(t, s)
	secret, _ := enrolTwoFactor(t, s, user.ID)

	code, err := certiocrypto.TOTPCode(secret, time.Now().Add(certiocrypto.TOTPPeriod*time.Second))
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}

	// A wrong password must be refused even with a valid code.
	if err := s.DisableTwoFactor(testActor(), user.ID, "wrong-password", code); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password = %v, want ErrInvalidCredentials", err)
	}
	// And the right password is not enough on its own.
	if err := s.DisableTwoFactor(testActor(), user.ID, twoFactorPassword, "000000"); !errors.Is(err, ErrInvalidTwoFactorCode) {
		t.Errorf("wrong code = %v, want ErrInvalidTwoFactorCode", err)
	}

	if err := s.DisableTwoFactor(testActor(), user.ID, twoFactorPassword, code); err != nil {
		t.Fatalf("DisableTwoFactor: %v", err)
	}

	status, err := s.TwoFactorStatusOf(user.ID)
	if err != nil {
		t.Fatalf("TwoFactorStatusOf: %v", err)
	}
	if status.Enabled || status.Pending || status.RecoveryCodesRemaining != 0 {
		t.Fatalf("after disabling: %+v, want everything cleared", status)
	}
}

func TestResetTwoFactor(t *testing.T) {
	s := newTestService(t)
	auth := NewAuthenticator([]byte("test-signing-secret-value"), "certio", time.Minute, time.Hour)
	user := newTwoFactorUser(t, s)
	enrolTwoFactor(t, s, user.ID)

	if err := s.ResetTwoFactor(testActor(), user.ID); err != nil {
		t.Fatalf("ResetTwoFactor: %v", err)
	}
	// The password alone is enough again.
	result, err := s.Login(testActor(), auth, LoginInput{Email: user.Email, Password: twoFactorPassword})
	if err != nil {
		t.Fatalf("Login after reset: %v", err)
	}
	if result.TwoFactorRequired || result.Tokens == nil {
		t.Fatal("the reset account still demanded a second factor")
	}

	// Resetting an account that has none is a validation error, not a silent
	// no-op: the caller asked for something that did not apply.
	if err := s.ResetTwoFactor(testActor(), user.ID); !errors.Is(err, ErrValidation) {
		t.Errorf("second reset = %v, want ErrValidation", err)
	}
}
