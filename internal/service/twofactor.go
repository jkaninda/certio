package service

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jkaninda/certio/internal/audit"
	certiocrypto "github.com/jkaninda/certio/internal/crypto"
	"github.com/jkaninda/certio/internal/store"
	qrcode "github.com/skip2/go-qrcode"
)

// ErrInvalidTwoFactorCode covers a wrong TOTP code and a spent or unknown
// recovery code alike. As with ErrInvalidCredentials the two are deliberately
// indistinguishable.
var ErrInvalidTwoFactorCode = errors.New("that code is not valid")

// ErrTwoFactorNotEnabled is returned when an operation needs an enrolled
// second factor and there is none.
var ErrTwoFactorNotEnabled = errors.New("two-factor authentication is not enabled on this account")

// qrPixelSize is the width of the enrolment QR code in pixels. 256 is large
// enough to scan from a laptop screen without making the data URI heavy.
const qrPixelSize = 256

// TwoFactorStatus describes an account's second factor as the API reports it.
type TwoFactorStatus struct {
	Enabled                bool       `json:"enabled"`
	Pending                bool       `json:"pending"`
	EnabledAt              *time.Time `json:"enabled_at,omitempty"`
	RecoveryCodesRemaining int        `json:"recovery_codes_remaining"`
}

// TOTPEnrollment is everything the setup step hands back so the user can add
// the account to an authenticator app.
type TOTPEnrollment struct {
	// Secret is the base32 shared secret, spaced for manual entry.
	Secret string `json:"secret"`
	// URI is the otpauth:// URL the QR code encodes.
	URI string `json:"uri"`
	// QRCode is a PNG data URI, rendered here so the dashboard needs no
	// QR library of its own.
	QRCode  string `json:"qr_code"`
	Issuer  string `json:"issuer"`
	Account string `json:"account"`
}

// TwoFactorStatusOf reads an account's second-factor state.
func (s *Service) TwoFactorStatusOf(userID string) (*TwoFactorStatus, error) {
	user, err := s.Store.Users.Get(userID)
	if err != nil {
		return nil, err
	}
	return statusOf(user), nil
}

func statusOf(u *store.User) *TwoFactorStatus {
	return &TwoFactorStatus{
		Enabled:                u.HasTwoFactor(),
		Pending:                u.TOTPEnrollmentPending(),
		EnabledAt:              u.TOTPEnabledAt,
		RecoveryCodesRemaining: u.RecoveryCodesRemaining(),
	}
}

// BeginTOTPEnrollment generates a fresh secret and stores it sealed, but
// leaves the second factor switched off until a code confirms the
// authenticator actually holds it. Calling this again replaces an unconfirmed
// secret, so a half-finished setup can simply be restarted.
func (s *Service) BeginTOTPEnrollment(userID string) (*TOTPEnrollment, error) {
	user, err := s.Store.Users.Get(userID)
	if err != nil {
		return nil, err
	}
	if user.HasTwoFactor() {
		return nil, validationError(
			"two-factor authentication is already enabled; disable it before enrolling a new device")
	}

	secret, err := certiocrypto.GenerateTOTPSecret()
	if err != nil {
		return nil, err
	}
	env, err := s.Keyring.SealString(secret, "")
	if err != nil {
		return nil, err
	}

	user.TOTPSecretEncrypted, user.TOTPSecretNonce, user.TOTPSecretSalt = env.Ciphertext, env.Nonce, env.Salt
	user.TOTPEnabled, user.TOTPEnabledAt, user.TOTPLastStep = false, nil, 0
	user.RecoveryCodes = store.JSON([]string(nil))
	if err := s.Store.Users.Update(user); err != nil {
		return nil, err
	}

	issuer := s.totpIssuer()
	uri := certiocrypto.TOTPProvisioningURI(issuer, user.Email, secret)
	png, err := qrcode.Encode(uri, qrcode.Medium, qrPixelSize)
	if err != nil {
		return nil, fmt.Errorf("service: render the enrolment QR code: %w", err)
	}

	return &TOTPEnrollment{
		Secret:  certiocrypto.FormatTOTPSecret(secret),
		URI:     uri,
		QRCode:  dataURI("image/png", png),
		Issuer:  issuer,
		Account: user.Email,
	}, nil
}

// ConfirmTOTPEnrollment switches the second factor on once the pending secret
// produces a matching code, and returns the recovery codes exactly once.
func (s *Service) ConfirmTOTPEnrollment(actor audit.Actor, userID, code string) ([]string, error) {
	user, err := s.Store.Users.Get(userID)
	if err != nil {
		return nil, err
	}
	if user.HasTwoFactor() {
		return nil, validationError("two-factor authentication is already enabled on this account")
	}
	if !user.TOTPEnrollmentPending() {
		return nil, validationError("start the enrolment before confirming it")
	}

	secret, err := s.openTOTPSecret(user)
	if err != nil {
		return nil, err
	}
	step, ok := certiocrypto.VerifyTOTPStep(secret, code, time.Now())
	if !ok {
		s.Audit.RecordFailure(actor, audit.Entry{
			Action: audit.ActionTwoFactorFailed, ResourceType: audit.ResourceUser,
			ResourceID: user.ID, ResourceName: user.Email,
		}, ErrInvalidTwoFactorCode)
		return nil, ErrInvalidTwoFactorCode
	}

	codes, hashes, err := certiocrypto.GenerateRecoveryCodes()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	user.TOTPEnabled, user.TOTPEnabledAt, user.TOTPLastStep = true, &now, step
	user.RecoveryCodes = store.JSON(hashes)
	if err := s.Store.Users.Update(user); err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionTwoFactorEnabled, ResourceType: audit.ResourceUser,
		ResourceID: user.ID, ResourceName: user.Email,
		Metadata: map[string]any{"method": "totp", "recovery_codes": len(codes)},
	})
	return codes, nil
}

// DisableTwoFactor turns the second factor off for the account holder. It
// demands the current password as well as a valid code: a borrowed session
// must not be enough to strip a factor off.
func (s *Service) DisableTwoFactor(actor audit.Actor, userID, password, code string) error {
	user, err := s.Store.Users.Get(userID)
	if err != nil {
		return err
	}
	if !user.HasTwoFactor() && !user.TOTPEnrollmentPending() {
		return validationError("two-factor authentication is not enabled on this account")
	}

	if err := certiocrypto.VerifyPassword(password, user.PasswordHash); err != nil {
		return ErrInvalidCredentials
	}
	// An abandoned enrolment has no working authenticator to produce a code
	// with, so only a confirmed factor has to be proved before removal.
	if user.HasTwoFactor() {
		if _, err := s.verifySecondFactor(actor, user, code); err != nil {
			return err
		}
	}

	s.clearTwoFactor(user)
	if err := s.Store.Users.Update(user); err != nil {
		return err
	}

	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionTwoFactorDisabled, ResourceType: audit.ResourceUser,
		ResourceID: user.ID, ResourceName: user.Email,
	})
	return nil
}

// ResetTwoFactor clears another account's second factor. It is the way back in
// for someone who lost their device and their recovery codes, so it is an
// administrator action and is always audited under a distinct action name.
func (s *Service) ResetTwoFactor(actor audit.Actor, userID string) error {
	user, err := s.Store.Users.Get(userID)
	if err != nil {
		return err
	}
	if !user.HasTwoFactor() && !user.TOTPEnrollmentPending() {
		return validationError("two-factor authentication is not enabled on this account")
	}

	s.clearTwoFactor(user)
	if err := s.Store.Users.Update(user); err != nil {
		return err
	}

	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionTwoFactorReset, ResourceType: audit.ResourceUser,
		ResourceID: user.ID, ResourceName: user.Email,
	})
	return nil
}

// RegenerateRecoveryCodes issues a fresh set and invalidates every old one.
// A current code is required, so a session alone cannot mint credentials that
// outlive it.
func (s *Service) RegenerateRecoveryCodes(actor audit.Actor, userID, code string) ([]string, error) {
	user, err := s.Store.Users.Get(userID)
	if err != nil {
		return nil, err
	}
	if !user.HasTwoFactor() {
		return nil, fmt.Errorf("%w: %w", ErrValidation, ErrTwoFactorNotEnabled)
	}
	if _, err := s.verifySecondFactor(actor, user, code); err != nil {
		return nil, err
	}

	codes, hashes, err := certiocrypto.GenerateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	user.RecoveryCodes = store.JSON(hashes)
	if err := s.Store.Users.Update(user); err != nil {
		return nil, err
	}

	s.Audit.Record(actor, audit.Entry{
		Action: audit.ActionRecoveryCodesRenewed, ResourceType: audit.ResourceUser,
		ResourceID: user.ID, ResourceName: user.Email,
		Metadata: map[string]any{"count": len(codes)},
	})
	return codes, nil
}

// verifySecondFactor accepts either a TOTP code or an unspent recovery code,
// persisting whatever the acceptance consumed: the time step for a TOTP code,
// the code itself for a recovery code. It reports whether a recovery code was
// used so the caller can warn the user.
func (s *Service) verifySecondFactor(actor audit.Actor, user *store.User, code string) (usedRecovery bool, err error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return false, ErrInvalidTwoFactorCode
	}

	secret, err := s.openTOTPSecret(user)
	if err != nil {
		return false, err
	}

	if step, ok := certiocrypto.VerifyTOTPStep(secret, code, time.Now()); ok {
		// Refusing a step already spent is what makes an observed code useless
		// for the remainder of its window.
		if step <= user.TOTPLastStep {
			s.recordTwoFactorFailure(actor, user, "code already used")
			return false, ErrInvalidTwoFactorCode
		}
		user.TOTPLastStep = step
		if err := s.Store.Users.Update(user); err != nil {
			return false, err
		}
		return false, nil
	}

	if spent := consumeRecoveryCode(user, code); spent {
		if err := s.Store.Users.Update(user); err != nil {
			return false, err
		}
		s.Audit.Record(actor, audit.Entry{
			Action: audit.ActionRecoveryCodeUsed, ResourceType: audit.ResourceUser,
			ResourceID: user.ID, ResourceName: user.Email,
			Metadata: map[string]any{"remaining": user.RecoveryCodesRemaining()},
		})
		return true, nil
	}

	s.recordTwoFactorFailure(actor, user, "")
	return false, ErrInvalidTwoFactorCode
}

func (s *Service) recordTwoFactorFailure(actor audit.Actor, user *store.User, reason string) {
	entry := audit.Entry{
		Action: audit.ActionTwoFactorFailed, ResourceType: audit.ResourceUser,
		ResourceID: user.ID, ResourceName: user.Email,
	}
	if reason != "" {
		entry.Metadata = map[string]any{"reason": reason}
	}
	s.Audit.RecordFailure(actor, entry, ErrInvalidTwoFactorCode)
}

// consumeRecoveryCode removes a matching unspent code from the user in memory,
// reporting whether one was found. Every stored digest is compared so the work
// does not depend on which code was supplied.
func consumeRecoveryCode(user *store.User, code string) bool {
	stored := user.RecoveryCodes.Data
	if len(stored) == 0 {
		return false
	}

	want := certiocrypto.HashRecoveryCode(code)
	remaining := make([]string, 0, len(stored))
	found := false
	for _, hash := range stored {
		if certiocrypto.ConstantTimeEqual([]byte(hash), []byte(want)) {
			found = true
			continue
		}
		remaining = append(remaining, hash)
	}
	if !found {
		return false
	}
	user.RecoveryCodes = store.JSON(remaining)
	return true
}

// clearTwoFactor wipes every trace of the second factor from a user in memory.
func (s *Service) clearTwoFactor(user *store.User) {
	user.TOTPEnabled = false
	user.TOTPSecretEncrypted, user.TOTPSecretNonce, user.TOTPSecretSalt = nil, nil, nil
	user.TOTPEnabledAt, user.TOTPLastStep = nil, 0
	user.RecoveryCodes = store.JSON([]string(nil))
}

// openTOTPSecret unseals the stored shared secret.
func (s *Service) openTOTPSecret(user *store.User) (string, error) {
	if len(user.TOTPSecretEncrypted) == 0 {
		return "", fmt.Errorf("%w: %w", ErrValidation, ErrTwoFactorNotEnabled)
	}
	return s.Keyring.OpenString(certiocrypto.Envelope{
		Ciphertext: user.TOTPSecretEncrypted,
		Nonce:      user.TOTPSecretNonce,
		Salt:       user.TOTPSecretSalt,
	}, "")
}

// totpIssuer is the label authenticator apps group the entry under. The base
// URL's host distinguishes one Certio instance from another on the same phone;
// without it every deployment would just be "Certio".
func (s *Service) totpIssuer() string {
	if s.Config == nil || s.Config.Server.BaseURL == "" {
		return "Certio"
	}
	parsed, err := url.Parse(s.Config.Server.BaseURL)
	if err != nil || parsed.Hostname() == "" {
		return "Certio"
	}
	// A colon in the issuer breaks the otpauth label, which is colon-separated.
	return "Certio (" + strings.ReplaceAll(parsed.Hostname(), ":", "") + ")"
}

// dataURI renders bytes as an inline data: URL.
func dataURI(mediaType string, payload []byte) string {
	return "data:" + mediaType + ";base64," + base64.StdEncoding.EncodeToString(payload)
}
