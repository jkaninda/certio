package handlers

import (
	"net/http"

	"github.com/jkaninda/certio/internal/server/dto"
	"github.com/jkaninda/certio/internal/server/middleware"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/okapi"
)

// recoveryCodeWarning is shown wherever recovery codes are returned. They are
// stored only as digests, so this really is the one chance to keep them.
const recoveryCodeWarning = "These codes are shown once and cannot be recovered. " +
	"Store them somewhere other than the device holding your authenticator app. " +
	"Each one works exactly once."

// TwoFactorStatus reports whether the caller has a second factor enrolled.
func (h *Handler) TwoFactorStatus(c *okapi.Context) error {
	principal := middleware.PrincipalOf(c)
	if principal == nil {
		return h.fail(c, service.ErrInvalidCredentials)
	}

	status, err := h.Service.TwoFactorStatusOf(principal.UserID)
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.NewTwoFactorStatusResponse(status))
}

// SetupTwoFactor generates a pending secret and returns the QR code to scan.
// Nothing is enforced until EnableTwoFactor confirms it.
func (h *Handler) SetupTwoFactor(c *okapi.Context) error {
	principal := middleware.PrincipalOf(c)
	if principal == nil {
		return h.fail(c, service.ErrInvalidCredentials)
	}
	// An API token is a credential in its own right; letting one enrol a second
	// factor for the account it belongs to would defeat the point of the
	// factor. Enrolment is a browser-session action.
	if principal.TokenID != "" {
		return c.AbortWithJSON(http.StatusForbidden, dto.ErrorResponse{
			Error:   "forbidden",
			Message: "two-factor enrolment must be done from a signed-in session, not with an API token",
		})
	}

	enrollment, err := h.Service.BeginTOTPEnrollment(principal.UserID)
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.TwoFactorSetupResponse{
		Secret: enrollment.Secret, URI: enrollment.URI, QRCode: enrollment.QRCode,
		Issuer: enrollment.Issuer, Account: enrollment.Account,
	})
}

// EnableTwoFactor confirms a pending enrolment and returns the recovery codes.
func (h *Handler) EnableTwoFactor(c *okapi.Context, req *dto.TwoFactorCodeRequest) error {
	principal := middleware.PrincipalOf(c)
	if principal == nil {
		return h.fail(c, service.ErrInvalidCredentials)
	}

	codes, err := h.Service.ConfirmTOTPEnrollment(h.actor(c), principal.UserID, req.Body.Code)
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.RecoveryCodesResponse{RecoveryCodes: codes, Warning: recoveryCodeWarning})
}

// DisableTwoFactor removes the caller's own second factor.
func (h *Handler) DisableTwoFactor(c *okapi.Context, req *dto.TwoFactorDisableRequest) error {
	principal := middleware.PrincipalOf(c)
	if principal == nil {
		return h.fail(c, service.ErrInvalidCredentials)
	}

	if err := h.Service.DisableTwoFactor(h.actor(c), principal.UserID,
		req.Body.Password, req.Body.Code); err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.MessageResponse{Message: "two-factor authentication disabled"})
}

// RegenerateRecoveryCodes issues a fresh set and voids the old one.
func (h *Handler) RegenerateRecoveryCodes(c *okapi.Context, req *dto.TwoFactorCodeRequest) error {
	principal := middleware.PrincipalOf(c)
	if principal == nil {
		return h.fail(c, service.ErrInvalidCredentials)
	}

	codes, err := h.Service.RegenerateRecoveryCodes(h.actor(c), principal.UserID, req.Body.Code)
	if err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.RecoveryCodesResponse{RecoveryCodes: codes, Warning: recoveryCodeWarning})
}

// ResetUserTwoFactor clears another account's second factor. It is the way
// back in for someone who lost both their device and their recovery codes.
func (h *Handler) ResetUserTwoFactor(c *okapi.Context, req *dto.UserRefRequest) error {
	if err := h.Service.ResetTwoFactor(h.actor(c), req.ID); err != nil {
		return h.fail(c, err)
	}
	return c.OK(dto.MessageResponse{
		Message: "two-factor authentication reset; the account can sign in with its password alone",
	})
}
