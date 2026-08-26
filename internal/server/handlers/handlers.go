// Package handlers implements the HTTP endpoints. Handlers stay thin: they
// bind, delegate to the service layer, and map errors onto status codes.
package handlers

import (
	"errors"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/jkaninda/certio/internal/audit"
	"github.com/jkaninda/certio/internal/config"
	"github.com/jkaninda/certio/internal/server/dto"
	"github.com/jkaninda/certio/internal/server/middleware"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
	"github.com/jkaninda/okapi"
)

// Build carries the values stamped in at link time, for /health and /about.
type Build struct {
	Version string
	Commit  string
	Date    string
}

// Handler owns the dependencies every endpoint needs.
type Handler struct {
	Service *service.Service
	Auth    *service.Authenticator
	Config  *config.Config
	Build   Build
	Started time.Time
}

// New builds a Handler.
func New(svc *service.Service, auth *service.Authenticator, cfg *config.Config, build Build) *Handler {
	return &Handler{Service: svc, Auth: auth, Config: cfg, Build: build, Started: time.Now()}
}

// Version is the release the process was built from.
func (h *Handler) Version() string { return h.Build.Version }

// actor derives the audit actor for the current request.
func (h *Handler) actor(c *okapi.Context) audit.Actor {
	principal := middleware.PrincipalOf(c)
	return principal.Actor(c.RealIP(), c.Header("User-Agent"))
}

// fail maps a service error onto the right status code and body. Keeping the
// mapping in one place is what stops a validation error leaking as a 500.
func (h *Handler) fail(c *okapi.Context, err error) error {
	switch {
	case errors.Is(err, service.ErrNotFound):
		return c.AbortWithJSON(http.StatusNotFound, dto.ErrorResponse{
			Error: "not_found", Message: err.Error(),
		})

	case errors.Is(err, service.ErrValidation):
		return c.AbortWithJSON(http.StatusBadRequest, dto.ErrorResponse{
			Error: "validation_failed", Message: cleanMessage(err),
		})

	case errors.Is(err, service.ErrConflict), errors.Is(err, store.ErrInUse):
		return c.AbortWithJSON(http.StatusConflict, dto.ErrorResponse{
			Error: "conflict", Message: cleanMessage(err),
		})

	case errors.Is(err, service.ErrForbidden):
		return c.AbortWithJSON(http.StatusForbidden, dto.ErrorResponse{
			Error: "forbidden", Message: cleanMessage(err),
		})

	case errors.Is(err, service.ErrPassphraseRequired):
		// 428: the request is well-formed but cannot proceed until the client
		// supplies the CA passphrase.
		return c.AbortWithJSON(http.StatusPreconditionRequired, dto.ErrorResponse{
			Error: "passphrase_required", Message: cleanMessage(err),
		})

	case errors.Is(err, service.ErrKeyUnavailable):
		return c.AbortWithJSON(http.StatusUnprocessableEntity, dto.ErrorResponse{
			Error: "key_unavailable", Message: cleanMessage(err),
		})

	case errors.Is(err, service.ErrInvalidTwoFactorCode):
		// A distinct code so the dashboard can keep the user on the code step
		// instead of sending them back to the password form.
		return c.AbortWithJSON(http.StatusUnauthorized, dto.ErrorResponse{
			Error: "invalid_two_factor_code", Message: err.Error(),
		})

	case errors.Is(err, service.ErrInvalidCredentials), errors.Is(err, service.ErrAccountDisabled):
		return c.AbortWithJSON(http.StatusUnauthorized, dto.ErrorResponse{
			Error: "unauthorized", Message: err.Error(),
		})

	default:
		// Log the detail, return a generic message: an internal error's text
		// may name tables, paths or key material.
		h.Service.Log.Error("request failed", "error", err, "path", c.Path())
		return c.AbortWithJSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "internal_error",
			Message: "the request could not be completed; see the server log for details",
		})
	}
}

// cleanMessage strips the sentinel prefix so users see the useful half.
func cleanMessage(err error) string {
	msg := err.Error()
	for _, prefix := range []string{"validation failed: ", "pki: ", "store: ", "service: "} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	return msg
}

// badRequest is the reply for a payload that failed binding.
func badRequest(c *okapi.Context, err error) error {
	return c.AbortWithJSON(http.StatusBadRequest, dto.ErrorResponse{
		Error: "invalid_request", Message: err.Error(),
	})
}

// page turns the bound page and limit parameters into a normalised
// store.Pagination. Zero means "not supplied", which Normalize turns into the
// defaults — the binder leaves an absent query parameter untouched.
func page(number, limit int) store.Pagination {
	p := store.Pagination{Page: number, Limit: limit}
	p.Normalize()
	return p
}

func meta(p store.Pagination, total int64, pages int) dto.PageMeta {
	return dto.PageMeta{Total: total, Page: p.Page, Limit: p.Limit, TotalPages: pages}
}

// days parses the expiring_in filter, where "30d" and "30" both mean thirty
// days. It returns nil when the parameter is absent or unreadable, which the
// store treats as "no expiry filter".
func days(raw string) *int {
	if raw == "" {
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSuffix(raw, "d"))
	if err != nil {
		return nil
	}
	return &n
}

// Health reports liveness and database reachability.
func (h *Handler) Health(c *okapi.Context) error {
	resp := dto.HealthResponse{
		Status:   "ok",
		Version:  h.Build.Version,
		Database: "ok",
		Uptime:   time.Since(h.Started).Round(time.Second).String(),
	}
	if err := h.Service.Store.Ping(); err != nil {
		resp.Status, resp.Database = "degraded", "unreachable"
		return c.JSON(http.StatusServiceUnavailable, resp)
	}
	return c.OK(resp)
}

// Meta returns the reference data the UI needs to build its forms — profiles,
// key algorithms, export formats and revocation reasons — so the frontend
// never hard-codes a list the backend owns.
func (h *Handler) Meta(c *okapi.Context) error {
	profiles := pkiProfiles()

	reasons := make([]dto.ReasonDTO, 0, 10)
	for _, code := range []int{0, 1, 2, 3, 4, 5, 6, 8, 9, 10} {
		reasons = append(reasons, dto.ReasonDTO{Code: code, Name: reasonName(code)})
	}

	return c.OK(dto.MetaResponse{
		Profiles:          profiles,
		KeyAlgorithms:     keyAlgorithms(),
		ExportFormats:     service.ExportFormats(),
		RevocationReasons: reasons,
		SANTypes:          []string{"dns", "ip", "email", "uri"},
		TokenScopes:       tokenScopes(),
		MaxLeafValidity:   maxLeafValidity(),
		KeyDownloadPolicy: h.Config.Security.KeyDownloadPolicy,
		Version:           h.Build.Version,
	})
}

// About gathers what the dashboard's About page shows: the release this binary
// was built from, the Go runtime under it, and the switches this particular
// deployment is running with.
func (h *Handler) About(c *okapi.Context) error {
	return c.OK(dto.AboutResponse{
		Name:    "Certio",
		Tagline: "Self-signed PKI and TLS certificate management, in a single binary.",
		Description: "Certio manages a private certificate authority: create roots and intermediates " +
			"or import the CA you already have, issue and renew certificates with full SAN support, " +
			"revoke and publish CRLs, and export in every format a server actually wants. " +
			"The same engine backs the web dashboard, the REST API and the CLI.",

		Version:   h.Build.Version,
		Commit:    h.Build.Commit,
		BuildDate: h.Build.Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,

		License:       "AGPL-3.0",
		LicenseURL:    "https://github.com/jkaninda/certio/blob/main/LICENSE",
		Repository:    "https://github.com/jkaninda/certio",
		Documentation: "https://github.com/jkaninda/certio#readme",
		IssuesURL:     "https://github.com/jkaninda/certio/issues",

		StartedAt: h.Started.UTC(),
		Uptime:    time.Since(h.Started).Round(time.Second).String(),

		Instance: dto.AboutInstance{
			BaseURL:           h.Config.Server.BaseURL,
			DatabaseDriver:    h.Config.Database.Driver,
			TLS:               h.Config.Server.TLSCert != "" && h.Config.Server.TLSKey != "",
			DocsEnabled:       h.Config.Server.EnableDocs,
			SchedulerEnabled:  h.Config.Scheduler.Enabled,
			KeyDownloadPolicy: h.Config.Security.KeyDownloadPolicy,
			ExpiryWarnDays:    h.Config.Scheduler.ExpiryWarnDays,
			AccessTokenTTL:    h.Config.Security.AccessTokenTTL.String(),
			RefreshTokenTTL:   h.Config.Security.RefreshTokenTTL.String(),
		},
	})
}
