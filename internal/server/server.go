// Package server wires the okapi HTTP application: routes, middleware,
// OpenAPI documentation and the embedded SPA.
package server

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/jkaninda/certio/internal/config"
	certiocrypto "github.com/jkaninda/certio/internal/crypto"
	"github.com/jkaninda/certio/internal/metrics"
	"github.com/jkaninda/certio/internal/server/handlers"
	"github.com/jkaninda/certio/internal/server/middleware"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
	"github.com/jkaninda/okapi"
)

const (
	// defaultAdminEmail names the bootstrap account when CERTIO_ADMIN_EMAIL is
	// unset. It is an address nobody can receive mail at on purpose: it is a
	// login, and one an operator is expected to change.
	defaultAdminEmail = "admin@example.com"

	// initialPasswordFile holds a generated bootstrap password inside the data
	// directory until the operator has used it.
	initialPasswordFile = "initial-admin-password.txt"
)

// Server owns the okapi application and everything hanging off it.
type Server struct {
	app     *okapi.Okapi
	cfg     *config.Config
	log     *slog.Logger
	handler *handlers.Handler
	metrics *metrics.Metrics

	// csp is assembled after the routes exist, because part of it is derived
	// from the docs page okapi renders. The middleware reads it per request, so
	// it is written exactly once here and only read afterwards.
	csp atomic.Pointer[string]
}

// Options configures a Server.
type Options struct {
	Service *service.Service
	Auth    *service.Authenticator
	Config  *config.Config
	Logger  *slog.Logger
	Version string
	// Commit and Date are the rest of the link-time build stamp, surfaced on
	// /about so an operator can tell exactly which build is running.
	Commit string
	Date   string
	// WebFS holds the built SPA. Nil serves the API only, which is what the
	// tests and a headless deployment want.
	WebFS fs.FS
	// WebRoot is the directory inside WebFS holding index.html.
	WebRoot string
}

// New builds the HTTP application.
func New(opts Options) *Server {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	options := []okapi.OptionFunc{
		okapi.WithAddr(opts.Config.Addr()),
		okapi.WithLogger(log),
		// Everything okapi rejects before a handler runs — a failed bind, a
		// failed validation — comes back in the same shape the handlers use.
		okapi.WithErrorHandler(errorHandler),
		okapi.WithReadTimeout(opts.Config.Server.ReadTimeout),
		okapi.WithWriteTimeout(opts.Config.Server.WriteTimeout),
		okapi.WithIdleTimeout(opts.Config.Server.IdleTimeout),
		okapi.WithCors(okapi.Cors{
			AllowedOrigins:   opts.Config.Server.CORSOrigins,
			AllowedHeaders:   []string{"Authorization", "Content-Type", "Accept", "X-Requested-With"},
			AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			AllowCredentials: true,
		}),
	}
	// okapi serves the OpenAPI document by default, and StartServer registers
	// the routes again on its own. Simply not calling WithOpenAPIDocs is
	// therefore not enough to honour enable_docs=false — it has to be turned
	// off at construction, or a deployment that asked for no docs gets them.
	if !opts.Config.Server.EnableDocs {
		options = append(options, okapi.WithOpenAPIDisabled())
	}

	app := okapi.New(options...)

	s := &Server{
		app: app, cfg: opts.Config, log: log, metrics: opts.Service.Metrics,
		handler: handlers.New(opts.Service, opts.Auth, opts.Config, handlers.Build{
			Version: opts.Version, Commit: opts.Commit, Date: opts.Date,
		}),
	}

	// The policy is read per request rather than captured, because the routes
	// have to exist before it can be finished — /docs is rendered and hashed
	// below, and that needs a handler to render it.
	app.Use(middleware.SecurityHeaders(func() string {
		if policy := s.csp.Load(); policy != nil {
			return *policy
		}
		return ""
	}))

	s.routes(opts)
	s.buildContentSecurityPolicy(opts)
	return s
}

// buildContentSecurityPolicy assembles the policy once the routes are up.
//
// Both the dashboard and the docs page bootstrap from inline scripts, so both
// have to be hashed; the docs page additionally pulls Scalar from a CDN, which
// is the one external origin this application allows and only when docs are on.
func (s *Server) buildContentSecurityPolicy(opts Options) {
	builder := newPolicyBuilder()
	builder.allowInlineScriptsInFS(opts.WebFS, opts.WebRoot)

	if opts.Config.Server.EnableDocs {
		builder.allowHost(scalarCDN)
		builder.allowFontHost(scalarFonts)
		if page := renderDocsPage(s.app); page != nil {
			builder.allowInlineScriptsIn(page)
		} else {
			s.log.Warn("could not render /docs to derive its content security policy; " +
				"the documentation UI may not load")
		}
	}

	policy := builder.String()
	s.csp.Store(&policy)
}

// docs registers the OpenAPI document and its UI.
//
// It has to run after every API route, because the document is built from the
// routes registered so far — and *before* the SPA fallback, because that
// fallback owns "/" and would otherwise shadow /docs and /openapi.json, which
// is how they came to 404 in the binary while passing in the API-only tests.
//
// okapi rebuilds the document in StartServer too; doing it here as well means
// an embedded handler — tests, or mounting into another server — serves a
// complete spec without ever calling Start.
func (s *Server) docs(version string) {
	s.app.WithOpenAPIDocs(okapi.OpenAPI{
		Title:   "Certio API",
		Version: version,
		Description: "Self-signed PKI and TLS certificate management. " +
			"Create certificate authorities, issue and renew certificates with full SAN support, " +
			"revoke and publish CRLs, and export in every format a server actually wants.",
		License: okapi.License{Name: "Apache-2.0", URL: "https://github.com/jkaninda/certio/blob/main/LICENSE"},
		Contact: okapi.Contact{Name: "jkaninda", URL: "https://github.com/jkaninda/certio"},
	}).WithDocUI(okapi.ScalarUI)
}

// spa mounts the embedded dashboard. It is registered last so it never shadows
// an API route or the documentation.
func (s *Server) spa(opts Options) {
	if opts.WebFS == nil {
		return
	}
	s.app.WebFS("/", opts.WebFS, okapi.WebConfig{
		Root:   opts.WebRoot,
		MaxAge: time.Hour,
		// Never let a mistyped API path fall through to index.html: a JSON
		// client deserves a 404, not an HTML page.
		//
		// An entry matches the path itself or anything below it, so the spec
		// documents have to be named in full — "/openapi" alone would not
		// cover "/openapi.json". They are excluded whether or not docs are
		// enabled, so turning docs off yields a 404 rather than the dashboard
		// shell dressed up as a spec.
		Exclude: []string{
			"/api", "/ca", "/health", "/metrics", "/docs",
			"/openapi.json", "/openapi.yaml", "/openapi-3.0.json", "/openapi-3.0.yaml",
		},
	})
}

// Handler exposes the router for tests and for embedding in another server.
func (s *Server) Handler() http.Handler { return s.app }

// Okapi exposes the underlying application.
func (s *Server) Okapi() *okapi.Okapi { return s.app }

// Start runs the HTTP server until Stop is called.
func (s *Server) Start() error {
	if s.cfg.Server.TLSCert != "" && s.cfg.Server.TLSKey != "" {
		s.log.Info("starting HTTPS server", "addr", s.cfg.Addr())
		server := &http.Server{
			Addr:              s.cfg.Addr(),
			Handler:           s.app,
			ReadHeaderTimeout: 10 * time.Second,
		}
		return server.ListenAndServeTLS(s.cfg.Server.TLSCert, s.cfg.Server.TLSKey)
	}
	s.log.Info("starting HTTP server", "addr", s.cfg.Addr(), "docs", s.cfg.Server.EnableDocs)
	return s.app.Start()
}

// Stop shuts the server down gracefully.
func (s *Server) Stop(ctx context.Context) error {
	if err := s.app.StopWithContext(ctx); err != nil {
		return fmt.Errorf("server: shutdown: %w", err)
	}
	return nil
}

// EnsureSchema migrates the database and bootstraps the first admin.
func EnsureSchema(st *store.Store, svc *service.Service, cfg *config.Config, log *slog.Logger) error {
	if err := st.Migrate(); err != nil {
		return err
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	needs, err := svc.NeedsBootstrap()
	if err != nil {
		return fmt.Errorf("server: check for an existing account: %w", err)
	}
	if !needs {
		return nil
	}

	email := cfg.Admin.Email
	if email == "" {
		email = defaultAdminEmail
	}

	password, generated := cfg.Admin.Password, false
	if password == "" {
		password, err = certiocrypto.RandomString(18)
		if err != nil {
			return fmt.Errorf("server: generate the initial administrator password: %w", err)
		}
		generated = true
	}

	user, err := svc.Bootstrap(email, password, cfg.Admin.Name)
	if err != nil {
		return fmt.Errorf("server: bootstrap the initial administrator: %w", err)
	}
	if user == nil || !generated {
		return nil
	}

	path, err := writeInitialPassword(cfg, user.Email, password)
	if err != nil {
		log.Warn("could not write the generated administrator password to a file",
			"error", err)
	}
	log.Warn("no CERTIO_ADMIN_PASSWORD was set, so an administrator was created with a generated one",
		"email", user.Email, "password", password, "file", path,
		"action", "sign in, change this password, then delete the file")
	return nil
}

// writeInitialPassword records the generated credential next to the database,
// for the operator who reads the logs after they have rotated away. It is
// written 0600 and only ever created — an existing file is left alone, since
// bootstrap only runs on an empty database and a file already there belongs to
// an older instance.
func writeInitialPassword(cfg *config.Config, email, password string) (string, error) {
	dir := cfg.DataDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(dir, initialPasswordFile)

	body := fmt.Sprintf(`# Certio generated this administrator because CERTIO_ADMIN_PASSWORD was unset.
# Sign in, change the password, then delete this file.
email=%s
password=%s
`, email, password)

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", err
	}
	return path, nil
}
