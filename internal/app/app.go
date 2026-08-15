// Package app assembles a running Certio instance from configuration. Both
// `certio serve` and every CLI subcommand build the same object graph, so a
// certificate issued from the terminal is identical to one issued over HTTP.
package app

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/jkaninda/certio/internal/config"
	certiocrypto "github.com/jkaninda/certio/internal/crypto"
	"github.com/jkaninda/certio/internal/schedule"
	"github.com/jkaninda/certio/internal/server"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
	"github.com/jkaninda/logger"
)

// App holds every long-lived component of a Certio instance.
type App struct {
	Config    *config.Config
	Log       *slog.Logger
	Store     *store.Store
	Service   *service.Service
	Auth      *service.Authenticator
	Scheduler *schedule.Scheduler
	Server    *server.Server
	Version   string

	logger *logger.Logger
}

// Options configures how an instance is built.
type Options struct {
	ConfigPath string
	Version    string
	// Commit and Date complete the link-time build stamp; the server reports
	// them on /about.
	Commit string
	Date   string
	// WebFS holds the built SPA to embed. Nil serves the API alone.
	WebFS   fs.FS
	WebRoot string
	// WithServer builds the HTTP layer. CLI commands that talk straight to
	// the database leave it false.
	WithServer bool
}

// New builds an instance: configuration, logger, store, keyring and service.
func New(opts Options) (*App, error) {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return nil, err
	}

	log := newLogger(cfg)

	keyring, err := loadKeyring(cfg, log.Logger)
	if err != nil {
		return nil, err
	}

	st, err := store.Open(cfg, log.Logger)
	if err != nil {
		return nil, err
	}

	svc := service.New(st, keyring, cfg, log.Logger)
	// Settings persisted through the API override the file and environment,
	// so a change made in the UI survives a restart.
	applyStoredSettings(svc, cfg, log.Logger)

	jwtSecret, err := loadJWTSecret(cfg)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	auth := service.NewAuthenticator(jwtSecret, cfg.Security.JWTIssuer,
		cfg.Security.AccessTokenTTL, cfg.Security.RefreshTokenTTL)

	app := &App{
		Config: cfg, Log: log.Logger, Store: st, Service: svc, Auth: auth,
		Version: opts.Version, logger: log,
		Scheduler: schedule.New(svc, cfg, log.Logger),
	}

	if opts.WithServer {
		app.Server = server.New(server.Options{
			Service: svc, Auth: auth, Config: cfg, Logger: log.Logger,
			Version: opts.Version, Commit: opts.Commit, Date: opts.Date,
			WebFS: opts.WebFS, WebRoot: opts.WebRoot,
		})
	}
	return app, nil
}

// Migrate creates the schema and bootstraps the first administrator.
func (a *App) Migrate() error {
	return server.EnsureSchema(a.Store, a.Service, a.Config, a.Log)
}

// Close releases the database and flushes the log.
func (a *App) Close() error {
	if a.Scheduler != nil {
		a.Scheduler.Stop()
	}
	var errs []error
	if a.Store != nil {
		if err := a.Store.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if a.logger != nil {
		if err := a.logger.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// newLogger builds the process logger from configuration.
func newLogger(cfg *config.Config) *logger.Logger {
	opts := []logger.Option{logger.WithLevel(logger.LogLevel(cfg.Log.Level))}
	if cfg.Log.Format == "json" {
		opts = append(opts, logger.WithJSONFormat())
	}
	if cfg.Log.File != "" {
		opts = append(opts, logger.WithOutputFile(cfg.Log.File), logger.WithCompression())
	}
	if cfg.Log.Caller {
		opts = append(opts, logger.WithCaller())
	}
	return logger.New(opts...)
}

// loadKeyring resolves the master key and builds the envelope keyring.
//
// In production an absent key is fatal: booting with a generated one would
// silently make every previously stored private key undecryptable. In
// development a key is generated and printed so `go run` just works.
func loadKeyring(cfg *config.Config, log *slog.Logger) (*certiocrypto.Keyring, error) {
	raw, err := config.ResolveSecret(cfg.Security.MasterKey, cfg.Security.MasterKeyFile)
	if err != nil {
		return nil, err
	}

	if raw == "" {
		if cfg.Production {
			return nil, errors.New(
				"CERTIO_MASTER_KEY (or CERTIO_MASTER_KEY_FILE) is required in production mode. " +
					"Generate one with: certio keygen")
		}
		generated, err := certiocrypto.GenerateMasterKey()
		if err != nil {
			return nil, err
		}
		log.Warn("no master key configured; generated an ephemeral one for development. "+
			"Every stored private key becomes unreadable when this process exits.",
			"set", "CERTIO_MASTER_KEY="+certiocrypto.FormatMasterKey(generated))
		return certiocrypto.NewKeyring(generated)
	}

	key, err := certiocrypto.ParseMasterKey(raw)
	if err != nil {
		return nil, err
	}
	return certiocrypto.NewKeyring(key)
}

// loadJWTSecret resolves the token signing secret, generating one outside
// production. A generated secret simply invalidates existing sessions on
// restart, which is an inconvenience rather than data loss.
func loadJWTSecret(cfg *config.Config) ([]byte, error) {
	raw, err := config.ResolveSecret(cfg.Security.JWTSecret, cfg.Security.JWTSecretFile)
	if err != nil {
		return nil, err
	}
	if raw != "" {
		return []byte(raw), nil
	}
	if cfg.Production {
		return nil, errors.New(
			"CERTIO_JWT_SECRET (or CERTIO_JWT_SECRET_FILE) is required in production mode")
	}
	generated, err := certiocrypto.RandomString(32)
	if err != nil {
		return nil, err
	}
	return []byte(generated), nil
}

// applyStoredSettings overlays settings saved through the API onto the loaded
// configuration.
func applyStoredSettings(svc *service.Service, cfg *config.Config, log *slog.Logger) {
	// A fresh database has no settings table until Migrate runs. Checking
	// first keeps the very first boot from logging a SQL error that looks
	// like a fault but is simply the expected state.
	if !svc.Store.DB().Migrator().HasTable(&store.Setting{}) {
		return
	}

	rows, err := svc.Store.Settings.All()
	if err != nil {
		log.Warn("could not read stored settings; using file and environment values", "error", err)
		return
	}

	for _, row := range rows {
		switch row.Key {
		case "default_organization":
			cfg.PKI.DefaultOrganization = row.Value
		case "default_country":
			cfg.PKI.DefaultCountry = row.Value
		case "default_key_algorithm":
			cfg.PKI.DefaultKeyAlgorithm = row.Value
		case "default_validity_days":
			cfg.PKI.DefaultValidityDays = atoi(row.Value, cfg.PKI.DefaultValidityDays)
		case "expiry_warn_days":
			cfg.Scheduler.ExpiryWarnDays = atoi(row.Value, cfg.Scheduler.ExpiryWarnDays)
		}
	}
}

func atoi(s string, fallback int) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return fallback
	}
	return n
}

// MustGetenv is a small helper for CLI commands that need an environment value.
func MustGetenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
