// Package config loads Certio configuration from a YAML file, overlays
// environment variables (CERTIO_*) and validates the result.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/logger"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

const (
	// EnvPrefix is the prefix for every Certio environment variable.
	EnvPrefix = "CERTIO_"

	// KeyDownloadOnce allows a private key to be downloaded exactly once.
	KeyDownloadOnce = "once"
	// KeyDownloadAlways allows unlimited private key downloads.
	KeyDownloadAlways = "always"
	// KeyDownloadNever forbids private key downloads through the API.
	KeyDownloadNever = "never"
)

// Config is the root configuration document.
type Config struct {
	// Production refuses insecure defaults (empty/development master key).
	Production bool `yaml:"production"`

	Server    ServerConfig    `yaml:"server"`
	Database  DatabaseConfig  `yaml:"database"`
	ACME      ACMEConfig      `yaml:"acme"`
	Security  SecurityConfig  `yaml:"security"`
	Admin     AdminConfig     `yaml:"admin"`
	Scheduler SchedulerConfig `yaml:"scheduler"`
	Log       LogConfig       `yaml:"log"`
	PKI       PKIConfig       `yaml:"pki"`
}

// ServerConfig controls the HTTP listener.
type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	// BaseURL is the externally reachable root, used to build CRL/OCSP
	// distribution points baked into issued certificates.
	BaseURL      string   `yaml:"base_url"`
	ReadTimeout  int      `yaml:"read_timeout"`
	WriteTimeout int      `yaml:"write_timeout"`
	IdleTimeout  int      `yaml:"idle_timeout"`
	CORSOrigins  []string `yaml:"cors_origins"`
	EnableDocs   bool     `yaml:"enable_docs"`
	TLSCert      string   `yaml:"tls_cert"`
	TLSKey       string   `yaml:"tls_key"`
}

// Database drivers Certio can persist to.
const (
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"
)

// DefaultDBPath is the SQLite file used when nothing else is configured.
const DefaultDBPath = "certio.db"

// DatabaseConfig selects the persistence backend.
//
// SQLite is the default and the single-binary story; Postgres exists for the
// deployment that wants managed backups or more than one instance in front of
// one database. Path applies to SQLite; DSN applies to either and wins when
// both are set.
type DatabaseConfig struct {
	// URL is the whole database configuration in one value, the way every
	// other service takes it:
	//
	//	postgres://certio:secret@db:5432/certio?sslmode=require
	//	sqlite:///data/certio.db
	//
	// The scheme picks the driver, so nothing else has to be set. It wins over
	// Driver, Path and DSN, which remain for configurations written before it.
	URL    string `yaml:"url"`
	Driver string `yaml:"driver"`
	Path   string `yaml:"path"`
	DSN    string `yaml:"dsn"`
}

// ACMEConfig configures the RFC 8555 server.
//
// It is off by default. Turning it on means anything that can reach the
// directory and hold a valid external account binding can obtain certificates
// from the configured CA — which is the point, but it is a decision rather
// than a default.
type ACMEConfig struct {
	Enabled bool `yaml:"enabled"`
	// Authority is the CA that signs ACME orders, by ID or slug. Pointing it
	// at a name-constrained intermediate is the arrangement that makes
	// unattended issuance safe.
	Authority string `yaml:"authority"`
	// ValidityDays is the lifetime of an ACME-issued certificate. Short is
	// correct here: the whole point is that renewal is automatic.
	ValidityDays int `yaml:"validity_days"`

	// RequireEAB demands an administrator-issued binding to register. Leaving
	// it on is what stops any host on the network from minting certificates.
	RequireEAB bool `yaml:"require_eab"`

	HTTP01Enabled bool `yaml:"http01_enabled"`
	DNS01Enabled  bool `yaml:"dns01_enabled"`
	// HTTP01Port is where http-01 challenges are fetched. RFC 8555 fixes it at
	// 80; a segmented private network sometimes cannot offer that.
	HTTP01Port int `yaml:"http01_port"`
	// Resolver is the DNS server used for dns-01, e.g. "10.0.0.53:53". Empty
	// uses the system resolver — which on a private network often cannot see
	// the names being validated.
	Resolver string `yaml:"resolver"`

	TermsURL   string `yaml:"terms_url"`
	WebsiteURL string `yaml:"website_url"`
}

// SecurityConfig holds secrets, token lifetimes and download policy.
type SecurityConfig struct {
	MasterKey     string `yaml:"master_key"`
	MasterKeyFile string `yaml:"master_key_file"`
	JWTSecret     string `yaml:"jwt_secret"`
	JWTSecretFile string `yaml:"jwt_secret_file"`
	JWTIssuer     string `yaml:"jwt_issuer"`

	AccessTokenTTL  time.Duration `yaml:"access_token_ttl"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl"`

	// KeyDownloadPolicy is one of once|always|never.
	KeyDownloadPolicy string `yaml:"key_download_policy"`

	// LoginRateLimit is the number of login attempts allowed per window.
	LoginRateLimit  int           `yaml:"login_rate_limit"`
	LoginRateWindow time.Duration `yaml:"login_rate_window"`

	// IssueRateLimit caps issuance per window per client. Signing is the one
	// authenticated operation that both costs real CPU and writes a permanent
	// row, so a looping CI job can fill the database and the CRL with
	// certificates nobody asked for. Zero disables the limit.
	IssueRateLimit  int           `yaml:"issue_rate_limit"`
	IssueRateWindow time.Duration `yaml:"issue_rate_window"`
}

// AdminConfig bootstraps the first administrator on an empty database.
type AdminConfig struct {
	Email    string `yaml:"email"`
	Password string `yaml:"password"`
	Name     string `yaml:"name"`
}

// SchedulerConfig drives the in-process background worker.
type SchedulerConfig struct {
	Enabled     bool          `yaml:"enabled"`
	Interval    time.Duration `yaml:"interval"`
	CRLInterval time.Duration `yaml:"crl_interval"`
	// ExpiryWarnDays is the threshold at which a certificate is marked
	// "expiring" and notifications fire.
	ExpiryWarnDays int `yaml:"expiry_warn_days"`
}

// LogConfig configures the process logger.
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	File   string `yaml:"file"`
	Caller bool   `yaml:"caller"`
}

// PKIConfig holds issuance defaults applied when a request omits them.
type PKIConfig struct {
	DefaultOrganization string `yaml:"default_organization"`
	DefaultCountry      string `yaml:"default_country"`
	DefaultKeyAlgorithm string `yaml:"default_key_algorithm"`
	DefaultValidityDays int    `yaml:"default_validity_days"`
	DefaultCAValidity   int    `yaml:"default_ca_validity_days"`
	// CRLValidity is how long a generated CRL stays valid.
	CRLValidity time.Duration `yaml:"crl_validity"`
}

// Default returns a configuration with every field populated.
func Default() *Config {
	return &Config{
		Production: false,
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8080,
			BaseURL:      "http://localhost:8080",
			ReadTimeout:  30,
			WriteTimeout: 60,
			IdleTimeout:  120,
			CORSOrigins:  []string{"*"},
			// The API description is the documentation; an instance that
			// serves the API without it is harder to use for no gain. Set
			// CERTIO_ENABLE_DOCS=false to turn it off.
			EnableDocs: true,
		},
		ACME: ACMEConfig{
			Enabled:       false,
			ValidityDays:  90,
			RequireEAB:    true,
			HTTP01Enabled: true,
			DNS01Enabled:  true,
			HTTP01Port:    80,
		},
		Database: DatabaseConfig{
			Driver: DriverSQLite,
			Path:   DefaultDBPath,
		},
		Security: SecurityConfig{
			JWTIssuer: "certio",
			// An hour is long enough that issuing a batch of certificates or
			// walking a trust guide never expires mid-task, and short enough
			// that a leaked access token is not a lasting problem. Certio
			// keeps no denylist, so this window *is* the revocation story for
			// a session — shorten it if that trade does not suit you.
			AccessTokenTTL:    time.Hour,
			RefreshTokenTTL:   7 * 24 * time.Hour,
			KeyDownloadPolicy: KeyDownloadAlways,
			LoginRateLimit:    10,
			LoginRateWindow:   time.Minute,
			IssueRateLimit:    60,
			IssueRateWindow:   time.Minute,
		},
		Admin: AdminConfig{
			Name: "Administrator",
		},
		Scheduler: SchedulerConfig{
			Enabled:        true,
			Interval:       time.Hour,
			CRLInterval:    24 * time.Hour,
			ExpiryWarnDays: 30,
		},
		Log: LogConfig{
			Level:  "info",
			Format: "text",
		},
		PKI: PKIConfig{
			DefaultKeyAlgorithm: "ecdsa-p256",
			DefaultValidityDays: 397,
			DefaultCAValidity:   3650,
			CRLValidity:         7 * 24 * time.Hour,
		},
	}
}

// Load reads an optional YAML file, applies environment overrides and
// validates the result. An empty path skips the file.
func Load(path string) (*Config, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // operator-provided path
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("read config %s: %w", path, err)
			}
		} else if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
	}

	cfg.applyEnv()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyEnv overlays CERTIO_* environment variables on top of the file values.
//
// Each lookup passes the value already in hand as its fallback, so the
// precedence reads straight off the page: environment beats file beats
// Default(). Defaults themselves stay in Default() and are not repeated here —
// one source, so a literal in this function can never disagree with it.
func (c *Config) applyEnv() {
	if err := godotenv.Load(); err != nil {
		logger.Debug("no .env file found, using environment variables")
	}

	c.Production = envBool("PRODUCTION", c.Production)

	c.Server.Host = env("HOST", c.Server.Host)
	c.Server.Port = envInt("PORT", c.Server.Port)
	c.Server.BaseURL = env("BASE_URL", c.Server.BaseURL)
	c.Server.EnableDocs = envBool("ENABLE_DOCS", c.Server.EnableDocs)
	c.Server.TLSCert = env("TLS_CERT", c.Server.TLSCert)
	c.Server.TLSKey = env("TLS_KEY", c.Server.TLSKey)
	c.Server.ReadTimeout = envInt("READ_TIMEOUT", c.Server.ReadTimeout)
	c.Server.WriteTimeout = envInt("WRITE_TIMEOUT", c.Server.WriteTimeout)
	c.Server.IdleTimeout = envInt("IDLE_TIMEOUT", c.Server.IdleTimeout)
	c.Server.CORSOrigins = envList("CORS_ORIGINS", c.Server.CORSOrigins)

	c.ACME.Enabled = envBool("ACME_ENABLED", c.ACME.Enabled)
	c.ACME.Authority = env("ACME_AUTHORITY", c.ACME.Authority)
	c.ACME.ValidityDays = envInt("ACME_VALIDITY_DAYS", c.ACME.ValidityDays)
	c.ACME.RequireEAB = envBool("ACME_REQUIRE_EAB", c.ACME.RequireEAB)
	c.ACME.HTTP01Enabled = envBool("ACME_HTTP01_ENABLED", c.ACME.HTTP01Enabled)
	c.ACME.DNS01Enabled = envBool("ACME_DNS01_ENABLED", c.ACME.DNS01Enabled)
	c.ACME.HTTP01Port = envInt("ACME_HTTP01_PORT", c.ACME.HTTP01Port)
	c.ACME.Resolver = env("ACME_RESOLVER", c.ACME.Resolver)
	c.ACME.TermsURL = env("ACME_TERMS_URL", c.ACME.TermsURL)
	c.ACME.WebsiteURL = env("ACME_WEBSITE_URL", c.ACME.WebsiteURL)

	c.Database.URL = env("DB_URL", c.Database.URL)
	c.Database.Driver = env("DB_DRIVER", c.Database.Driver)
	c.Database.Path = env("DB_PATH", c.Database.Path)
	c.Database.DSN = env("DB_DSN", c.Database.DSN)

	if c.Database.DSN == "" {
		c.Database.DSN = env("DB_URL", c.Database.DSN)
	}

	c.Security.MasterKey = env("MASTER_KEY", c.Security.MasterKey)
	c.Security.MasterKeyFile = env("MASTER_KEY_FILE", c.Security.MasterKeyFile)
	c.Security.JWTSecret = env("JWT_SECRET", c.Security.JWTSecret)
	c.Security.JWTSecretFile = env("JWT_SECRET_FILE", c.Security.JWTSecretFile)
	c.Security.JWTIssuer = env("JWT_ISSUER", c.Security.JWTIssuer)
	c.Security.AccessTokenTTL = envDuration("ACCESS_TOKEN_TTL", c.Security.AccessTokenTTL)
	c.Security.RefreshTokenTTL = envDuration("REFRESH_TOKEN_TTL", c.Security.RefreshTokenTTL)
	c.Security.KeyDownloadPolicy = env("KEY_DOWNLOAD_POLICY", c.Security.KeyDownloadPolicy)
	c.Security.LoginRateLimit = envInt("LOGIN_RATE_LIMIT", c.Security.LoginRateLimit)
	c.Security.LoginRateWindow = envDuration("LOGIN_RATE_WINDOW", c.Security.LoginRateWindow)
	c.Security.IssueRateLimit = envInt("ISSUE_RATE_LIMIT", c.Security.IssueRateLimit)
	c.Security.IssueRateWindow = envDuration("ISSUE_RATE_WINDOW", c.Security.IssueRateWindow)

	c.Admin.Email = env("ADMIN_EMAIL", c.Admin.Email)
	c.Admin.Password = env("ADMIN_PASSWORD", c.Admin.Password)
	c.Admin.Name = env("ADMIN_NAME", c.Admin.Name)

	c.Scheduler.Enabled = envBool("SCHEDULER_ENABLED", c.Scheduler.Enabled)
	c.Scheduler.Interval = envDuration("SCHEDULER_INTERVAL", c.Scheduler.Interval)
	c.Scheduler.CRLInterval = envDuration("CRL_INTERVAL", c.Scheduler.CRLInterval)
	c.Scheduler.ExpiryWarnDays = envInt("EXPIRY_WARN_DAYS", c.Scheduler.ExpiryWarnDays)

	c.Log.Level = env("LOG_LEVEL", c.Log.Level)
	c.Log.Format = env("LOG_FORMAT", c.Log.Format)
	c.Log.File = env("LOG_FILE", c.Log.File)
	c.Log.Caller = envBool("LOG_CALLER", c.Log.Caller)

	c.PKI.DefaultOrganization = env("DEFAULT_ORGANIZATION", c.PKI.DefaultOrganization)
	c.PKI.DefaultCountry = env("DEFAULT_COUNTRY", c.PKI.DefaultCountry)
	c.PKI.DefaultKeyAlgorithm = env("DEFAULT_KEY_ALGORITHM", c.PKI.DefaultKeyAlgorithm)
	c.PKI.DefaultValidityDays = envInt("DEFAULT_VALIDITY_DAYS", c.PKI.DefaultValidityDays)
	c.PKI.DefaultCAValidity = envInt("DEFAULT_CA_VALIDITY_DAYS", c.PKI.DefaultCAValidity)
	c.PKI.CRLValidity = envDuration("CRL_VALIDITY", c.PKI.CRLValidity)
}

// Validate reports configuration that would produce a broken or unsafe server.
func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port %d out of range", c.Server.Port)
	}
	if err := c.applyDatabaseURL(); err != nil {
		return err
	}
	switch c.Database.Driver {
	case DriverSQLite, "":
		c.Database.Driver = DriverSQLite
		if c.Database.Path == "" && c.Database.DSN == "" {
			return errors.New("database.path is required for the sqlite driver")
		}
	case DriverPostgres, "postgresql", "pgx":
		c.Database.Driver = DriverPostgres
		if c.Database.DSN == "" {
			return errors.New(
				"the postgres driver needs a connection string: set CERTIO_DB_URL, " +
					"e.g. postgres://certio:secret@localhost:5432/certio?sslmode=require")
		}
	default:
		return fmt.Errorf("unsupported database driver %q (want sqlite or postgres)", c.Database.Driver)
	}

	switch c.Security.KeyDownloadPolicy {
	case KeyDownloadOnce, KeyDownloadAlways, KeyDownloadNever:
	default:
		return fmt.Errorf("security.key_download_policy %q must be one of once|always|never",
			c.Security.KeyDownloadPolicy)
	}

	if c.Scheduler.ExpiryWarnDays <= 0 {
		c.Scheduler.ExpiryWarnDays = 30
	}
	if c.PKI.DefaultValidityDays <= 0 {
		c.PKI.DefaultValidityDays = 397
	}
	if c.PKI.DefaultCAValidity <= 0 {
		c.PKI.DefaultCAValidity = 3650
	}
	if c.PKI.CRLValidity <= 0 {
		c.PKI.CRLValidity = 7 * 24 * time.Hour
	}
	if c.ACME.Enabled {
		if c.ACME.Authority == "" {
			return errors.New(
				"acme.authority (CERTIO_ACME_AUTHORITY) is required when ACME is enabled: " +
					"it names the CA that signs ACME orders")
		}
		if !c.ACME.HTTP01Enabled && !c.ACME.DNS01Enabled {
			return errors.New("acme needs at least one of http01_enabled and dns01_enabled")
		}
		if c.ACME.ValidityDays <= 0 {
			c.ACME.ValidityDays = 90
		}
		if c.ACME.HTTP01Port <= 0 {
			c.ACME.HTTP01Port = 80
		}
	}

	c.Server.BaseURL = strings.TrimSuffix(c.Server.BaseURL, "/")
	return nil
}

// Addr is the listen address for the HTTP server.
func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// ResolveSecret returns the value of an inline secret, or the trimmed contents
// of the file it points at. Returns an empty string when neither is set.
func ResolveSecret(inline, file string) (string, error) {
	if file != "" {
		data, err := os.ReadFile(file) //nolint:gosec // operator-provided path
		if err != nil {
			return "", fmt.Errorf("read secret file %s: %w", file, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return inline, nil
}

// applyDatabaseURL expands database.url (CERTIO_DB_URL) into the driver and
// the connection string that driver wants. It runs before validation, so the
// rest of the program never has to know which of the two forms was used.
//
// The scheme is the whole decision:
//
//	postgres:// | postgresql:// | pgx://   the URL is handed to pgx as it is
//	sqlite:// | sqlite3:// | file:         the path is opened as a SQLite file
//	(no scheme)                            a bare path is a SQLite file
func (c *Config) applyDatabaseURL() error {
	raw := strings.TrimSpace(c.Database.URL)
	if raw == "" {
		return nil
	}

	scheme, _, hasScheme := strings.Cut(raw, ":")
	if !hasScheme || strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, ".") {
		c.Database.Driver = DriverSQLite
		c.Database.Path, c.Database.DSN = raw, ""
		return nil
	}

	switch strings.ToLower(scheme) {
	case DriverPostgres, "postgresql", "pgx":
		c.Database.Driver = DriverPostgres
		c.Database.DSN, c.Database.Path = raw, ""
		return nil

	case DriverSQLite, "sqlite3", "file":
		parsed, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("database.url (%s) is not a URL: %w", EnvPrefix+"DB_URL", err)
		}

		path := parsed.Opaque
		if path == "" {
			path = parsed.Host + parsed.Path
		}
		if path == "" {
			return fmt.Errorf("database.url (%s) names no SQLite file", EnvPrefix+"DB_URL")
		}
		c.Database.Driver = DriverSQLite
		c.Database.Path = path
		c.Database.DSN = ""
		if parsed.RawQuery != "" {
			c.Database.DSN = path + "?" + parsed.RawQuery
		}
		return nil

	default:
		return fmt.Errorf("unsupported database.url scheme %q (want postgres:// or sqlite:)", scheme)
	}
}

// DatabaseDSN returns the connection string for the configured driver.
func (c *Config) DatabaseDSN() string {
	if c.Database.DSN != "" {
		return c.Database.DSN
	}
	if c.Database.Driver == DriverPostgres {
		// Validate refuses this combination, so reaching here means the config
		// was built by hand rather than loaded.
		return ""
	}
	// Foreign keys are off by default in SQLite; Certio relies on them for the
	// CA -> certificate relationship.
	return c.Database.Path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
}

// EnsureDataDir creates the directory holding the SQLite database.
func (c *Config) EnsureDataDir() error {
	if c.Database.Driver != DriverSQLite || c.Database.Path == "" {
		return nil
	}
	dir := filepath.Dir(c.Database.Path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o750)
}

// The lookups below delegate to go-utils, which owns the parsing and the
// fallback in one call. They exist as thin wrappers only to apply EnvPrefix,
// so no call site has to spell "CERTIO_" out and none can misspell it.

func env(key, fallback string) string {
	return goutils.Env(EnvPrefix+key, fallback)
}

func envInt(key string, fallback int) int {
	return goutils.EnvInt(EnvPrefix+key, fallback)
}

func envBool(key string, fallback bool) bool {
	return goutils.EnvBool(EnvPrefix+key, fallback)
}

// envDuration has no go-utils counterpart, so it is built on Env: an
// unparseable value falls back rather than failing the boot, matching how
// EnvInt and EnvBool behave.
func envDuration(key string, fallback time.Duration) time.Duration {
	raw := goutils.Env(EnvPrefix+key, "")
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		logger.Warn("ignoring an unparseable duration",
			"variable", EnvPrefix+key, "value", raw, "using", fallback)
		return fallback
	}
	return d
}

// envList reads a comma-separated variable, dropping blanks so a trailing
// comma cannot turn into an empty allowed origin.
func envList(key string, fallback []string) []string {
	raw := goutils.Env(EnvPrefix+key, "")
	if raw == "" {
		return fallback
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}
