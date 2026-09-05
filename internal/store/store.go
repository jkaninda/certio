package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/jkaninda/certio/internal/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Store owns the database handle and exposes one repository per aggregate.
type Store struct {
	db *gorm.DB
	// driver names the backend, for the handful of operations that cannot be
	// expressed portably — the online backup, chiefly.
	driver string

	Authorities   *AuthorityRepo
	Certificates  *CertificateRepo
	Revocations   *RevocationRepo
	Users         *UserRepo
	Tokens        *TokenRepo
	Audit         *AuditRepo
	Jobs          *JobRepo
	Notifications *NotificationRepo
	Deliveries    *DeliveryRepo
	Deployments   *DeploymentRepo
	ACME          *ACMERepo
	Sessions      *SessionRepo
	Settings      *SettingRepo
	OAuth         *OAuthRepo
}

// Open connects to the configured database and wires up the repositories.
// It does not migrate; call Migrate explicitly so `certio migrate` and
// `certio serve` share one code path.
func Open(cfg *config.Config, log *slog.Logger) (*Store, error) {
	if err := cfg.EnsureDataDir(); err != nil {
		return nil, fmt.Errorf("store: create data directory: %w", err)
	}

	gormCfg := &gorm.Config{
		Logger:                 newGormLogger(log),
		SkipDefaultTransaction: true,
		NowFunc:                func() time.Time { return time.Now().UTC() },
	}

	db, err := gorm.Open(dialector(cfg), gormCfg)
	if err != nil {
		return nil, fmt.Errorf("store: open database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("store: get sql.DB: %w", err)
	}
	if cfg.Database.Driver == config.DriverPostgres {
		// Postgres handles concurrent writers, so the pool is sized for the
		// server rather than for a single-writer file.
		sqlDB.SetMaxOpenConns(25)
		sqlDB.SetMaxIdleConns(5)
	} else {
		// SQLite serialises writes; a large pool buys nothing and invites
		// "database is locked". One writer plus a few readers is the sweet spot.
		sqlDB.SetMaxOpenConns(4)
		sqlDB.SetMaxIdleConns(2)
	}
	sqlDB.SetConnMaxLifetime(time.Hour)

	st := New(db)
	st.driver = cfg.Database.Driver
	return st, nil
}

// dialector picks the GORM driver for the configured backend.
func dialector(cfg *config.Config) gorm.Dialector {
	if cfg.Database.Driver == config.DriverPostgres {
		return postgres.Open(cfg.DatabaseDSN())
	}
	return sqlite.Open(cfg.DatabaseDSN())
}

// New wraps an existing GORM handle. Tests use it with an in-memory database.
func New(db *gorm.DB) *Store {
	s := &Store{db: db, driver: config.DriverSQLite}
	s.Authorities = &AuthorityRepo{db: db}
	s.Certificates = &CertificateRepo{db: db}
	s.Revocations = &RevocationRepo{db: db}
	s.Users = &UserRepo{db: db}
	s.Tokens = &TokenRepo{db: db}
	s.Audit = &AuditRepo{db: db}
	s.Jobs = &JobRepo{db: db}
	s.Notifications = &NotificationRepo{db: db}
	s.Deliveries = &DeliveryRepo{db: db}
	s.Deployments = &DeploymentRepo{db: db}
	s.ACME = &ACMERepo{db: db}
	s.Sessions = &SessionRepo{db: db}
	s.Settings = &SettingRepo{db: db}
	s.OAuth = &OAuthRepo{db: db}
	return s
}

// DB exposes the underlying handle for migrations, transactions and health
// checks.
func (s *Store) DB() *gorm.DB { return s.db }

// Close releases the connection pool.
func (s *Store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Ping checks the database is reachable.
func (s *Store) Ping() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

// Transaction runs fn inside a database transaction, rolling back on error.
func (s *Store) Transaction(fn func(*Store) error) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		return fn(New(tx))
	})
}

// Backup writes a consistent copy of the database to dst while the instance
// keeps running.
//
// It uses SQLite's VACUUM INTO rather than copying the file: a running server
// owns the write-ahead log, and a tar of the .db plus its -wal and -shm
// sidecars can capture a torn write that only shows itself when the backup is
// restored — which is the one moment nobody wants to discover it. VACUUM INTO
// takes a read lock, walks the pages, and emits a single clean file with no
// sidecars and no free space.
//
// dst must not exist; SQLite refuses to overwrite, and so does this.
func (s *Store) Backup(dst string) error {
	if s.driver != config.DriverSQLite {
		return fmt.Errorf("store: online backup is only implemented for sqlite, not %q", s.driver)
	}
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("store: %s already exists; refusing to overwrite a backup", dst)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("store: check %s: %w", dst, err)
	}

	// The path is interpolated because VACUUM INTO takes a literal, not a
	// bound parameter. Quotes are doubled so a path containing one cannot
	// terminate the string early.
	quoted := "'" + strings.ReplaceAll(dst, "'", "''") + "'"
	if err := s.db.Exec("VACUUM INTO " + quoted).Error; err != nil {
		return fmt.Errorf("store: backup to %s: %w", dst, err)
	}
	return nil
}

// Migrate creates and updates every table.
func (s *Store) Migrate() error {
	models := []any{
		&Authority{}, &Certificate{}, &Revocation{},
		&User{}, &APIToken{}, &AuditLog{},
		&Notification{}, &Delivery{}, &DeploymentTarget{},
		&Job{}, &Setting{}, &RevokedSession{}, &OAuthProvider{},
		&ACMEAccount{}, &ACMEExternalAccount{}, &ACMEOrder{},
		&ACMEAuthorization{}, &ACMEChallenge{}, &ACMENonce{},
	}
	if err := s.db.AutoMigrate(models...); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// assignID fills a UUID primary key when the caller left it empty.
func assignID(id *string) error {
	if *id == "" {
		*id = uuid.NewString()
	}
	return nil
}

// translate maps GORM and driver errors onto the package's sentinel errors so
// handlers never import gorm.
func translate(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return ErrNotFound
	case isUniqueViolation(err):
		return ErrConflict
	default:
		return err
	}
}

// isUniqueViolation recognises a unique-constraint error across the drivers
// Certio may run on.
func isUniqueViolation(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "constraint failed: unique")
}

// gormLogger bridges GORM's logger interface onto the application's slog
// handler, so SQL diagnostics land in the same stream as everything else.
type gormLogger struct {
	log   *slog.Logger
	level logger.LogLevel
}

func newGormLogger(log *slog.Logger) logger.Interface {
	if log == nil {
		log = slog.Default()
	}
	level := logger.Warn
	if log.Enabled(context.Background(), slog.LevelDebug) {
		level = logger.Info
	}
	return &gormLogger{log: log, level: level}
}

// LogMode returns a copy of the logger set to the given level, which is how
// gorm asks for a quieter or louder logger without mutating this one.
func (g *gormLogger) LogMode(level logger.LogLevel) logger.Interface {
	clone := *g
	clone.level = level
	return &clone
}

// Info forwards a gorm informational message to the structured logger.
func (g *gormLogger) Info(_ context.Context, msg string, args ...any) {
	if g.level >= logger.Info {
		g.log.Info(fmt.Sprintf(msg, args...))
	}
}

// Warn forwards a gorm warning to the structured logger.
func (g *gormLogger) Warn(_ context.Context, msg string, args ...any) {
	if g.level >= logger.Warn {
		g.log.Warn(fmt.Sprintf(msg, args...))
	}
}

// Error forwards a gorm error to the structured logger.
func (g *gormLogger) Error(_ context.Context, msg string, args ...any) {
	if g.level >= logger.Error {
		g.log.Error(fmt.Sprintf(msg, args...))
	}
}

// Trace logs a completed statement: its SQL, row count and duration, and the
// error if it failed. gorm calls this for every query.
func (g *gormLogger) Trace(_ context.Context, begin time.Time, fc func() (string, int64), err error) {
	if g.level <= logger.Silent {
		return
	}
	elapsed := time.Since(begin)
	sql, rows := fc()

	switch {
	case err != nil && !errors.Is(err, gorm.ErrRecordNotFound):
		g.log.Error("query failed", "error", err, "sql", sql, "rows", rows, "elapsed", elapsed)
	case elapsed > 200*time.Millisecond:
		g.log.Warn("slow query", "sql", sql, "rows", rows, "elapsed", elapsed)
	case g.level >= logger.Info:
		g.log.Debug("query", "sql", sql, "rows", rows, "elapsed", elapsed)
	}
}
