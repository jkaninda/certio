// Package store holds the persistence layer: GORM models, migrations and
// repositories. SQLite and PostgreSQL are both supported, and every query goes
// through a repository so a handler never has to know which is underneath.
package store

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jkaninda/certio/internal/pki"
	"gorm.io/gorm"
)

// Authority types.
const (
	AuthorityTypeRoot         = "root"
	AuthorityTypeIntermediate = "intermediate"
)

// Lifecycle status values shared by authorities and certificates.
const (
	StatusActive   = "active"
	StatusExpiring = "expiring"
	StatusExpired  = "expired"
	StatusRevoked  = "revoked"
	// StatusHeld is RFC 5280's certificateHold: on the CRL, but reversibly.
	// It is the state for "we think this key may have leaked, and we will know
	// by Monday" — the certificate stops being trusted now and can be brought
	// back without re-issuing it.
	StatusHeld = "held"
)

// User roles, from most to least privileged.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

// Audit actor types.
const (
	ActorUser   = "user"
	ActorToken  = "token"
	ActorSystem = "system"
)

// Job kinds run by the scheduler.
const (
	JobExpiryScan = "expiry_scan"
	JobAutoRenew  = "auto_renew"
	JobCRLRefresh = "crl_refresh"
	JobNotify     = "notify"
	// JobDeploy pushes renewed certificates to their deployment targets.
	JobDeploy = "deploy"
	// JobRetryNotify redelivers notifications whose first attempt failed.
	JobRetryNotify = "notify_retry"
	// JobPrune drops expired denylist entries and old job history.
	JobPrune = "prune"
)

// Job statuses.
const (
	JobPending   = "pending"
	JobRunning   = "running"
	JobSucceeded = "succeeded"
	JobFailed    = "failed"
)

// Notification channels.
const (
	ChannelWebhook  = "webhook"
	ChannelSMTP     = "smtp"
	ChannelSlack    = "slack"
	ChannelTelegram = "telegram"
)

// Model is the shared primary key and timestamp set. IDs are string UUIDs so
// they are safe to expose in URLs and stable across a backup/restore.
type Model struct {
	ID        string    `gorm:"primaryKey;size:36" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Authority is a certificate authority — a root or an intermediate.
type Authority struct {
	Model
	Name string `gorm:"size:191;not null" json:"name"`
	Slug string `gorm:"size:191;uniqueIndex;not null" json:"slug"`
	Type string `gorm:"size:20;not null;index" json:"type"`

	// ParentID links an intermediate to its issuer. Nil for a root.
	ParentID *string    `gorm:"size:36;index" json:"parent_id,omitempty"`
	Parent   *Authority `gorm:"foreignKey:ParentID" json:"-"`

	Subject JSONField[pki.Subject] `gorm:"type:text" json:"subject"`

	KeyAlgorithm string `gorm:"size:32;not null" json:"key_algorithm"`
	KeySize      int    `json:"key_size,omitempty"`
	KeyCurve     string `gorm:"size:16" json:"key_curve,omitempty"`

	SerialNumber string    `gorm:"size:64;index;not null" json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`

	PathLenConstraint *int `json:"path_len_constraint,omitempty"`

	// NameConstraints mirrors the RFC 5280 extension carried by the CA
	// certificate. It is stored as well as embedded so issuance can refuse an
	// out-of-scope name without re-parsing the PEM on every request.
	NameConstraints JSONField[pki.NameConstraints] `gorm:"column:name_constraints;type:text" json:"name_constraints"`

	CertPEM      string `gorm:"type:text;not null" json:"-"`
	KeyEncrypted []byte `gorm:"type:blob" json:"-"`
	KeyNonce     []byte `gorm:"type:blob" json:"-"`
	KeySalt      []byte `gorm:"type:blob" json:"-"`
	// PassphraseProtected means the key needs an operator-supplied passphrase
	// at signing time. The passphrase itself is never stored.
	PassphraseProtected bool `json:"passphrase_protected"`

	CRLURL        string     `gorm:"size:255" json:"crl_url,omitempty"`
	OCSPURL       string     `gorm:"size:255" json:"ocsp_url,omitempty"`
	CRLNumber     int64      `gorm:"default:0" json:"crl_number"`
	CRLPEM        string     `gorm:"type:text" json:"-"`
	NextCRLUpdate *time.Time `json:"next_crl_update,omitempty"`

	Status            string `gorm:"size:20;not null;index;default:active" json:"status"`
	FingerprintSHA256 string `gorm:"size:64;index" json:"fingerprint_sha256"`

	Description string `gorm:"type:text" json:"description,omitempty"`
	CreatedBy   string `gorm:"size:36" json:"created_by,omitempty"`

	Certificates []Certificate `gorm:"foreignKey:AuthorityID" json:"-"`
}

// TableName pins the table name so a model rename cannot silently migrate data.
func (Authority) TableName() string { return "authorities" }

// BeforeCreate assigns the UUID primary key.
func (a *Authority) BeforeCreate(tx *gorm.DB) error { return assignID(&a.ID) }

// KeySpec reconstructs the pki.KeySpec for this authority's key.
func (a *Authority) KeySpec() pki.KeySpec {
	return pki.KeySpec{Algorithm: a.KeyAlgorithm, Size: a.KeySize, Curve: a.KeyCurve}
}

// Certificate is an issued end-entity certificate.
type Certificate struct {
	Model
	// AuthorityID is the first column of the (ca, serial) unique index, so a
	// serial only has to be unique within its own CA — the same guarantee
	// openssl's .srl file gives, enforced by the database instead.
	AuthorityID string    `gorm:"size:36;not null;index;index:idx_cert_ca_serial,unique,priority:1" json:"ca_id"`
	Authority   Authority `gorm:"foreignKey:AuthorityID" json:"-"`

	CommonName string                 `gorm:"size:191;not null;index" json:"common_name"`
	Subject    JSONField[pki.Subject] `gorm:"type:text" json:"subject"`
	Profile    string                 `gorm:"size:32;not null;index" json:"profile"`

	KeyAlgorithm string `gorm:"size:32;not null" json:"key_algorithm"`
	KeySize      int    `json:"key_size,omitempty"`
	KeyCurve     string `gorm:"size:16" json:"key_curve,omitempty"`

	SerialNumber string `gorm:"size:64;not null;index;index:idx_cert_ca_serial,unique,priority:2" json:"serial_number"`

	// The column names are pinned: GORM's default namer turns "SANs" into
	// "sa_ns", which then leaks into hand-written WHERE clauses.
	SANs        JSONField[pki.SANSet] `gorm:"column:sans;type:text" json:"sans"`
	KeyUsage    JSONField[[]string]   `gorm:"column:key_usage;type:text" json:"key_usage"`
	ExtKeyUsage JSONField[[]string]   `gorm:"column:ext_key_usage;type:text" json:"ext_key_usage"`

	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `gorm:"index" json:"not_after"`
	ValidityDays int       `json:"validity_days"`

	CertPEM      string `gorm:"type:text;not null" json:"-"`
	KeyEncrypted []byte `gorm:"type:blob" json:"-"`
	KeyNonce     []byte `gorm:"type:blob" json:"-"`
	KeySalt      []byte `gorm:"type:blob" json:"-"`
	// CSRPEM is set only for the BYO-CSR flow, where Certio never held the key.
	CSRPEM string `gorm:"column:csr_pem;type:text" json:"-"`

	FingerprintSHA256 string `gorm:"size:64;index" json:"fingerprint_sha256"`
	Status            string `gorm:"size:20;not null;index;default:active" json:"status"`

	AutoRenew       bool `gorm:"default:false;index" json:"auto_renew"`
	RenewBeforeDays int  `gorm:"default:30" json:"renew_before_days"`
	// RenewedFromID points at the certificate this one replaced. Renewal
	// creates a new row so history and rollback survive.
	RenewedFromID *string `gorm:"size:36;index" json:"renewed_from_id,omitempty"`

	// KeyDownloadCount backs the once|always|never download policy.
	KeyDownloadCount int        `gorm:"default:0" json:"key_download_count"`
	LastDownloadedAt *time.Time `json:"last_downloaded_at,omitempty"`

	Labels JSONField[map[string]string] `gorm:"type:text" json:"labels"`
	Notes  string                       `gorm:"type:text" json:"notes,omitempty"`

	CreatedBy string `gorm:"size:36" json:"created_by,omitempty"`
}

// TableName pins the table name.
func (Certificate) TableName() string { return "certificates" }

// BeforeCreate assigns the UUID primary key.
func (c *Certificate) BeforeCreate(tx *gorm.DB) error { return assignID(&c.ID) }

// HasPrivateKey reports whether Certio holds the key for this certificate.
// False for anything issued through the BYO-CSR flow.
func (c *Certificate) HasPrivateKey() bool { return len(c.KeyEncrypted) > 0 }

// DaysRemaining is the whole days left before expiry, negative once expired.
func (c *Certificate) DaysRemaining() int {
	return int(time.Until(c.NotAfter).Hours() / 24)
}

// DeriveStatus recomputes the lifecycle status from the clock. A revoked
// certificate stays revoked regardless of its dates.
//
// Expiry is decided by comparing instants, not by rounding DaysRemaining:
// a certificate that lapsed twenty minutes ago has zero days remaining but is
// unambiguously expired.
func (c *Certificate) DeriveStatus(warnDays int) string {
	if c.Status == StatusRevoked {
		return StatusRevoked
	}
	// A held certificate stays held until somebody decides. Letting the clock
	// reclassify it as merely "expiring" would hide the fact that it is
	// currently on a CRL.
	if c.Status == StatusHeld {
		return StatusHeld
	}
	now := time.Now()
	switch {
	case now.After(c.NotAfter):
		return StatusExpired
	case now.AddDate(0, 0, warnDays).After(c.NotAfter):
		return StatusExpiring
	default:
		return StatusActive
	}
}

// Revocation records a revoked certificate and the reason, and is the source
// of truth for CRL generation.
type Revocation struct {
	Model
	CertificateID string      `gorm:"size:36;not null;uniqueIndex" json:"certificate_id"`
	Certificate   Certificate `gorm:"foreignKey:CertificateID" json:"-"`
	AuthorityID   string      `gorm:"size:36;not null;index" json:"ca_id"`
	SerialNumber  string      `gorm:"size:64;not null;index" json:"serial_number"`
	ReasonCode    int         `gorm:"not null" json:"reason_code"`
	Reason        string      `gorm:"size:40" json:"reason"`
	RevokedAt     time.Time   `gorm:"not null" json:"revoked_at"`
	RevokedBy     string      `gorm:"size:36" json:"revoked_by,omitempty"`
}

// TableName pins the table name.
func (Revocation) TableName() string { return "revocations" }

// BeforeCreate assigns the UUID primary key.
func (r *Revocation) BeforeCreate(tx *gorm.DB) error { return assignID(&r.ID) }

// User is a dashboard account.
type User struct {
	Model
	Email        string     `gorm:"size:191;uniqueIndex;not null" json:"email"`
	Name         string     `gorm:"size:191" json:"name"`
	PasswordHash string     `gorm:"size:255;not null" json:"-"`
	Role         string     `gorm:"size:20;not null;default:viewer" json:"role"`
	Status       string     `gorm:"size:20;not null;default:active" json:"status"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`

	// TOTPSecret* hold the second factor's shared secret, sealed with the
	// master key like every other secret Certio stores. It is written when
	// enrolment starts and only becomes usable once TOTPEnabled flips, so an
	// abandoned setup can never lock an account out.
	//
	// Unlike AuditLog.Success this one does carry a default: false is the
	// right value for both a new row and an existing one, and SQLite refuses
	// to add a NOT NULL column to a populated table without it.
	TOTPEnabled         bool   `gorm:"not null;default:false" json:"totp_enabled"`
	TOTPSecretEncrypted []byte `gorm:"type:blob" json:"-"`
	TOTPSecretNonce     []byte `gorm:"type:blob" json:"-"`
	TOTPSecretSalt      []byte `gorm:"type:blob" json:"-"`
	// TOTPEnabledAt is when the enrolment was confirmed, not when it started.
	TOTPEnabledAt *time.Time `json:"totp_enabled_at,omitempty"`
	// TOTPLastStep is the newest time step already spent. A code is valid for
	// up to three steps once drift is allowed, and without this an attacker
	// who observes one — through a phishing proxy, or over someone's shoulder
	// — could replay it for another minute.
	TOTPLastStep int64 `gorm:"default:0" json:"-"`
	// RecoveryCodes holds the SHA-256 digests of the unused single-use codes.
	// A code is removed from the list the moment it is spent.
	RecoveryCodes JSONField[[]string] `gorm:"column:recovery_codes;type:text" json:"-"`
}

// TableName pins the table name.
func (User) TableName() string { return "users" }

// BeforeCreate assigns the UUID primary key.
func (u *User) BeforeCreate(tx *gorm.DB) error { return assignID(&u.ID) }

// IsActive reports whether the account may sign in.
func (u *User) IsActive() bool { return u.Status == StatusActive }

// HasTwoFactor reports whether the account must present a second factor to
// sign in. A pending enrolment does not count.
func (u *User) HasTwoFactor() bool { return u.TOTPEnabled && len(u.TOTPSecretEncrypted) > 0 }

// TOTPEnrollmentPending reports whether a secret has been generated but never
// confirmed with a code.
func (u *User) TOTPEnrollmentPending() bool { return !u.TOTPEnabled && len(u.TOTPSecretEncrypted) > 0 }

// RecoveryCodesRemaining is how many single-use codes are still unspent.
func (u *User) RecoveryCodesRemaining() int { return len(u.RecoveryCodes.Data) }

// APIToken is a long-lived bearer credential for automation.
type APIToken struct {
	Model
	UserID string `gorm:"size:36;not null;index" json:"user_id"`
	User   User   `gorm:"foreignKey:UserID" json:"-"`

	Name string `gorm:"size:191;not null" json:"name"`
	// TokenHash is a SHA-256 digest; the plaintext is shown exactly once.
	TokenHash string              `gorm:"size:64;uniqueIndex;not null" json:"-"`
	Prefix    string              `gorm:"size:16" json:"prefix"`
	Scopes    JSONField[[]string] `gorm:"type:text" json:"scopes"`

	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// TableName pins the table name.
func (APIToken) TableName() string { return "api_tokens" }

// BeforeCreate assigns the UUID primary key.
func (t *APIToken) BeforeCreate(tx *gorm.DB) error { return assignID(&t.ID) }

// IsUsable reports whether the token may still authenticate a request.
func (t *APIToken) IsUsable() bool {
	if t.RevokedAt != nil {
		return false
	}
	return t.ExpiresAt == nil || t.ExpiresAt.After(time.Now())
}

// RevokedSession is a session that must no longer authenticate, keyed by the
// session id both tokens of a pair carry.
//
// JWTs are self-contained, which is what makes them cheap and what makes
// "sign out" meaningless without a list like this: the token stays valid in
// whatever copied it until it expires. Keying on the session rather than on
// each token means one row kills the access token and the refresh token that
// would mint its replacement.
//
// Rows are pruned once ExpiresAt passes, because a denied token that has also
// expired is denied twice over.
type RevokedSession struct {
	SessionID string    `gorm:"primaryKey;size:36" json:"session_id"`
	UserID    string    `gorm:"size:36;index" json:"user_id"`
	Reason    string    `gorm:"size:64" json:"reason"`
	ExpiresAt time.Time `gorm:"index" json:"expires_at"`
	RevokedAt time.Time `json:"revoked_at"`
}

// TableName pins the table name.
func (RevokedSession) TableName() string { return "revoked_sessions" }

// AuditLog is an append-only record of every mutation. The API exposes no
// update or delete route for this table.
type AuditLog struct {
	ID        string    `gorm:"primaryKey;size:36" json:"id"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`

	ActorType string `gorm:"size:20;not null;index" json:"actor_type"`
	ActorID   string `gorm:"size:36;index" json:"actor_id,omitempty"`
	ActorName string `gorm:"size:191" json:"actor_name,omitempty"`

	Action       string `gorm:"size:64;not null;index" json:"action"`
	ResourceType string `gorm:"size:32;index" json:"resource_type,omitempty"`
	ResourceID   string `gorm:"size:36;index" json:"resource_id,omitempty"`
	ResourceName string `gorm:"size:191" json:"resource_name,omitempty"`

	Metadata  JSONField[map[string]any] `gorm:"type:text" json:"metadata,omitempty"`
	IP        string                    `gorm:"size:45" json:"ip,omitempty"`
	UserAgent string                    `gorm:"size:255" json:"user_agent,omitempty"`
	// Success carries no column default on purpose. GORM skips zero-valued
	// fields on insert, so `default:true` would silently rewrite every failed
	// entry as a success — exactly the records that matter most.
	Success bool   `gorm:"not null" json:"success"`
	Error   string `gorm:"type:text" json:"error,omitempty"`
}

// TableName pins the table name.
func (AuditLog) TableName() string { return "audit_logs" }

// BeforeCreate assigns the UUID primary key.
func (a *AuditLog) BeforeCreate(tx *gorm.DB) error { return assignID(&a.ID) }

// Notification is a configured delivery channel for expiry and renewal events.
type Notification struct {
	Model
	Name    string `gorm:"size:191;not null" json:"name"`
	Channel string `gorm:"size:20;not null" json:"channel"`

	// ConfigEncrypted holds channel settings — webhook URLs, SMTP passwords —
	// sealed with the master key.
	ConfigEncrypted []byte `gorm:"type:blob" json:"-"`
	ConfigNonce     []byte `gorm:"type:blob" json:"-"`
	ConfigSalt      []byte `gorm:"type:blob" json:"-"`

	Events JSONField[[]string] `gorm:"column:events;type:text" json:"events"`
	// No column default, for the same reason as AuditLog.Success: it would
	// make disabling a channel impossible.
	Enabled bool `gorm:"not null" json:"enabled"`

	LastSentAt *time.Time `json:"last_sent_at,omitempty"`
	LastError  string     `gorm:"type:text" json:"last_error,omitempty"`
}

// TableName pins the table name.
func (Notification) TableName() string { return "notifications" }

// Delivery statuses.
const (
	DeliveryPending   = "pending"
	DeliveryDelivered = "delivered"
	DeliveryFailed    = "failed"
)

// Delivery is one attempt to push an event through one channel, kept until it
// succeeds or gives up.
//
// Without it a notification is fire-once: an expiry warning lost to a
// thirty-second outage at the receiving end is lost for good, and the whole
// point of the channel is that somebody hears about the certificate. The row
// carries the event so a retry sends the same thing rather than a re-derived
// approximation of it.
type Delivery struct {
	Model
	NotificationID string       `gorm:"size:36;not null;index" json:"notification_id"`
	Notification   Notification `gorm:"foreignKey:NotificationID" json:"-"`

	Event   string                    `gorm:"size:64;not null;index" json:"event"`
	Payload JSONField[map[string]any] `gorm:"type:text" json:"payload"`

	Status    string `gorm:"size:20;not null;index;default:pending" json:"status"`
	Attempts  int    `gorm:"not null;default:0" json:"attempts"`
	LastError string `gorm:"type:text" json:"last_error,omitempty"`

	// NextAttemptAt is when the retry pass should pick this up. Indexed
	// together with status because that pair is the whole query.
	NextAttemptAt time.Time  `gorm:"index" json:"next_attempt_at"`
	DeliveredAt   *time.Time `json:"delivered_at,omitempty"`
}

// TableName pins the table name.
func (Delivery) TableName() string { return "deliveries" }

// BeforeCreate assigns the UUID primary key.
func (d *Delivery) BeforeCreate(tx *gorm.DB) error { return assignID(&d.ID) }

// BeforeCreate assigns the UUID primary key.
func (n *Notification) BeforeCreate(tx *gorm.DB) error { return assignID(&n.ID) }

// DeploymentTarget is somewhere a renewed certificate has to be written for
// the renewal to mean anything.
//
// Certificates are selected by label rather than by id, because renewal
// creates a *new* row: a target bound to a certificate id would deploy once
// and then quietly go stale at exactly the moment it was needed. Labels
// survive renewal, so `env=prod, app=api` keeps pointing at whatever is
// currently the certificate for that thing.
type DeploymentTarget struct {
	Model
	Name string `gorm:"size:191;not null" json:"name"`
	Kind string `gorm:"size:20;not null;index" json:"kind"`

	// ConfigEncrypted holds the target's settings — SSH keys, cluster tokens —
	// sealed with the master key.
	ConfigEncrypted []byte `gorm:"type:blob" json:"-"`
	ConfigNonce     []byte `gorm:"type:blob" json:"-"`
	ConfigSalt      []byte `gorm:"type:blob" json:"-"`

	// Selector matches certificates by label. Empty matches nothing: a target
	// that silently deployed every certificate in the instance would be a
	// spectacular way to overwrite the wrong key.
	Selector JSONField[map[string]string] `gorm:"column:selector;type:text" json:"selector"`
	// CommonName narrows further, for the common case of one certificate.
	CommonName string `gorm:"size:191;index" json:"common_name,omitempty"`

	Enabled bool `gorm:"not null" json:"enabled"`

	LastRunAt   *time.Time `json:"last_run_at,omitempty"`
	LastSuccess *time.Time `json:"last_success_at,omitempty"`
	LastError   string     `gorm:"type:text" json:"last_error,omitempty"`
	// LastSerial is the serial most recently pushed, so a repeat pass can skip
	// a target that already has the current certificate.
	LastSerial string `gorm:"size:64" json:"last_serial,omitempty"`
}

// TableName pins the table name.
func (DeploymentTarget) TableName() string { return "deployment_targets" }

// BeforeCreate assigns the UUID primary key.
func (d *DeploymentTarget) BeforeCreate(tx *gorm.DB) error { return assignID(&d.ID) }

// Matches reports whether a certificate is one this target deploys.
func (d *DeploymentTarget) Matches(cert *Certificate) bool {
	if cert == nil {
		return false
	}
	if d.CommonName != "" && !strings.EqualFold(d.CommonName, cert.CommonName) {
		return false
	}
	selector := d.Selector.Data
	if len(selector) == 0 {
		// With no labels, a common name is the only thing making this target
		// specific — and without either, it matches nothing on purpose.
		return d.CommonName != ""
	}
	labels := cert.Labels.Data
	for key, want := range selector {
		if labels[key] != want {
			return false
		}
	}
	return true
}

// Job is one run of a scheduled background task, kept for history.
type Job struct {
	Model
	Kind    string                    `gorm:"size:32;not null;index" json:"kind"`
	Status  string                    `gorm:"size:20;not null;index" json:"status"`
	Payload JSONField[map[string]any] `gorm:"type:text" json:"payload,omitempty"`
	Result  JSONField[map[string]any] `gorm:"type:text" json:"result,omitempty"`
	Error   string                    `gorm:"type:text" json:"error,omitempty"`

	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// TableName pins the table name.
func (Job) TableName() string { return "jobs" }

// BeforeCreate assigns the UUID primary key.
func (j *Job) BeforeCreate(tx *gorm.DB) error { return assignID(&j.ID) }

// Duration is how long the job ran, zero while still running.
func (j *Job) Duration() time.Duration {
	if j.StartedAt == nil || j.FinishedAt == nil {
		return 0
	}
	return j.FinishedAt.Sub(*j.StartedAt)
}

// Setting is a key/value row for instance defaults. Values are sealed so a
// setting can hold a secret without needing its own table.
type Setting struct {
	Key            string    `gorm:"primaryKey;size:64" json:"key"`
	Value          string    `gorm:"type:text" json:"value"`
	ValueEncrypted []byte    `gorm:"type:blob" json:"-"`
	ValueNonce     []byte    `gorm:"type:blob" json:"-"`
	ValueSalt      []byte    `gorm:"type:blob" json:"-"`
	Secret         bool      `gorm:"default:false" json:"secret"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// TableName pins the table name.
func (Setting) TableName() string { return "settings" }

// JSONField stores any Go value as a JSON text column. GORM has no portable
// JSON type across SQLite and Postgres, and hand-rolled marshalling at every
// call site is where bugs hide.
type JSONField[T any] struct {
	Data T
}

// JSON wraps a value in a JSONField.
func JSON[T any](v T) JSONField[T] { return JSONField[T]{Data: v} }

// Value implements driver.Valuer.
func (j JSONField[T]) Value() (driver.Value, error) {
	b, err := json.Marshal(j.Data)
	if err != nil {
		return nil, fmt.Errorf("store: marshal JSON column: %w", err)
	}
	return string(b), nil
}

// Scan implements sql.Scanner.
func (j *JSONField[T]) Scan(src any) error {
	if src == nil {
		var zero T
		j.Data = zero
		return nil
	}
	var raw []byte
	switch v := src.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return fmt.Errorf("store: cannot scan %T into a JSON column", src)
	}
	if len(raw) == 0 {
		var zero T
		j.Data = zero
		return nil
	}
	return json.Unmarshal(raw, &j.Data)
}

// MarshalJSON emits the wrapped value directly, so API responses do not show
// the wrapper.
func (j JSONField[T]) MarshalJSON() ([]byte, error) { return json.Marshal(j.Data) }

// UnmarshalJSON reads into the wrapped value.
func (j *JSONField[T]) UnmarshalJSON(b []byte) error { return json.Unmarshal(b, &j.Data) }

// ErrNotFound is returned by repositories when a lookup misses. Handlers map
// it to 404 without importing gorm.
var ErrNotFound = errors.New("store: record not found")

// ErrConflict is returned when a uniqueness constraint would be violated.
var ErrConflict = errors.New("store: record already exists")

// ErrInUse is returned when deleting a record would orphan dependent rows.
var ErrInUse = errors.New("store: record is still referenced")
