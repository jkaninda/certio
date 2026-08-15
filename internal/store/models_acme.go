package store

import (
	"time"

	"gorm.io/gorm"
)

// ACME account statuses mirror RFC 8555 §7.1.6.
const (
	ACMEStatusPending     = "pending"
	ACMEStatusReady       = "ready"
	ACMEStatusProcessing  = "processing"
	ACMEStatusValid       = "valid"
	ACMEStatusInvalid     = "invalid"
	ACMEStatusDeactivated = "deactivated"
	ACMEStatusRevoked     = "revoked"
)

// ACMEAccount is a registered ACME client.
//
// The account is identified by its key, not by a name or a password: every
// later request is a JWS signed with it, and the thumbprint is what ties a
// challenge response back to the account that asked. Only the public key is
// stored, so a database that leaks cannot be used to impersonate a client.
type ACMEAccount struct {
	Model
	// KeyThumbprint is the RFC 7638 thumbprint, and the lookup key for a
	// returning client: RFC 8555 requires newAccount with a known key to
	// return the existing account rather than create a second one.
	KeyThumbprint string              `gorm:"size:64;uniqueIndex;not null" json:"key_thumbprint"`
	KeyJWK        string              `gorm:"column:key_jwk;type:text;not null" json:"-"`
	Contact       JSONField[[]string] `gorm:"column:contact;type:text" json:"contact"`
	Status        string              `gorm:"size:20;not null;index;default:valid" json:"status"`
	TermsAgreed   bool                `gorm:"not null;default:false" json:"terms_agreed"`

	// ExternalAccountID records which administrator-issued binding admitted
	// this account, so a compromised credential can be traced to everything
	// registered with it.
	ExternalAccountID string `gorm:"size:36;index" json:"external_account_id,omitempty"`

	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// TableName pins the table name.
func (ACMEAccount) TableName() string { return "acme_accounts" }

// BeforeCreate assigns the UUID primary key.
func (a *ACMEAccount) BeforeCreate(tx *gorm.DB) error { return assignID(&a.ID) }

// ACMEExternalAccount is a credential an administrator issues out of band so a
// client may register at all.
//
// Without external account binding, anything that can reach the directory can
// obtain a certificate for any name the CA will sign — which on an internal
// network is most of them. Let's Encrypt can be open because it validates
// against the public DNS; a private CA validating against internal names has
// no such backstop, so binding is on by default.
type ACMEExternalAccount struct {
	Model
	// KID is the identifier the client is given. It is not secret.
	//
	// The column name is pinned: GORM's namer turns "KID" into "k_id", which
	// then has to be spelled that way in every hand-written WHERE clause —
	// the same trap SANs falls into on the certificate model.
	KID         string `gorm:"column:kid;size:64;uniqueIndex;not null" json:"kid"`
	Description string `gorm:"size:255" json:"description,omitempty"`

	// HMACEncrypted is the shared secret, sealed with the master key. The
	// plaintext is shown to the administrator exactly once.
	HMACEncrypted []byte `gorm:"type:blob" json:"-"`
	HMACNonce     []byte `gorm:"type:blob" json:"-"`
	HMACSalt      []byte `gorm:"type:blob" json:"-"`

	// AllowedDomains restricts what accounts bound with this credential may
	// request. Empty means whatever the CA's own name constraints allow.
	AllowedDomains JSONField[[]string] `gorm:"column:allowed_domains;type:text" json:"allowed_domains"`

	Enabled    bool       `gorm:"not null" json:"enabled"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedBy  string     `gorm:"size:36" json:"created_by,omitempty"`
}

// TableName pins the table name.
func (ACMEExternalAccount) TableName() string { return "acme_external_accounts" }

// BeforeCreate assigns the UUID primary key.
func (e *ACMEExternalAccount) BeforeCreate(tx *gorm.DB) error { return assignID(&e.ID) }

// IsUsable reports whether the credential may still admit a registration.
func (e *ACMEExternalAccount) IsUsable() bool {
	if !e.Enabled {
		return false
	}
	return e.ExpiresAt == nil || e.ExpiresAt.After(time.Now())
}

// ACMEOrder is one request for a certificate.
type ACMEOrder struct {
	Model
	AccountID string      `gorm:"size:36;not null;index" json:"account_id"`
	Account   ACMEAccount `gorm:"foreignKey:AccountID" json:"-"`

	Status      string              `gorm:"size:20;not null;index" json:"status"`
	Identifiers JSONField[[]string] `gorm:"column:identifiers;type:text" json:"identifiers"`
	NotBefore   *time.Time          `json:"not_before,omitempty"`
	NotAfter    *time.Time          `json:"not_after,omitempty"`
	ExpiresAt   time.Time           `gorm:"index" json:"expires_at"`

	// CertificateID links to the issued certificate once finalize succeeds.
	CertificateID string `gorm:"size:36;index" json:"certificate_id,omitempty"`
	// Error holds the problem document a failed finalize produced, so a
	// polling client is told why rather than being left on "invalid".
	Error string `gorm:"type:text" json:"error,omitempty"`
}

// TableName pins the table name.
func (ACMEOrder) TableName() string { return "acme_orders" }

// BeforeCreate assigns the UUID primary key.
func (o *ACMEOrder) BeforeCreate(tx *gorm.DB) error { return assignID(&o.ID) }

// ACMEAuthorization is proof of control over one identifier.
type ACMEAuthorization struct {
	Model
	OrderID   string `gorm:"size:36;not null;index" json:"order_id"`
	AccountID string `gorm:"size:36;not null;index" json:"account_id"`

	Identifier string    `gorm:"size:255;not null;index" json:"identifier"`
	Wildcard   bool      `gorm:"not null;default:false" json:"wildcard"`
	Status     string    `gorm:"size:20;not null;index" json:"status"`
	ExpiresAt  time.Time `gorm:"index" json:"expires_at"`
}

// TableName pins the table name.
func (ACMEAuthorization) TableName() string { return "acme_authorizations" }

// BeforeCreate assigns the UUID primary key.
func (a *ACMEAuthorization) BeforeCreate(tx *gorm.DB) error { return assignID(&a.ID) }

// ACMEChallenge is one way of proving an authorization.
type ACMEChallenge struct {
	Model
	AuthorizationID string `gorm:"size:36;not null;index" json:"authorization_id"`

	Type   string `gorm:"size:20;not null" json:"type"`
	Token  string `gorm:"size:128;not null;index" json:"token"`
	Status string `gorm:"size:20;not null;index" json:"status"`

	ValidatedAt *time.Time `json:"validated_at,omitempty"`
	Error       string     `gorm:"type:text" json:"error,omitempty"`
	// Attempts bounds retries: a client that keeps poking a challenge against
	// a name it does not control should not be able to make Certio dial out
	// forever.
	Attempts int `gorm:"not null;default:0" json:"attempts"`
}

// TableName pins the table name.
func (ACMEChallenge) TableName() string { return "acme_challenges" }

// BeforeCreate assigns the UUID primary key.
func (c *ACMEChallenge) BeforeCreate(tx *gorm.DB) error { return assignID(&c.ID) }

// ACMENonce is an anti-replay value.
//
// Every ACME request carries one and it is spent on use, which is what stops a
// captured request being replayed. They live in the database rather than in
// memory so a restart does not invalidate every client's in-flight request,
// and so two instances behind one address agree on what has been spent.
type ACMENonce struct {
	Value     string    `gorm:"primaryKey;size:64" json:"value"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `gorm:"index" json:"expires_at"`
}

// TableName pins the table name.
func (ACMENonce) TableName() string { return "acme_nonces" }
