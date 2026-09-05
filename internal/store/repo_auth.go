package store

import (
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UserRepo persists dashboard accounts.
type UserRepo struct{ db *gorm.DB }

// Create inserts a new user.
func (r *UserRepo) Create(u *User) error {
	u.Email = strings.ToLower(strings.TrimSpace(u.Email))
	return translate(r.db.Create(u).Error)
}

// Update saves every field of an existing user.
func (r *UserRepo) Update(u *User) error {
	return translate(r.db.Save(u).Error)
}

// Get loads a user by ID.
func (r *UserRepo) Get(id string) (*User, error) {
	var u User
	if err := r.db.First(&u, "id = ?", id).Error; err != nil {
		return nil, translate(err)
	}
	return &u, nil
}

// GetByEmail loads a user by email, case-insensitively.
func (r *UserRepo) GetByEmail(email string) (*User, error) {
	var u User
	err := r.db.First(&u, "email = ?", strings.ToLower(strings.TrimSpace(email))).Error
	if err != nil {
		return nil, translate(err)
	}
	return &u, nil
}

// GetByOAuth loads the account a federated identity belongs to, keyed on the
// provider's own subject rather than on the email it happens to carry today.
func (r *UserRepo) GetByOAuth(provider, subject string) (*User, error) {
	if provider == "" || subject == "" {
		return nil, ErrNotFound
	}
	var u User
	err := r.db.First(&u, "oauth_provider = ? AND oauth_subject = ?", provider, subject).Error
	if err != nil {
		return nil, translate(err)
	}
	return &u, nil
}

// List returns a page of users.
func (r *UserRepo) List(p Pagination) (Page[User], error) {
	p.Normalize()
	q := r.db.Model(&User{})

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return Page[User]{}, translate(err)
	}

	var items []User
	if err := q.Order("created_at ASC").Limit(p.Limit).Offset(p.Offset()).Find(&items).Error; err != nil {
		return Page[User]{}, translate(err)
	}
	return newPage(items, total, p), nil
}

// Delete removes a user and every token they own.
func (r *UserRepo) Delete(id string) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", id).Delete(&APIToken{}).Error; err != nil {
			return err
		}
		res := tx.Delete(&User{}, "id = ?", id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// Count returns the total number of users, used to decide whether the instance
// still needs bootstrapping.
func (r *UserRepo) Count() (int64, error) {
	var n int64
	err := r.db.Model(&User{}).Count(&n).Error
	return n, translate(err)
}

// CountAdmins returns how many active admins exist, so the last one cannot be
// deleted or demoted.
func (r *UserRepo) CountAdmins() (int64, error) {
	var n int64
	err := r.db.Model(&User{}).Where("role = ? AND status = ?", RoleAdmin, StatusActive).Count(&n).Error
	return n, translate(err)
}

// TouchLogin records a successful sign-in.
func (r *UserRepo) TouchLogin(id string) error {
	now := time.Now().UTC()
	return translate(r.db.Model(&User{}).Where("id = ?", id).Update("last_login_at", now).Error)
}

// OAuthRepo persists the single external identity provider. Every method
// works on "the" provider rather than on an id: the table holds at most one
// row by construction, and an id in the API would only invite a second.
type OAuthRepo struct{ db *gorm.DB }

// Get loads the configured provider, returning ErrNotFound when sign-in has
// not been federated.
func (r *OAuthRepo) Get() (*OAuthProvider, error) {
	var p OAuthProvider
	if err := r.db.Order("created_at ASC").First(&p).Error; err != nil {
		return nil, translate(err)
	}
	return &p, nil
}

// Save upserts the provider onto the one row, adopting the existing row's id
// so a re-save replaces the configuration rather than accumulating providers.
func (r *OAuthRepo) Save(p *OAuthProvider) error {
	existing, err := r.Get()
	switch {
	case errors.Is(err, ErrNotFound):
		return translate(r.db.Create(p).Error)
	case err != nil:
		return err
	}
	p.ID = existing.ID
	p.CreatedAt = existing.CreatedAt
	return translate(r.db.Save(p).Error)
}

// Delete removes the provider, returning federated sign-in to off.
func (r *OAuthRepo) Delete() error {
	return translate(r.db.Where("1 = 1").Delete(&OAuthProvider{}).Error)
}

// TokenRepo persists API tokens.
type TokenRepo struct{ db *gorm.DB }

// Create inserts a new token.
func (r *TokenRepo) Create(t *APIToken) error {
	return translate(r.db.Create(t).Error)
}

// Get loads a token by ID.
func (r *TokenRepo) Get(id string) (*APIToken, error) {
	var t APIToken
	if err := r.db.First(&t, "id = ?", id).Error; err != nil {
		return nil, translate(err)
	}
	return &t, nil
}

// GetByHash looks a token up by its stored digest — the authentication path.
func (r *TokenRepo) GetByHash(hash string) (*APIToken, error) {
	var t APIToken
	if err := r.db.First(&t, "token_hash = ?", hash).Error; err != nil {
		return nil, translate(err)
	}
	return &t, nil
}

// ByUser lists a user's tokens.
func (r *TokenRepo) ByUser(userID string) ([]APIToken, error) {
	var items []APIToken
	if err := r.db.Where("user_id = ?", userID).Order("created_at DESC").Find(&items).Error; err != nil {
		return nil, translate(err)
	}
	return items, nil
}

// All lists every token, for the admin view.
func (r *TokenRepo) All() ([]APIToken, error) {
	var items []APIToken
	if err := r.db.Order("created_at DESC").Find(&items).Error; err != nil {
		return nil, translate(err)
	}
	return items, nil
}

// TouchUsed records that a token authenticated a request.
func (r *TokenRepo) TouchUsed(id string) error {
	now := time.Now().UTC()
	return translate(r.db.Model(&APIToken{}).Where("id = ?", id).Update("last_used_at", now).Error)
}

// Revoke marks a token unusable without deleting its audit trail.
func (r *TokenRepo) Revoke(id string) error {
	now := time.Now().UTC()
	res := r.db.Model(&APIToken{}).Where("id = ?", id).Update("revoked_at", now)
	if res.Error != nil {
		return translate(res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a token outright.
func (r *TokenRepo) Delete(id string) error {
	res := r.db.Delete(&APIToken{}, "id = ?", id)
	if res.Error != nil {
		return translate(res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// DeliveryRepo persists notification delivery attempts.
type DeliveryRepo struct{ db *gorm.DB }

// Create records an attempt.
func (r *DeliveryRepo) Create(d *Delivery) error { return translate(r.db.Create(d).Error) }

// Update saves an attempt.
func (r *DeliveryRepo) Update(d *Delivery) error { return translate(r.db.Save(d).Error) }

// Due returns the pending deliveries whose backoff has elapsed, oldest first
// so a backlog drains in the order it accumulated.
func (r *DeliveryRepo) Due(now time.Time, limit int) ([]Delivery, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []Delivery
	err := r.db.Preload("Notification").
		Where("status = ?", DeliveryPending).
		Where("next_attempt_at <= ?", now.UTC()).
		Order("created_at ASC").
		Limit(limit).
		Find(&out).Error
	return out, translate(err)
}

// ByNotification returns the recent attempts for one channel, newest first.
func (r *DeliveryRepo) ByNotification(notificationID string, limit int) ([]Delivery, error) {
	if limit <= 0 {
		limit = 20
	}
	var out []Delivery
	err := r.db.Where("notification_id = ?", notificationID).
		Order("created_at DESC").Limit(limit).Find(&out).Error
	return out, translate(err)
}

// PruneDelivered drops successful attempts older than the cutoff. Failures are
// kept: a channel that gave up is a thing somebody still needs to see.
func (r *DeliveryRepo) PruneDelivered(before time.Time) (int64, error) {
	res := r.db.Where("status = ?", DeliveryDelivered).
		Where("created_at < ?", before.UTC()).
		Delete(&Delivery{})
	return res.RowsAffected, translate(res.Error)
}

// DeploymentRepo persists deployment targets.
type DeploymentRepo struct{ db *gorm.DB }

// Create inserts a target.
func (r *DeploymentRepo) Create(d *DeploymentTarget) error { return translate(r.db.Create(d).Error) }

// Update saves a target.
func (r *DeploymentRepo) Update(d *DeploymentTarget) error { return translate(r.db.Save(d).Error) }

// Get loads a target by ID.
func (r *DeploymentRepo) Get(id string) (*DeploymentTarget, error) {
	var d DeploymentTarget
	if err := r.db.First(&d, "id = ?", id).Error; err != nil {
		return nil, translate(err)
	}
	return &d, nil
}

// All returns every target, newest first.
func (r *DeploymentRepo) All() ([]DeploymentTarget, error) {
	var items []DeploymentTarget
	err := r.db.Order("created_at DESC").Find(&items).Error
	return items, translate(err)
}

// Enabled returns the targets a deployment pass should consider.
func (r *DeploymentRepo) Enabled() ([]DeploymentTarget, error) {
	var items []DeploymentTarget
	err := r.db.Where("enabled = ?", true).Order("created_at ASC").Find(&items).Error
	return items, translate(err)
}

// Delete removes a target.
func (r *DeploymentRepo) Delete(id string) error {
	res := r.db.Delete(&DeploymentTarget{}, "id = ?", id)
	if res.Error != nil {
		return translate(res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// SessionRepo holds the denylist that makes signing out mean something.
type SessionRepo struct{ db *gorm.DB }

// Revoke denies a session. Revoking twice is not an error: two browser tabs
// signing out at once is normal.
func (r *SessionRepo) Revoke(sessionID, userID, reason string, expiresAt time.Time) error {
	row := &RevokedSession{
		SessionID: sessionID, UserID: userID, Reason: reason,
		ExpiresAt: expiresAt.UTC(), RevokedAt: time.Now().UTC(),
	}
	err := r.db.Clauses(clause.OnConflict{DoNothing: true}).Create(row).Error
	return translate(err)
}

// RevokeAllForUser denies every session a user currently holds, without
// needing to know their ids: a sentinel row keyed on the user is checked
// alongside the per-session ones.
//
// This is what a password change and a two-factor reset need — the sessions an
// attacker may already hold are exactly the ones the change is meant to end.
func (r *SessionRepo) RevokeAllForUser(userID, reason string, until time.Time) error {
	return r.Revoke(allSessionsKey(userID), userID, reason, until)
}

// IsRevoked reports whether a session may still authenticate.
func (r *SessionRepo) IsRevoked(sessionID, userID string) (bool, error) {
	keys := []string{sessionID}
	if userID != "" {
		keys = append(keys, allSessionsKey(userID))
	}
	var n int64
	err := r.db.Model(&RevokedSession{}).
		Where("session_id IN ?", keys).
		Where("expires_at > ?", time.Now().UTC()).
		Count(&n).Error
	if err != nil {
		return false, translate(err)
	}
	return n > 0, nil
}

// Prune drops entries whose tokens have expired anyway.
func (r *SessionRepo) Prune(before time.Time) (int64, error) {
	res := r.db.Where("expires_at < ?", before.UTC()).Delete(&RevokedSession{})
	return res.RowsAffected, translate(res.Error)
}

// allSessionsKey is the sentinel session id standing for "everything this user
// holds". It is prefixed so it can never collide with a real UUID.
func allSessionsKey(userID string) string { return "user:" + userID }

// AuditRepo appends to the audit log. It deliberately exposes no update or
// delete method: the log is append-only by construction, not by convention.
type AuditRepo struct{ db *gorm.DB }

// AuditFilter narrows an audit listing.
type AuditFilter struct {
	ActorID      string
	Action       string
	ResourceType string
	ResourceID   string
	Since        *time.Time
	Until        *time.Time
	Query        string
}

// Append writes an audit entry.
func (r *AuditRepo) Append(entry *AuditLog) error {
	return translate(r.db.Create(entry).Error)
}

// List returns a filtered page of audit entries, newest first.
func (r *AuditRepo) List(f AuditFilter, p Pagination) (Page[AuditLog], error) {
	p.Normalize()
	q := r.db.Model(&AuditLog{})

	if f.ActorID != "" {
		q = q.Where("actor_id = ?", f.ActorID)
	}
	if f.Action != "" {
		q = q.Where("action = ?", f.Action)
	}
	if f.ResourceType != "" {
		q = q.Where("resource_type = ?", f.ResourceType)
	}
	if f.ResourceID != "" {
		q = q.Where("resource_id = ?", f.ResourceID)
	}
	if f.Since != nil {
		q = q.Where("created_at >= ?", *f.Since)
	}
	if f.Until != nil {
		q = q.Where("created_at <= ?", *f.Until)
	}
	if f.Query != "" {
		like := "%" + strings.ToLower(f.Query) + "%"
		q = q.Where("LOWER(action) LIKE ? OR LOWER(resource_name) LIKE ? OR LOWER(actor_name) LIKE ?",
			like, like, like)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return Page[AuditLog]{}, translate(err)
	}

	var items []AuditLog
	if err := q.Order("created_at DESC").Limit(p.Limit).Offset(p.Offset()).Find(&items).Error; err != nil {
		return Page[AuditLog]{}, translate(err)
	}
	return newPage(items, total, p), nil
}

// Recent returns the newest entries, for the dashboard activity feed.
func (r *AuditRepo) Recent(limit int) ([]AuditLog, error) {
	if limit <= 0 {
		limit = 10
	}
	var items []AuditLog
	if err := r.db.Order("created_at DESC").Limit(limit).Find(&items).Error; err != nil {
		return nil, translate(err)
	}
	return items, nil
}

// Prune deletes entries older than a cutoff. It is the one destructive
// operation on the log, reserved for the retention job, and it is never
// exposed over the API.
func (r *AuditRepo) Prune(before time.Time) (int64, error) {
	res := r.db.Where("created_at < ?", before).Delete(&AuditLog{})
	return res.RowsAffected, translate(res.Error)
}

// JobRepo persists scheduler run history.
type JobRepo struct{ db *gorm.DB }

// Create inserts a job record.
func (r *JobRepo) Create(j *Job) error {
	return translate(r.db.Create(j).Error)
}

// Update saves a job record.
func (r *JobRepo) Update(j *Job) error {
	return translate(r.db.Save(j).Error)
}

// List returns a page of jobs, newest first.
func (r *JobRepo) List(kind string, p Pagination) (Page[Job], error) {
	p.Normalize()
	q := r.db.Model(&Job{})
	if kind != "" {
		q = q.Where("kind = ?", kind)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return Page[Job]{}, translate(err)
	}

	var items []Job
	if err := q.Order("created_at DESC").Limit(p.Limit).Offset(p.Offset()).Find(&items).Error; err != nil {
		return Page[Job]{}, translate(err)
	}
	return newPage(items, total, p), nil
}

// LastRun returns the most recent job of a kind.
func (r *JobRepo) LastRun(kind string) (*Job, error) {
	var j Job
	if err := r.db.Where("kind = ?", kind).Order("created_at DESC").First(&j).Error; err != nil {
		return nil, translate(err)
	}
	return &j, nil
}

// Prune deletes job history older than a cutoff.
func (r *JobRepo) Prune(before time.Time) (int64, error) {
	res := r.db.Where("created_at < ?", before).Delete(&Job{})
	return res.RowsAffected, translate(res.Error)
}

// NotificationRepo persists notification channels.
type NotificationRepo struct{ db *gorm.DB }

// Create inserts a channel.
func (r *NotificationRepo) Create(n *Notification) error {
	return translate(r.db.Create(n).Error)
}

// Update saves a channel.
func (r *NotificationRepo) Update(n *Notification) error {
	return translate(r.db.Save(n).Error)
}

// Get loads a channel by ID.
func (r *NotificationRepo) Get(id string) (*Notification, error) {
	var n Notification
	if err := r.db.First(&n, "id = ?", id).Error; err != nil {
		return nil, translate(err)
	}
	return &n, nil
}

// All lists every channel.
func (r *NotificationRepo) All() ([]Notification, error) {
	var items []Notification
	if err := r.db.Order("created_at ASC").Find(&items).Error; err != nil {
		return nil, translate(err)
	}
	return items, nil
}

// Enabled lists channels subscribed to an event.
func (r *NotificationRepo) Enabled(event string) ([]Notification, error) {
	var items []Notification
	if err := r.db.Where("enabled = ?", true).Find(&items).Error; err != nil {
		return nil, translate(err)
	}
	if event == "" {
		return items, nil
	}

	out := make([]Notification, 0, len(items))
	for _, n := range items {
		for _, e := range n.Events.Data {
			if e == event || e == "*" {
				out = append(out, n)
				break
			}
		}
	}
	return out, nil
}

// Delete removes a channel.
func (r *NotificationRepo) Delete(id string) error {
	res := r.db.Delete(&Notification{}, "id = ?", id)
	if res.Error != nil {
		return translate(res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// SettingRepo persists instance settings.
type SettingRepo struct{ db *gorm.DB }

// Get loads one setting.
func (r *SettingRepo) Get(key string) (*Setting, error) {
	var s Setting
	if err := r.db.First(&s, "key = ?", key).Error; err != nil {
		return nil, translate(err)
	}
	return &s, nil
}

// GetString returns a plain setting value, or a fallback when it is unset.
func (r *SettingRepo) GetString(key, fallback string) string {
	s, err := r.Get(key)
	if err != nil || s.Value == "" {
		return fallback
	}
	return s.Value
}

// Set upserts a plain setting.
func (r *SettingRepo) Set(key, value string) error {
	setting := Setting{Key: key, Value: value, UpdatedAt: time.Now().UTC()}
	return translate(r.db.Save(&setting).Error)
}

// SetSealed upserts a setting whose value is encrypted at rest.
func (r *SettingRepo) SetSealed(key string, ciphertext, nonce, salt []byte) error {
	setting := Setting{
		Key:            key,
		ValueEncrypted: ciphertext,
		ValueNonce:     nonce,
		ValueSalt:      salt,
		Secret:         true,
		UpdatedAt:      time.Now().UTC(),
	}
	return translate(r.db.Save(&setting).Error)
}

// All lists every setting.
func (r *SettingRepo) All() ([]Setting, error) {
	var items []Setting
	if err := r.db.Order("key ASC").Find(&items).Error; err != nil {
		return nil, translate(err)
	}
	return items, nil
}

// Delete removes a setting.
func (r *SettingRepo) Delete(key string) error {
	return translate(r.db.Delete(&Setting{}, "key = ?", key).Error)
}
