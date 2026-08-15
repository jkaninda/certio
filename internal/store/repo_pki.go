package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// Pagination is the shared page/limit input for list endpoints.
type Pagination struct {
	Page  int
	Limit int
}

// Normalize clamps the page and limit into sane bounds.
func (p *Pagination) Normalize() {
	if p.Page < 1 {
		p.Page = 1
	}
	switch {
	case p.Limit <= 0:
		p.Limit = 25
	case p.Limit > 200:
		p.Limit = 200
	}
}

// Offset is the SQL offset for the current page.
func (p Pagination) Offset() int { return (p.Page - 1) * p.Limit }

// Page is a slice of results plus the counts a UI needs to render pagination.
type Page[T any] struct {
	Items      []T   `json:"items"`
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	TotalPages int   `json:"total_pages"`
}

func newPage[T any](items []T, total int64, p Pagination) Page[T] {
	pages := int(total) / p.Limit
	if int(total)%p.Limit != 0 {
		pages++
	}
	if items == nil {
		items = []T{}
	}
	return Page[T]{Items: items, Total: total, Page: p.Page, Limit: p.Limit, TotalPages: pages}
}

// AuthorityRepo persists certificate authorities.
type AuthorityRepo struct{ db *gorm.DB }

// AuthorityFilter narrows a listing.
type AuthorityFilter struct {
	Type   string
	Status string
	Query  string
}

// Create inserts a new authority.
func (r *AuthorityRepo) Create(a *Authority) error {
	return translate(r.db.Create(a).Error)
}

// Update saves every field of an existing authority.
func (r *AuthorityRepo) Update(a *Authority) error {
	return translate(r.db.Save(a).Error)
}

// Get loads an authority by ID.
func (r *AuthorityRepo) Get(id string) (*Authority, error) {
	var a Authority
	if err := r.db.First(&a, "id = ?", id).Error; err != nil {
		return nil, translate(err)
	}
	return &a, nil
}

// GetBySlug loads an authority by its URL-friendly slug, which is what the CLI
// accepts in place of an ID.
func (r *AuthorityRepo) GetBySlug(slug string) (*Authority, error) {
	var a Authority
	if err := r.db.First(&a, "slug = ?", slug).Error; err != nil {
		return nil, translate(err)
	}
	return &a, nil
}

// Resolve looks an authority up by ID first, then by slug — so every CLI flag
// and API path accepts either.
func (r *AuthorityRepo) Resolve(idOrSlug string) (*Authority, error) {
	a, err := r.Get(idOrSlug)
	if err == nil {
		return a, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return r.GetBySlug(idOrSlug)
}

// List returns a filtered page of authorities.
func (r *AuthorityRepo) List(f AuthorityFilter, p Pagination) (Page[Authority], error) {
	p.Normalize()
	q := r.db.Model(&Authority{})

	if f.Type != "" {
		q = q.Where("type = ?", f.Type)
	}
	if f.Status != "" {
		q = q.Where("status = ?", f.Status)
	}
	if f.Query != "" {
		like := "%" + strings.ToLower(f.Query) + "%"
		q = q.Where("LOWER(name) LIKE ? OR LOWER(slug) LIKE ? OR LOWER(serial_number) LIKE ?", like, like, like)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return Page[Authority]{}, translate(err)
	}

	var items []Authority
	if err := q.Order("created_at DESC").Limit(p.Limit).Offset(p.Offset()).Find(&items).Error; err != nil {
		return Page[Authority]{}, translate(err)
	}
	return newPage(items, total, p), nil
}

// All returns every authority, used by the scheduler and the CLI.
func (r *AuthorityRepo) All() ([]Authority, error) {
	var items []Authority
	if err := r.db.Order("created_at ASC").Find(&items).Error; err != nil {
		return nil, translate(err)
	}
	return items, nil
}

// Children returns the intermediates directly below an authority.
func (r *AuthorityRepo) Children(parentID string) ([]Authority, error) {
	var items []Authority
	if err := r.db.Where("parent_id = ?", parentID).Find(&items).Error; err != nil {
		return nil, translate(err)
	}
	return items, nil
}

// Chain walks from an authority up to its root, parent first.
func (r *AuthorityRepo) Chain(a *Authority) ([]Authority, error) {
	var chain []Authority
	current := a
	// A cycle would mean corrupt data; bound the walk rather than hang.
	for range 16 {
		if current.ParentID == nil {
			return chain, nil
		}
		parent, err := r.Get(*current.ParentID)
		if err != nil {
			return chain, err
		}
		chain = append(chain, *parent)
		current = parent
	}
	return chain, fmt.Errorf("store: authority chain for %s exceeds 16 levels", a.ID)
}

// Delete removes an authority. It refuses while certificates or child CAs
// still reference it unless force is set.
func (r *AuthorityRepo) Delete(id string, force bool) error {
	if !force {
		var certs int64
		if err := r.db.Model(&Certificate{}).Where("authority_id = ?", id).Count(&certs).Error; err != nil {
			return translate(err)
		}
		if certs > 0 {
			return fmt.Errorf("%w: %d certificate(s) were issued by this CA", ErrInUse, certs)
		}
		var children int64
		if err := r.db.Model(&Authority{}).Where("parent_id = ?", id).Count(&children).Error; err != nil {
			return translate(err)
		}
		if children > 0 {
			return fmt.Errorf("%w: %d intermediate CA(s) chain to this CA", ErrInUse, children)
		}
	}

	return r.db.Transaction(func(tx *gorm.DB) error {
		if force {
			if err := tx.Where("authority_id = ?", id).Delete(&Revocation{}).Error; err != nil {
				return err
			}
			if err := tx.Where("authority_id = ?", id).Delete(&Certificate{}).Error; err != nil {
				return err
			}
			if err := tx.Where("parent_id = ?", id).Delete(&Authority{}).Error; err != nil {
				return err
			}
		}
		return tx.Delete(&Authority{}, "id = ?", id).Error
	})
}

// SlugExists reports whether a slug is taken, so the API can suggest another.
func (r *AuthorityRepo) SlugExists(slug string) (bool, error) {
	var count int64
	if err := r.db.Model(&Authority{}).Where("slug = ?", slug).Count(&count).Error; err != nil {
		return false, translate(err)
	}
	return count > 0, nil
}

// CountByStatus returns a status → count map for the dashboard.
func (r *AuthorityRepo) CountByStatus() (map[string]int64, error) {
	return countByColumn(r.db.Model(&Authority{}), "status")
}

// CertificateRepo persists issued certificates.
type CertificateRepo struct{ db *gorm.DB }

// CertificateFilter narrows a listing.
type CertificateFilter struct {
	AuthorityID string
	Status      string
	Profile     string
	Query       string
	// ExpiringInDays limits results to certificates expiring within N days.
	ExpiringInDays *int
	AutoRenew      *bool
	// IncludeRevoked defaults to true; set false to hide revoked rows.
	IncludeRevoked bool
	// Labels narrows to certificates carrying every listed key=value pair.
	// Labels are the only way to answer "which certificates belong to the
	// payments team", so being able to write one and not read it back made
	// them decorative.
	Labels   map[string]string
	SortBy   string
	SortDesc bool
}

// Create inserts a new certificate.
func (r *CertificateRepo) Create(c *Certificate) error {
	return translate(r.db.Create(c).Error)
}

// Update saves every field of an existing certificate.
func (r *CertificateRepo) Update(c *Certificate) error {
	return translate(r.db.Save(c).Error)
}

// UpdateFields applies a partial update without loading the row first.
func (r *CertificateRepo) UpdateFields(id string, fields map[string]any) error {
	res := r.db.Model(&Certificate{}).Where("id = ?", id).Updates(fields)
	if res.Error != nil {
		return translate(res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// Get loads a certificate by ID.
func (r *CertificateRepo) Get(id string) (*Certificate, error) {
	var c Certificate
	if err := r.db.First(&c, "id = ?", id).Error; err != nil {
		return nil, translate(err)
	}
	return &c, nil
}

// GetWithAuthority loads a certificate together with its issuing CA.
func (r *CertificateRepo) GetWithAuthority(id string) (*Certificate, *Authority, error) {
	cert, err := r.Get(id)
	if err != nil {
		return nil, nil, err
	}
	var ca Authority
	if err := r.db.First(&ca, "id = ?", cert.AuthorityID).Error; err != nil {
		return nil, nil, translate(err)
	}
	return cert, &ca, nil
}

// GetByFingerprint finds a certificate by its SHA-256 fingerprint, which is
// how a caller holding only the certificate itself — an ACME revocation, say —
// identifies the row.
func (r *CertificateRepo) GetByFingerprint(fingerprint string) (*Certificate, error) {
	var c Certificate
	if err := r.db.First(&c, "fingerprint_sha256 = ?", fingerprint).Error; err != nil {
		return nil, translate(err)
	}
	return &c, nil
}

// GetBySerial finds a certificate by its serial within one CA.
func (r *CertificateRepo) GetBySerial(authorityID, serial string) (*Certificate, error) {
	var c Certificate
	err := r.db.First(&c, "authority_id = ? AND serial_number = ?", authorityID, serial).Error
	if err != nil {
		return nil, translate(err)
	}
	return &c, nil
}

// List returns a filtered, sorted page of certificates.
func (r *CertificateRepo) List(f CertificateFilter, p Pagination) (Page[Certificate], error) {
	p.Normalize()
	q := r.db.Model(&Certificate{})

	if f.AuthorityID != "" {
		q = q.Where("authority_id = ?", f.AuthorityID)
	}
	if f.Status != "" {
		q = q.Where("status = ?", f.Status)
	}
	if f.Profile != "" {
		q = q.Where("profile = ?", f.Profile)
	}
	if f.AutoRenew != nil {
		q = q.Where("auto_renew = ?", *f.AutoRenew)
	}
	if !f.IncludeRevoked {
		q = q.Where("status != ?", StatusRevoked)
	}
	if f.ExpiringInDays != nil {
		cutoff := time.Now().AddDate(0, 0, *f.ExpiringInDays)
		q = q.Where("not_after <= ?", cutoff)
	}
	for key, value := range f.Labels {
		// The column is JSON text, so the match is a LIKE over the encoded
		// pair. It is exact on both key and value — a substring match would
		// make env=prod also match env=production.
		encoded := "%" + jsonPair(key, value) + "%"
		q = q.Where("labels LIKE ?", encoded)
	}
	if f.Query != "" {
		like := "%" + strings.ToLower(f.Query) + "%"
		// SANs are JSON text, so a LIKE over the column matches any entry —
		// good enough for a search box, and it keeps the schema portable.
		q = q.Where(
			"LOWER(common_name) LIKE ? OR LOWER(serial_number) LIKE ? OR LOWER(sans) LIKE ? OR LOWER(fingerprint_sha256) LIKE ?",
			like, like, like, like)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return Page[Certificate]{}, translate(err)
	}

	var items []Certificate
	if err := q.Order(certificateOrder(f)).Limit(p.Limit).Offset(p.Offset()).Find(&items).Error; err != nil {
		return Page[Certificate]{}, translate(err)
	}
	return newPage(items, total, p), nil
}

// certificateOrder maps the API's sort parameter onto a safe ORDER BY clause.
// The column is chosen from a fixed set — never interpolated from user input.
func certificateOrder(f CertificateFilter) string {
	column := "created_at"
	switch f.SortBy {
	case "common_name", "not_after", "not_before", "status", "profile", "created_at":
		column = f.SortBy
	case "expiry":
		column = "not_after"
	}
	if f.SortDesc {
		return column + " DESC"
	}
	return column + " ASC"
}

// ExpiringBefore lists non-revoked certificates expiring before a cutoff,
// which is what the scheduler scans.
func (r *CertificateRepo) ExpiringBefore(cutoff time.Time) ([]Certificate, error) {
	var items []Certificate
	err := r.db.Where("status != ? AND not_after <= ?", StatusRevoked, cutoff).
		Order("not_after ASC").Find(&items).Error
	if err != nil {
		return nil, translate(err)
	}
	return items, nil
}

// DueForAutoRenew lists certificates whose renewal window has opened.
func (r *CertificateRepo) DueForAutoRenew(now time.Time) ([]Certificate, error) {
	var items []Certificate
	// A row is due when now + renew_before_days >= not_after. SQLite has no
	// portable date arithmetic across drivers, so the window is compared in
	// seconds against the stored timestamp.
	err := r.db.Where("auto_renew = ? AND status != ?", true, StatusRevoked).
		Order("not_after ASC").Find(&items).Error
	if err != nil {
		return nil, translate(err)
	}

	due := make([]Certificate, 0, len(items))
	for _, c := range items {
		window := time.Duration(c.RenewBeforeDays) * 24 * time.Hour
		if now.Add(window).After(c.NotAfter) {
			due = append(due, c)
		}
	}
	return due, nil
}

// ByAuthority lists every certificate issued by one CA.
func (r *CertificateRepo) ByAuthority(authorityID string) ([]Certificate, error) {
	var items []Certificate
	if err := r.db.Where("authority_id = ?", authorityID).Order("created_at DESC").Find(&items).Error; err != nil {
		return nil, translate(err)
	}
	return items, nil
}

// RenewalHistory walks the renewed_from chain backwards from a certificate.
func (r *CertificateRepo) RenewalHistory(id string) ([]Certificate, error) {
	var history []Certificate
	currentID := id
	for range 64 {
		cert, err := r.Get(currentID)
		if err != nil {
			return history, err
		}
		history = append(history, *cert)
		if cert.RenewedFromID == nil {
			return history, nil
		}
		currentID = *cert.RenewedFromID
	}
	return history, nil
}

// Delete removes a certificate and its revocation record.
func (r *CertificateRepo) Delete(id string) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("certificate_id = ?", id).Delete(&Revocation{}).Error; err != nil {
			return err
		}
		res := tx.Delete(&Certificate{}, "id = ?", id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// CountByStatus returns a status → count map for the dashboard.
func (r *CertificateRepo) CountByStatus() (map[string]int64, error) {
	return countByColumn(r.db.Model(&Certificate{}), "status")
}

// CountByProfile returns a profile → count map for the dashboard.
func (r *CertificateRepo) CountByProfile() (map[string]int64, error) {
	return countByColumn(r.db.Model(&Certificate{}), "profile")
}

// Count returns the total number of certificates.
func (r *CertificateRepo) Count() (int64, error) {
	var n int64
	err := r.db.Model(&Certificate{}).Count(&n).Error
	return n, translate(err)
}

// jsonPair renders a label as it appears inside the stored JSON object, so a
// LIKE can match the pair rather than the key and value independently.
func jsonPair(key, value string) string {
	encoded, err := json.Marshal(map[string]string{key: value})
	if err != nil {
		return ""
	}
	// Strip the surrounding braces: the pair sits among others in the column.
	return strings.Trim(string(encoded), "{}")
}

// CertificateSummary is the slim projection of a certificate: the identifying
// and lifecycle columns, and none of the PEM or key blobs. A whole-table scan
// happens on every metrics scrape, and pulling encrypted key material into
// memory to count rows would be both slow and needlessly risky.
type CertificateSummary struct {
	ID           string
	CommonName   string
	AuthorityID  string
	SerialNumber string
	Profile      string
	Status       string
	NotAfter     time.Time
	AutoRenew    bool
}

// Summaries returns every certificate in its slim form.
func (r *CertificateRepo) Summaries() ([]CertificateSummary, error) {
	var out []CertificateSummary
	err := r.db.Model(&Certificate{}).
		Select("id", "common_name", "authority_id", "serial_number", "profile",
			"status", "not_after", "auto_renew").
		Order("not_after ASC").
		Find(&out).Error
	return out, translate(err)
}

// RevocationRepo persists revocations, the source of truth for CRLs.
type RevocationRepo struct{ db *gorm.DB }

// Create records a revocation.
func (r *RevocationRepo) Create(rev *Revocation) error {
	return translate(r.db.Create(rev).Error)
}

// ByAuthority lists every revocation for one CA, oldest first — the order a
// CRL lists them in.
func (r *RevocationRepo) ByAuthority(authorityID string) ([]Revocation, error) {
	var items []Revocation
	if err := r.db.Where("authority_id = ?", authorityID).Order("revoked_at ASC").Find(&items).Error; err != nil {
		return nil, translate(err)
	}
	return items, nil
}

// ByCertificate loads the revocation for one certificate.
func (r *RevocationRepo) ByCertificate(certificateID string) (*Revocation, error) {
	var rev Revocation
	if err := r.db.First(&rev, "certificate_id = ?", certificateID).Error; err != nil {
		return nil, translate(err)
	}
	return &rev, nil
}

// Delete removes a revocation, which is how a certificateHold is lifted. It is
// deliberately the only way a row leaves this table: a revocation for key
// compromise is permanent, and the service layer is what enforces that only a
// hold ever reaches here.
func (r *RevocationRepo) Delete(id string) error {
	res := r.db.Delete(&Revocation{}, "id = ?", id)
	if res.Error != nil {
		return translate(res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// Count returns the total number of revocations.
func (r *RevocationRepo) Count() (int64, error) {
	var n int64
	err := r.db.Model(&Revocation{}).Count(&n).Error
	return n, translate(err)
}

// countByColumn groups rows by a column and returns value → count. The column
// name comes from Certio code, never from a request.
func countByColumn(q *gorm.DB, column string) (map[string]int64, error) {
	var rows []struct {
		Value string
		Count int64
	}
	err := q.Select(column + " as value, COUNT(*) as count").Group(column).Scan(&rows).Error
	if err != nil {
		return nil, translate(err)
	}
	out := make(map[string]int64, len(rows))
	for _, row := range rows {
		out[row.Value] = row.Count
	}
	return out, nil
}
