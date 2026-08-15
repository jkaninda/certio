package service

import (
	"sort"
	"time"

	"github.com/jkaninda/certio/internal/store"
)

// DashboardStats is everything the landing page renders.
type DashboardStats struct {
	Authorities    CountSummary     `json:"authorities"`
	Certificates   CountSummary     `json:"certificates"`
	ExpiringSoon   []ExpiryEntry    `json:"expiring_soon"`
	Timeline       []ExpiryEntry    `json:"timeline"`
	Revocations    int64            `json:"revocations"`
	ByProfile      map[string]int64 `json:"by_profile"`
	RecentActivity []store.AuditLog `json:"recent_activity"`
	LastJob        *store.Job       `json:"last_job,omitempty"`
	GeneratedAt    time.Time        `json:"generated_at"`
}

// CountSummary breaks a total down by lifecycle status.
type CountSummary struct {
	Total    int64 `json:"total"`
	Active   int64 `json:"active"`
	Expiring int64 `json:"expiring"`
	Expired  int64 `json:"expired"`
	Revoked  int64 `json:"revoked"`
}

// ExpiryEntry is one bar of the dashboard's expiry timeline.
type ExpiryEntry struct {
	ID            string    `json:"id"`
	CommonName    string    `json:"common_name"`
	AuthorityID   string    `json:"ca_id"`
	AuthorityName string    `json:"ca_name"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	// PercentElapsed is how far through its lifetime the certificate is,
	// which is what sets the bar's fill.
	PercentElapsed int    `json:"percent_elapsed"`
	Status         string `json:"status"`
	// Severity drives the bar colour: ok | warning | critical | expired.
	Severity  string `json:"severity"`
	AutoRenew bool   `json:"auto_renew"`
}

// Expiry severity thresholds, matching the timeline's colour ramp.
const (
	SeverityOK       = "ok"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
	SeverityExpired  = "expired"

	criticalDays = 7
)

// Dashboard assembles the landing page payload in one pass.
func (s *Service) Dashboard() (*DashboardStats, error) {
	stats := &DashboardStats{GeneratedAt: time.Now().UTC()}

	caCounts, err := s.Store.Authorities.CountByStatus()
	if err != nil {
		return nil, err
	}
	stats.Authorities = summarize(caCounts)

	certCounts, err := s.Store.Certificates.CountByStatus()
	if err != nil {
		return nil, err
	}
	stats.Certificates = summarize(certCounts)

	if stats.ByProfile, err = s.Store.Certificates.CountByProfile(); err != nil {
		return nil, err
	}
	if stats.Revocations, err = s.Store.Revocations.Count(); err != nil {
		return nil, err
	}
	if stats.RecentActivity, err = s.Store.Audit.Recent(10); err != nil {
		return nil, err
	}
	if job, err := s.Store.Jobs.LastRun(store.JobExpiryScan); err == nil {
		stats.LastJob = job
	}

	// The timeline shows what is closest to expiry, whether or not it is
	// inside the warning window — an empty timeline should mean "no
	// certificates", not "nothing urgent".
	timeline, err := s.expiryTimeline(20)
	if err != nil {
		return nil, err
	}
	stats.Timeline = timeline

	warn := time.Now().AddDate(0, 0, s.Config.Scheduler.ExpiryWarnDays)
	for _, entry := range timeline {
		if entry.NotAfter.Before(warn) {
			stats.ExpiringSoon = append(stats.ExpiringSoon, entry)
		}
	}
	if stats.ExpiringSoon == nil {
		stats.ExpiringSoon = []ExpiryEntry{}
	}
	return stats, nil
}

// expiryTimeline returns the certificates nearest to expiry, newest issuer
// names resolved, ready to render as bars.
func (s *Service) expiryTimeline(limit int) ([]ExpiryEntry, error) {
	page, err := s.Store.Certificates.List(store.CertificateFilter{
		SortBy: "not_after", SortDesc: false,
	}, store.Pagination{Page: 1, Limit: limit})
	if err != nil {
		return nil, err
	}

	authorities, err := s.Store.Authorities.All()
	if err != nil {
		return nil, err
	}
	names := make(map[string]string, len(authorities))
	for _, a := range authorities {
		names[a.ID] = a.Name
	}

	now := time.Now()
	entries := make([]ExpiryEntry, 0, len(page.Items))
	for i := range page.Items {
		cert := &page.Items[i]
		entries = append(entries, ExpiryEntry{
			ID:             cert.ID,
			CommonName:     cert.CommonName,
			AuthorityID:    cert.AuthorityID,
			AuthorityName:  names[cert.AuthorityID],
			NotBefore:      cert.NotBefore,
			NotAfter:       cert.NotAfter,
			DaysRemaining:  cert.DaysRemaining(),
			PercentElapsed: percentElapsed(cert.NotBefore, cert.NotAfter, now),
			Status:         cert.DeriveStatus(s.Config.Scheduler.ExpiryWarnDays),
			Severity:       severityFor(cert, s.Config.Scheduler.ExpiryWarnDays, now),
			AutoRenew:      cert.AutoRenew,
		})
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].NotAfter.Before(entries[j].NotAfter)
	})
	return entries, nil
}

// severityFor maps a certificate onto the timeline's colour ramp.
func severityFor(cert *store.Certificate, warnDays int, now time.Time) string {
	switch {
	case cert.Status == store.StatusRevoked, now.After(cert.NotAfter):
		return SeverityExpired
	case now.AddDate(0, 0, criticalDays).After(cert.NotAfter):
		return SeverityCritical
	case now.AddDate(0, 0, warnDays).After(cert.NotAfter):
		return SeverityWarning
	default:
		return SeverityOK
	}
}

// percentElapsed is how far through its validity window a certificate is,
// clamped to 0–100.
func percentElapsed(notBefore, notAfter, now time.Time) int {
	total := notAfter.Sub(notBefore)
	if total <= 0 {
		return 100
	}
	elapsed := now.Sub(notBefore)
	pct := int(elapsed * 100 / total)
	switch {
	case pct < 0:
		return 0
	case pct > 100:
		return 100
	default:
		return pct
	}
}

func summarize(counts map[string]int64) CountSummary {
	summary := CountSummary{
		Active:   counts[store.StatusActive],
		Expiring: counts[store.StatusExpiring],
		Expired:  counts[store.StatusExpired],
		Revoked:  counts[store.StatusRevoked],
	}
	for _, n := range counts {
		summary.Total += n
	}
	return summary
}
