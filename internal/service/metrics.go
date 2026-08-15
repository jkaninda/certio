package service

import (
	"github.com/jkaninda/certio/internal/metrics"
	"github.com/jkaninda/certio/internal/store"
)

// MetricsSnapshot reads the current PKI state for a Prometheus scrape.
//
// Statuses are derived from the clock rather than read from the status column.
// The column is only as fresh as the last scheduler pass, and a monitoring
// system that says a certificate is active for up to an hour after it expired
// is worse than no monitoring at all.
func (s *Service) MetricsSnapshot() (metrics.Snapshot, error) {
	warnDays := s.Config.Scheduler.ExpiryWarnDays

	rows, err := s.Store.Certificates.Summaries()
	if err != nil {
		return metrics.Snapshot{}, err
	}

	authorities, err := s.Store.Authorities.All()
	if err != nil {
		return metrics.Snapshot{}, err
	}
	// One lookup table so the per-certificate loop does not hit the database
	// once per row for a CA name.
	caNames := make(map[string]string, len(authorities))
	for i := range authorities {
		caNames[authorities[i].ID] = authorities[i].Name
	}

	certs := make([]metrics.CertificateState, 0, len(rows))
	for _, row := range rows {
		cert := store.Certificate{Status: row.Status, NotAfter: row.NotAfter}
		certs = append(certs, metrics.CertificateState{
			CommonName:   row.CommonName,
			Authority:    caNames[row.AuthorityID],
			SerialNumber: row.SerialNumber,
			Profile:      row.Profile,
			Status:       cert.DeriveStatus(warnDays),
			NotAfter:     row.NotAfter,
			AutoRenew:    row.AutoRenew,
		})
	}

	cas := make([]metrics.AuthorityState, 0, len(authorities))
	for i := range authorities {
		ca := &authorities[i]
		cas = append(cas, metrics.AuthorityState{
			Name: ca.Name, Type: ca.Type, Status: ca.Status, NotAfter: ca.NotAfter,
		})
	}

	revocations, err := s.Store.Revocations.Count()
	if err != nil {
		return metrics.Snapshot{}, err
	}

	return metrics.Snapshot{Certificates: certs, Authorities: cas, Revocations: revocations}, nil
}
