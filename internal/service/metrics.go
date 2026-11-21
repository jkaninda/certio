// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Certio - Self-signed PKI and TLS certificate management
// Copyright (C) 2026 Jonas Kaninda
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
