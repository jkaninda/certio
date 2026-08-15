package metrics

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func testSnapshot() (Snapshot, error) {
	expiry := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return Snapshot{
		Certificates: []CertificateState{
			{
				CommonName: "api.example.com", Authority: "Root CA", SerialNumber: "0A",
				Profile: "server", Status: "active", NotAfter: expiry, AutoRenew: true,
			},
			{
				CommonName: "old.example.com", Authority: "Root CA", SerialNumber: "0B",
				Profile: "server", Status: "revoked", NotAfter: expiry,
			},
		},
		Authorities: []AuthorityState{
			{Name: "Root CA", Type: "root", Status: "active", NotAfter: expiry},
		},
		Revocations: 1,
	}, nil
}

// TestCollectorEmitsExpiry checks the series an alert rule would be written
// against, and that a revoked certificate is left out of the expiry gauge —
// paging someone about a certificate that has already been dealt with is the
// failure mode this collector exists to avoid.
func TestCollectorEmitsExpiry(t *testing.T) {
	m := New(testSnapshot, nil)

	const want = `
# HELP certio_certificate_expiry_timestamp_seconds Unix time at which a certificate stops being valid. Alert on this rather than polling the UI.
# TYPE certio_certificate_expiry_timestamp_seconds gauge
certio_certificate_expiry_timestamp_seconds{auto_renew="true",ca="Root CA",common_name="api.example.com",profile="server",serial="0A"} 1.7882208e+09
`
	if err := testutil.GatherAndCompare(m.Registry(), strings.NewReader(want),
		"certio_certificate_expiry_timestamp_seconds"); err != nil {
		t.Error(err)
	}
}

// TestCollectorCountsByStatus checks the status breakdown, which is what the
// "how healthy is this PKI" panel reads.
func TestCollectorCountsByStatus(t *testing.T) {
	m := New(testSnapshot, nil)

	const want = `
# HELP certio_certificates Certificates by lifecycle status.
# TYPE certio_certificates gauge
certio_certificates{status="active"} 1
certio_certificates{status="revoked"} 1
`
	if err := testutil.GatherAndCompare(m.Registry(), strings.NewReader(want), "certio_certificates"); err != nil {
		t.Error(err)
	}
}

// TestCollectorSurvivesASnapshotError checks that a database blip degrades to
// missing series plus a counter, rather than a failed scrape.
func TestCollectorSurvivesASnapshotError(t *testing.T) {
	m := New(func() (Snapshot, error) { return Snapshot{}, errors.New("database is gone") }, nil)

	if _, err := m.Registry().Gather(); err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if got := testutil.ToFloat64(m.ScrapeErrors); got != 1 {
		t.Errorf("scrape_errors_total = %v, want 1", got)
	}
}

// TestResult checks the label helper every counter call site uses.
func TestResult(t *testing.T) {
	if got := Result(nil); got != "success" {
		t.Errorf("Result(nil) = %q, want success", got)
	}
	if got := Result(errors.New("boom")); got != "failure" {
		t.Errorf("Result(err) = %q, want failure", got)
	}
}

// TestNilSnapshotDisablesTheCollector checks the CLI's construction path: no
// snapshot function means no database-backed series, and no panic.
func TestNilSnapshotDisablesTheCollector(t *testing.T) {
	m := New(nil, nil)
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == "certio_certificates" {
			t.Error("the state collector was registered without a snapshot function")
		}
	}
}
