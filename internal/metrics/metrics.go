// Package metrics exposes Certio's own Prometheus series alongside the Go
// runtime ones.
//
// The interesting numbers in a PKI are not request rates — they are "how long
// until this certificate stops working". Those are collected at scrape time
// straight from the database rather than mirrored into a gauge on every write:
// a certificate's expiry is a fact about the row, and a cache of it is one
// more thing that can be wrong.
//
// Everything is registered on a per-instance registry rather than the default
// one, so two Certio instances in one test binary do not fight over a
// duplicate registration.
package metrics

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Namespace prefixes every series this package exports.
const Namespace = "certio"

// CertificateState is one row as the collector needs it.
type CertificateState struct {
	CommonName   string
	Authority    string
	SerialNumber string
	Profile      string
	Status       string
	NotAfter     time.Time
	AutoRenew    bool
}

// AuthorityState is one CA as the collector needs it. A CA quietly reaching
// its own expiry is the failure that takes every certificate under it with it,
// which is why it gets its own series rather than being folded into the
// certificate one.
type AuthorityState struct {
	Name     string
	Type     string
	Status   string
	NotAfter time.Time
}

// Snapshot is the whole picture one scrape needs.
type Snapshot struct {
	Certificates []CertificateState
	Authorities  []AuthorityState
	Revocations  int64
}

// SnapshotFunc reads the current state. It runs on the scrape's goroutine, so
// it must not block for long; returning an error skips the database-backed
// series for that scrape and leaves the counters intact.
type SnapshotFunc func() (Snapshot, error)

// Metrics owns the registry, the event counters and the scrape-time collector.
type Metrics struct {
	registry *prometheus.Registry
	log      *slog.Logger

	// CertificatesIssued counts issuance, split by the flow that produced it
	// so ACME traffic is distinguishable from dashboard clicks.
	CertificatesIssued *prometheus.CounterVec
	// Renewals counts renewal attempts by result.
	Renewals *prometheus.CounterVec
	// Revoked counts revocations by RFC 5280 reason name.
	Revoked *prometheus.CounterVec
	// Notifications counts delivery attempts by channel and result.
	Notifications *prometheus.CounterVec
	// Deployments counts pushes of a renewed certificate to a target.
	Deployments *prometheus.CounterVec
	// SchedulerRuns counts background job runs by kind and status.
	SchedulerRuns *prometheus.CounterVec
	// ACMEOrders counts ACME orders by their terminal state.
	ACMEOrders *prometheus.CounterVec
	// ScrapeErrors counts scrapes whose database read failed, so a silently
	// empty dashboard has a series explaining itself.
	ScrapeErrors prometheus.Counter
}

// New builds the metrics for one instance. A nil snapshot function disables
// the database-backed series, which is what a CLI process wants.
func New(snapshot SnapshotFunc, log *slog.Logger) *Metrics {
	if log == nil {
		log = slog.Default()
	}

	m := &Metrics{
		registry: prometheus.NewRegistry(),
		log:      log,

		CertificatesIssued: counter("certificates_issued_total",
			"Certificates issued, by the flow that produced them.", "ca", "profile", "source"),
		Renewals: counter("renewals_total",
			"Certificate renewal attempts.", "result", "trigger"),
		Revoked: counter("revocations_total",
			"Certificates revoked, by RFC 5280 reason.", "reason"),
		Notifications: counter("notification_deliveries_total",
			"Notification delivery attempts.", "channel", "result"),
		Deployments: counter("deployments_total",
			"Pushes of a certificate to a deployment target.", "kind", "result"),
		SchedulerRuns: counter("scheduler_runs_total",
			"Background job runs.", "kind", "status"),
		ACMEOrders: counter("acme_orders_total",
			"ACME orders by terminal state.", "result"),
		ScrapeErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "scrape_errors_total",
			Help:      "Scrapes whose database read failed.",
		}),
	}

	m.registry.MustRegister(
		m.CertificatesIssued, m.Renewals, m.Revoked, m.Notifications,
		m.Deployments, m.SchedulerRuns, m.ACMEOrders, m.ScrapeErrors,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	if snapshot != nil {
		m.registry.MustRegister(&stateCollector{snapshot: snapshot, metrics: m})
	}
	return m
}

func counter(name, help string, labels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace, Name: name, Help: help,
	}, labels)
}

// Registry exposes the underlying registry, for tests that want to gather
// without going through HTTP.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// Handler serves the exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
		Registry:      m.registry,
	})
}

// Descriptors for the scrape-time series.
var (
	certExpiry = prometheus.NewDesc(
		Namespace+"_certificate_expiry_timestamp_seconds",
		"Unix time at which a certificate stops being valid. Alert on this rather than polling the UI.",
		[]string{"common_name", "ca", "serial", "profile", "auto_renew"}, nil)

	certTotal = prometheus.NewDesc(
		Namespace+"_certificates",
		"Certificates by lifecycle status.",
		[]string{"status"}, nil)

	caExpiry = prometheus.NewDesc(
		Namespace+"_authority_expiry_timestamp_seconds",
		"Unix time at which a certificate authority stops being valid.",
		[]string{"name", "type"}, nil)

	caTotal = prometheus.NewDesc(
		Namespace+"_authorities",
		"Certificate authorities by status.",
		[]string{"status"}, nil)

	revocationTotal = prometheus.NewDesc(
		Namespace+"_revocations",
		"Entries currently on any CRL.",
		nil, nil)
)

// stateCollector reads the database on each scrape.
type stateCollector struct {
	snapshot SnapshotFunc
	metrics  *Metrics
}

// Describe sends the static descriptors.
func (c *stateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- certExpiry
	ch <- certTotal
	ch <- caExpiry
	ch <- caTotal
	ch <- revocationTotal
}

// Collect reads the current state and emits one sample per certificate.
func (c *stateCollector) Collect(ch chan<- prometheus.Metric) {
	snap, err := c.snapshot()
	if err != nil {
		c.metrics.ScrapeErrors.Inc()
		c.metrics.log.Error("could not read state for a metrics scrape", "error", err)
		return
	}

	byStatus := make(map[string]float64, 4)
	for _, cert := range snap.Certificates {
		byStatus[cert.Status]++
		// A revoked certificate's expiry is no longer actionable — alerting on
		// it would page someone about a certificate that has already been
		// dealt with.
		if cert.Status == "revoked" {
			continue
		}
		ch <- prometheus.MustNewConstMetric(
			certExpiry, prometheus.GaugeValue, float64(cert.NotAfter.Unix()),
			cert.CommonName, cert.Authority, cert.SerialNumber, cert.Profile,
			boolLabel(cert.AutoRenew),
		)
	}
	for status, count := range byStatus {
		ch <- prometheus.MustNewConstMetric(certTotal, prometheus.GaugeValue, count, status)
	}

	caByStatus := make(map[string]float64, 2)
	for _, ca := range snap.Authorities {
		caByStatus[ca.Status]++
		ch <- prometheus.MustNewConstMetric(
			caExpiry, prometheus.GaugeValue, float64(ca.NotAfter.Unix()), ca.Name, ca.Type)
	}
	for status, count := range caByStatus {
		ch <- prometheus.MustNewConstMetric(caTotal, prometheus.GaugeValue, count, status)
	}

	ch <- prometheus.MustNewConstMetric(revocationTotal, prometheus.GaugeValue, float64(snap.Revocations))
}

func boolLabel(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Result normalises an error into the "result" label every counter uses, so
// call sites read `m.Renewals.WithLabelValues(metrics.Result(err), "scheduler")`
// instead of repeating the same if.
func Result(err error) string {
	if err != nil {
		return "failure"
	}
	return "success"
}
