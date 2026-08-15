// Package schedule runs Certio's background work in-process: expiry scanning,
// auto-renewal, CRL refresh and expiry notifications. There is no external
// cron, so `docker run jkaninda/certio` is the whole deployment.
package schedule

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jkaninda/certio/internal/audit"
	"github.com/jkaninda/certio/internal/config"
	"github.com/jkaninda/certio/internal/notify"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
)

// Scheduler owns the background ticker and the jobs it runs.
type Scheduler struct {
	svc *service.Service
	cfg *config.Config
	log *slog.Logger

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// New builds a Scheduler.
func New(svc *service.Service, cfg *config.Config, log *slog.Logger) *Scheduler {
	if log == nil {
		log = slog.Default()
	}
	return &Scheduler{svc: svc, cfg: cfg, log: log}
}

// Start begins the background loop. It returns immediately.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return
	}
	if !s.cfg.Scheduler.Enabled {
		s.log.Info("scheduler is disabled; expiry scanning and auto-renewal will not run")
		return
	}

	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.running = true
	s.done = make(chan struct{})

	go s.loop(runCtx)
	s.log.Info("scheduler started",
		"interval", s.cfg.Scheduler.Interval,
		"crl_interval", s.cfg.Scheduler.CRLInterval,
		"expiry_warn_days", s.cfg.Scheduler.ExpiryWarnDays)
}

// Stop halts the loop and waits for the in-flight tick to finish.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	cancel, done, running := s.cancel, s.done, s.running
	s.running = false
	s.mu.Unlock()

	if !running || cancel == nil {
		return
	}
	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		s.log.Warn("scheduler did not stop within 30s; continuing shutdown")
	}
}

// loop drives the ticker.
func (s *Scheduler) loop(ctx context.Context) {
	defer close(s.done)

	interval := s.cfg.Scheduler.Interval
	if interval <= 0 {
		interval = time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	crlTicker := time.NewTicker(s.crlInterval())
	defer crlTicker.Stop()

	// Run once at startup so an instance that has been down over a renewal
	// window catches up immediately rather than at the next tick.
	s.RunOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			s.log.Info("scheduler stopped")
			return
		case <-ticker.C:
			s.RunOnce(ctx)
		case <-crlTicker.C:
			s.RefreshCRLs(ctx)
		}
	}
}

func (s *Scheduler) crlInterval() time.Duration {
	if s.cfg.Scheduler.CRLInterval > 0 {
		return s.cfg.Scheduler.CRLInterval
	}
	return 24 * time.Hour
}

// RunOnce performs a full pass: status refresh, expiry notifications and
// auto-renewal. It is exported so `certio scan` can run the same code.
func (s *Scheduler) RunOnce(ctx context.Context) {
	s.runJob(ctx, store.JobExpiryScan, s.expiryScan)
	s.runJob(ctx, store.JobAutoRenew, s.autoRenew)
	s.runJob(ctx, store.JobDeploy, s.deployPending)
	s.runJob(ctx, store.JobRetryNotify, s.retryNotifications)
	s.runJob(ctx, store.JobPrune, s.prune)
}

// deployPending pushes renewed certificates to the servers that use them.
//
// It runs straight after auto-renewal, in the same pass: a renewal that
// produces a certificate nobody deploys has only moved the manual step later,
// and later is when everyone has stopped watching.
func (s *Scheduler) deployPending(_ context.Context) (map[string]any, error) {
	deployed, failed, err := s.svc.DeployPending(audit.SystemActor())
	if err != nil {
		return nil, err
	}
	return map[string]any{"deployed": deployed, "failed": failed}, nil
}

// retryNotifications redelivers events whose first attempt failed.
func (s *Scheduler) retryNotifications(ctx context.Context) (map[string]any, error) {
	delivered, retried, abandoned, err := s.svc.RetryDeliveries(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"delivered": delivered, "retried": retried, "abandoned": abandoned,
	}, nil
}

// prune drops rows that have outlived their usefulness: denied sessions whose
// tokens have expired anyway, and finished job records.
//
// The session denylist is checked on every authenticated request, so letting
// it grow without bound would make every request slowly more expensive for no
// benefit — a denied token that has also expired is denied twice over.
func (s *Scheduler) prune(_ context.Context) (map[string]any, error) {
	now := time.Now()

	sessions, err := s.svc.Store.Sessions.Prune(now)
	if err != nil {
		return nil, fmt.Errorf("prune the session denylist: %w", err)
	}

	// Job history is kept long enough to answer "did last night's renewal
	// run", and no longer.
	jobs, err := s.svc.Store.Jobs.Prune(now.AddDate(0, 0, -jobHistoryDays))
	if err != nil {
		return nil, fmt.Errorf("prune the job history: %w", err)
	}

	// Expired ACME nonces and orders. The nonce table is written on every
	// single ACME request, so it is the fastest-growing thing here.
	nonces, orders, err := s.svc.PruneACME()
	if err != nil {
		return nil, fmt.Errorf("prune ACME state: %w", err)
	}

	// Successful deliveries are noise once they are old; failed ones stay, so
	// a channel that gave up is still visible.
	deliveries, err := s.svc.Store.Deliveries.PruneDelivered(now.AddDate(0, 0, -deliveryHistoryDays))
	if err != nil {
		return nil, fmt.Errorf("prune the delivery history: %w", err)
	}

	return map[string]any{
		"sessions": sessions, "jobs": jobs, "deliveries": deliveries,
		"acme_nonces": nonces, "acme_orders": orders,
	}, nil
}

// jobHistoryDays is how long a finished job row is kept.
const jobHistoryDays = 30

// deliveryHistoryDays is how long a successful delivery record is kept.
const deliveryHistoryDays = 7

// RefreshCRLs republishes every CA's revocation list.
func (s *Scheduler) RefreshCRLs(ctx context.Context) {
	s.runJob(ctx, store.JobCRLRefresh, s.refreshCRLs)
}

// runJob wraps a unit of work in a Job row so its history and errors survive
// in the UI rather than only in the process log.
func (s *Scheduler) runJob(ctx context.Context, kind string, fn func(context.Context) (map[string]any, error)) {
	started := time.Now().UTC()
	job := &store.Job{
		Kind: kind, Status: store.JobRunning, StartedAt: &started,
	}
	if err := s.svc.Store.Jobs.Create(job); err != nil {
		s.log.Error("could not record the job start", "error", err, "kind", kind)
	}

	result, err := fn(ctx)

	finished := time.Now().UTC()
	job.FinishedAt = &finished
	job.Result = store.JSON(result)
	if err != nil {
		job.Status, job.Error = store.JobFailed, err.Error()
		s.log.Error("scheduled job failed", "error", err, "kind", kind,
			"duration", finished.Sub(started).Round(time.Millisecond))
	} else {
		job.Status = store.JobSucceeded
		s.log.Info("scheduled job finished", "kind", kind,
			"duration", finished.Sub(started).Round(time.Millisecond), "result", result)
	}

	s.svc.Metrics.SchedulerRuns.WithLabelValues(kind, job.Status).Inc()

	if err := s.svc.Store.Jobs.Update(job); err != nil {
		s.log.Error("could not record the job result", "error", err, "kind", kind)
	}
}

// expiryScan reclassifies certificates and CAs against the clock and fires a
// notification for anything newly inside its warning window.
func (s *Scheduler) expiryScan(ctx context.Context) (map[string]any, error) {
	certChanged, err := s.svc.RefreshCertificateStatuses()
	if err != nil {
		return nil, fmt.Errorf("refresh certificate statuses: %w", err)
	}
	caChanged, err := s.svc.RefreshAuthorityStatuses()
	if err != nil {
		return nil, fmt.Errorf("refresh authority statuses: %w", err)
	}

	warnDays := s.cfg.Scheduler.ExpiryWarnDays
	cutoff := time.Now().AddDate(0, 0, warnDays)
	expiring, err := s.svc.Store.Certificates.ExpiringBefore(cutoff)
	if err != nil {
		return nil, fmt.Errorf("scan for expiring certificates: %w", err)
	}

	notified := 0
	for i := range expiring {
		if ctx.Err() != nil {
			break
		}
		cert := &expiring[i]
		// Anything already renewed or set to renew itself is not news; the
		// renewal job will report on it.
		if cert.AutoRenew && cert.DaysRemaining() > 0 {
			continue
		}

		event := notify.Event{
			Type:      notify.EventCertificateExpiring,
			Title:     fmt.Sprintf("Certificate %s expires in %d days", cert.CommonName, cert.DaysRemaining()),
			Severity:  "warning",
			Timestamp: time.Now().UTC(),
			Data: map[string]any{
				"common_name": cert.CommonName, "serial_number": cert.SerialNumber,
				"not_after": cert.NotAfter.Format(time.RFC3339), "days_remaining": cert.DaysRemaining(),
				"auto_renew": cert.AutoRenew,
			},
		}
		if cert.DaysRemaining() < 0 {
			event.Type = notify.EventCertificateExpired
			event.Severity = "critical"
			event.Title = fmt.Sprintf("Certificate %s has expired", cert.CommonName)
			event.Message = fmt.Sprintf("%s expired on %s and is no longer accepted by clients.",
				cert.CommonName, cert.NotAfter.Format("2006-01-02"))
		} else {
			event.Message = fmt.Sprintf("%s expires on %s. Renew it before then, or enable auto-renew.",
				cert.CommonName, cert.NotAfter.Format("2006-01-02"))
		}

		s.svc.Dispatch(event)
		notified++
	}

	// A CA nearing expiry is more urgent than any single leaf: everything
	// below it stops verifying at that moment.
	authorities, err := s.svc.Store.Authorities.All()
	if err != nil {
		return nil, err
	}
	for i := range authorities {
		ca := &authorities[i]
		if ca.Status != store.StatusExpiring && ca.Status != store.StatusExpired {
			continue
		}
		days := int(time.Until(ca.NotAfter).Hours() / 24)
		s.svc.Dispatch(notify.Event{
			Type:  notify.EventAuthorityExpiring,
			Title: fmt.Sprintf("Certificate authority %s expires in %d days", ca.Name, days),
			Message: fmt.Sprintf("%s expires on %s. Every certificate it issued stops verifying then. "+
				"Renew the CA before renewing anything under it.", ca.Name, ca.NotAfter.Format("2006-01-02")),
			Severity:  "critical",
			Timestamp: time.Now().UTC(),
			Data: map[string]any{
				"authority": ca.Name, "not_after": ca.NotAfter.Format(time.RFC3339), "days_remaining": days,
			},
		})
		notified++
	}

	return map[string]any{
		"certificates_updated": certChanged,
		"authorities_updated":  caChanged,
		"expiring":             len(expiring),
		"notifications_sent":   notified,
	}, nil
}

// autoRenew renews every certificate whose renewal window has opened.
func (s *Scheduler) autoRenew(ctx context.Context) (map[string]any, error) {
	due, err := s.svc.Store.Certificates.DueForAutoRenew(time.Now())
	if err != nil {
		return nil, fmt.Errorf("find certificates due for renewal: %w", err)
	}

	actor := audit.SystemActor()
	renewed, failed := 0, 0
	affectedCAs := map[string]bool{}

	for i := range due {
		if ctx.Err() != nil {
			break
		}
		cert := &due[i]

		result, err := s.svc.Renew(actor, cert.ID, service.RenewInput{Trigger: "scheduler"})
		if err != nil {
			failed++
			s.log.Error("auto-renewal failed",
				"error", err, "certificate", cert.CommonName, "id", cert.ID)
			s.svc.Dispatch(notify.Event{
				Type:      notify.EventRenewalFailed,
				Title:     fmt.Sprintf("Auto-renewal failed for %s", cert.CommonName),
				Message:   fmt.Sprintf("Certio could not renew %s: %s", cert.CommonName, err.Error()),
				Severity:  "critical",
				Timestamp: time.Now().UTC(),
				Data: map[string]any{
					"common_name": cert.CommonName, "certificate_id": cert.ID,
					"not_after": cert.NotAfter.Format(time.RFC3339), "error": err.Error(),
				},
			})
			continue
		}

		renewed++
		affectedCAs[cert.AuthorityID] = true
		s.svc.Dispatch(notify.Event{
			Type:      notify.EventCertificateRenewed,
			Title:     fmt.Sprintf("Renewed %s", cert.CommonName),
			Severity:  "success",
			Timestamp: time.Now().UTC(),
			Message: fmt.Sprintf("%s was renewed automatically and is now valid until %s. "+
				"Deploy the new certificate to take effect.",
				cert.CommonName, result.Certificate.NotAfter.Format("2006-01-02")),
			Data: map[string]any{
				"common_name": cert.CommonName,
				"old_id":      cert.ID, "new_id": result.Certificate.ID,
				"new_serial":    result.Certificate.SerialNumber,
				"new_not_after": result.Certificate.NotAfter.Format(time.RFC3339),
			},
		})
	}

	return map[string]any{"due": len(due), "renewed": renewed, "failed": failed}, nil
}

// refreshCRLs republishes each CA's revocation list so a stale nextUpdate does
// not make clients treat the list as unusable.
func (s *Scheduler) refreshCRLs(ctx context.Context) (map[string]any, error) {
	authorities, err := s.svc.Store.Authorities.All()
	if err != nil {
		return nil, err
	}

	actor := audit.SystemActor()
	refreshed, skipped, failed := 0, 0, 0

	for i := range authorities {
		if ctx.Err() != nil {
			break
		}
		ca := &authorities[i]

		// A passphrase-protected CA cannot be signed unattended. That is the
		// point of the passphrase, so it is skipped rather than failed.
		if ca.PassphraseProtected {
			skipped++
			continue
		}
		if ca.Status == store.StatusExpired {
			skipped++
			continue
		}

		if _, err := s.svc.GenerateCRL(actor, ca.ID, ""); err != nil {
			failed++
			s.log.Error("could not refresh the CRL", "error", err, "ca", ca.Slug)
			continue
		}
		refreshed++
	}

	return map[string]any{"refreshed": refreshed, "skipped": skipped, "failed": failed}, nil
}
