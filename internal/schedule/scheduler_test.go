package schedule

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jkaninda/certio/internal/audit"
	"github.com/jkaninda/certio/internal/config"
	certiocrypto "github.com/jkaninda/certio/internal/crypto"
	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/service"
	"github.com/jkaninda/certio/internal/store"
)

func newTestScheduler(t *testing.T) (*Scheduler, *service.Service) {
	t.Helper()

	cfg := config.Default()
	cfg.Database.Path = filepath.Join(t.TempDir(), "schedule-test.db")
	cfg.Server.BaseURL = "https://certio.test"
	// A tick would race the test; RunOnce is driven explicitly instead.
	cfg.Scheduler.Enabled = false

	st, err := store.Open(cfg, nil)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	master, _ := certiocrypto.GenerateMasterKey()
	keyring, err := certiocrypto.NewKeyring(master)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}

	svc := service.New(st, keyring, cfg, nil)
	return New(svc, cfg, nil), svc
}

func testCA(t *testing.T, svc *service.Service) *store.Authority {
	t.Helper()
	ca, err := svc.CreateAuthority(audit.SystemActor(), service.CreateAuthorityInput{
		Name:         "Scheduler Root",
		Type:         store.AuthorityTypeRoot,
		Subject:      pki.Subject{CommonName: "Scheduler Root CA"},
		KeyAlgorithm: "ecdsa-p256",
		ValidityDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateAuthority: %v", err)
	}
	return ca
}

func issue(t *testing.T, svc *service.Service, ca *store.Authority, cn string, autoRenew bool) *store.Certificate {
	t.Helper()
	result, err := svc.Issue(audit.SystemActor(), service.IssueInput{
		AuthorityID: ca.ID,
		Subject:     pki.Subject{CommonName: cn},
		SANs:        pki.SANSet{{Type: pki.SANDNS, Value: cn}},
		Profile:     pki.ProfileServer,
		AutoRenew:   autoRenew,
	})
	if err != nil {
		t.Fatalf("Issue %s: %v", cn, err)
	}
	return result.Certificate
}

// expireIn back-dates a certificate's expiry so the scheduler has something to
// act on without waiting a year.
func expireIn(t *testing.T, svc *service.Service, id string, days int) {
	t.Helper()
	err := svc.Store.Certificates.UpdateFields(id, map[string]any{
		"not_after": time.Now().AddDate(0, 0, days),
	})
	if err != nil {
		t.Fatalf("UpdateFields: %v", err)
	}
}

func TestAutoRenewOnlyTouchesEligibleCertificates(t *testing.T) {
	scheduler, svc := newTestScheduler(t)
	ca := testCA(t, svc)

	due := issue(t, svc, ca, "due.example.com", true)
	notDue := issue(t, svc, ca, "notdue.example.com", true)
	manual := issue(t, svc, ca, "manual.example.com", false)

	// Inside the 30-day window, outside it, and a manual one inside it.
	expireIn(t, svc, due.ID, 10)
	expireIn(t, svc, notDue.ID, 200)
	expireIn(t, svc, manual.ID, 5)

	scheduler.RunOnce(context.Background())

	// The renewal creates a new row pointing back at the original.
	page, err := svc.Store.Certificates.List(store.CertificateFilter{IncludeRevoked: true},
		store.Pagination{Page: 1, Limit: 100})
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	renewedFrom := map[string]bool{}
	for i := range page.Items {
		if src := page.Items[i].RenewedFromID; src != nil {
			renewedFrom[*src] = true
		}
	}

	if !renewedFrom[due.ID] {
		t.Error("a certificate inside its renewal window was not renewed")
	}
	if renewedFrom[notDue.ID] {
		t.Error("a certificate outside its renewal window was renewed")
	}
	if renewedFrom[manual.ID] {
		t.Error("a certificate with auto-renew off was renewed")
	}

	// And the run is recorded, so a failure is visible in the UI rather than
	// only in the process log.
	job, err := svc.Store.Jobs.LastRun(store.JobAutoRenew)
	if err != nil {
		t.Fatalf("LastRun: %v", err)
	}
	if job.Status != store.JobSucceeded {
		t.Errorf("job status = %q, error = %q", job.Status, job.Error)
	}
	if job.Result.Data["renewed"] != float64(1) && job.Result.Data["renewed"] != 1 {
		t.Errorf("job result = %v, want renewed: 1", job.Result.Data)
	}
	if job.FinishedAt == nil {
		t.Error("the job was not marked finished")
	}
}

func TestExpiryScanReclassifiesStatuses(t *testing.T) {
	scheduler, svc := newTestScheduler(t)
	ca := testCA(t, svc)

	expiring := issue(t, svc, ca, "expiring.example.com", false)
	expired := issue(t, svc, ca, "expired.example.com", false)
	healthy := issue(t, svc, ca, "healthy.example.com", false)

	expireIn(t, svc, expiring.ID, 10)
	expireIn(t, svc, expired.ID, -3)

	scheduler.RunOnce(context.Background())

	cases := map[string]string{
		expiring.ID: store.StatusExpiring,
		expired.ID:  store.StatusExpired,
		healthy.ID:  store.StatusActive,
	}
	for id, want := range cases {
		got, err := svc.Store.Certificates.Get(id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Status != want {
			t.Errorf("%s: status = %q, want %q", got.CommonName, got.Status, want)
		}
	}

	job, err := svc.Store.Jobs.LastRun(store.JobExpiryScan)
	if err != nil {
		t.Fatalf("LastRun: %v", err)
	}
	if job.Status != store.JobSucceeded {
		t.Errorf("expiry scan status = %q, error = %q", job.Status, job.Error)
	}
}

func TestCRLRefreshSkipsPassphraseProtectedCAs(t *testing.T) {
	scheduler, svc := newTestScheduler(t)

	open := testCA(t, svc)
	locked, err := svc.CreateAuthority(audit.SystemActor(), service.CreateAuthorityInput{
		Name:         "Locked Root",
		Type:         store.AuthorityTypeRoot,
		Subject:      pki.Subject{CommonName: "Locked Root CA"},
		KeyAlgorithm: "ecdsa-p256",
		ValidityDays: 3650,
		Passphrase:   "unattended signing is the point of not having this",
	})
	if err != nil {
		t.Fatalf("CreateAuthority: %v", err)
	}

	scheduler.RefreshCRLs(context.Background())

	// The unprotected CA gets a published CRL...
	refreshed, err := svc.Store.Authorities.Get(open.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if refreshed.CRLNumber != 1 {
		t.Errorf("unprotected CA CRL number = %d, want 1", refreshed.CRLNumber)
	}

	// ...and the protected one is skipped rather than failed, because the
	// scheduler has no way to supply the passphrase.
	skipped, err := svc.Store.Authorities.Get(locked.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if skipped.CRLNumber != 0 {
		t.Errorf("passphrase-protected CA CRL number = %d, want 0", skipped.CRLNumber)
	}

	job, err := svc.Store.Jobs.LastRun(store.JobCRLRefresh)
	if err != nil {
		t.Fatalf("LastRun: %v", err)
	}
	if job.Status != store.JobSucceeded {
		t.Errorf("crl refresh failed instead of skipping: %s", job.Error)
	}
}

func TestSchedulerStartStopIsClean(t *testing.T) {
	scheduler, svc := newTestScheduler(t)
	testCA(t, svc)

	// Enable it and use a short interval so the loop actually runs.
	scheduler.cfg.Scheduler.Enabled = true
	scheduler.cfg.Scheduler.Interval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scheduler.Start(ctx)
	// Starting twice must be a no-op rather than spawning a second loop.
	scheduler.Start(ctx)

	// Give the startup pass time to record a job.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := svc.Store.Jobs.LastRun(store.JobExpiryScan); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if _, err := svc.Store.Jobs.LastRun(store.JobExpiryScan); err != nil {
		t.Fatal("the scheduler did not run its startup pass")
	}

	// Stop must return rather than hang, and be safe to call twice.
	done := make(chan struct{})
	go func() {
		scheduler.Stop()
		scheduler.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return within 5s")
	}
}

func TestDisabledSchedulerDoesNothing(t *testing.T) {
	scheduler, svc := newTestScheduler(t)
	testCA(t, svc)

	// Enabled is false in the fixture.
	scheduler.Start(context.Background())
	time.Sleep(100 * time.Millisecond)

	if _, err := svc.Store.Jobs.LastRun(store.JobExpiryScan); err == nil {
		t.Error("a disabled scheduler ran anyway")
	}
	// Stopping something that never started must not panic or block.
	scheduler.Stop()
}

func TestAutoRenewConverges(t *testing.T) {
	scheduler, svc := newTestScheduler(t)
	ca := testCA(t, svc)

	// A 30-day certificate with the default 30-day renewal window is due the
	// moment it exists. Without a guard, every tick would renew it *and* the
	// certificate the previous tick produced, doubling the table each round.
	cert := issue(t, svc, ca, "loop.example.com", true)
	expireIn(t, svc, cert.ID, 30)

	for range 5 {
		scheduler.RunOnce(context.Background())
	}

	total, err := svc.Store.Certificates.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	// The original plus at most one renewal per round; exponential growth would
	// put this in the dozens.
	if total > 7 {
		t.Errorf("auto-renew produced %d certificates over 5 rounds — it is not converging", total)
	}

	// Exactly one certificate in the chain may still be auto-renewing: the
	// newest. A superseded certificate that keeps the flag forks the chain.
	page, err := svc.Store.Certificates.List(store.CertificateFilter{IncludeRevoked: true},
		store.Pagination{Page: 1, Limit: 100})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	active := 0
	for i := range page.Items {
		if page.Items[i].AutoRenew {
			active++
		}
	}
	if active != 1 {
		t.Errorf("%d certificates still have auto-renew on, want exactly 1", active)
	}
}

func TestRenewalWindowIsCappedBelowValidity(t *testing.T) {
	_, svc := newTestScheduler(t)
	ca := testCA(t, svc)

	result, err := svc.Issue(audit.SystemActor(), service.IssueInput{
		AuthorityID:  ca.ID,
		Subject:      pki.Subject{CommonName: "short.example.com"},
		SANs:         pki.SANSet{{Type: pki.SANDNS, Value: "short.example.com"}},
		Profile:      pki.ProfileServer,
		ValidityDays: 10,
		AutoRenew:    true,
		// Longer than the certificate itself lives.
		RenewBeforeDays: 90,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if result.Certificate.RenewBeforeDays >= result.Certificate.ValidityDays {
		t.Errorf("renew_before_days = %d with validity_days = %d — the certificate is due at birth",
			result.Certificate.RenewBeforeDays, result.Certificate.ValidityDays)
	}
}
