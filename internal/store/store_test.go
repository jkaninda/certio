package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jkaninda/certio/internal/config"
	"github.com/jkaninda/certio/internal/pki"
)

// newTestStore opens a migrated store backed by a temporary file. A file is
// used rather than :memory: because the connection pool would otherwise hand
// out separate empty databases.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	cfg := config.Default()
	cfg.Database.Path = filepath.Join(t.TempDir(), "certio-test.db")

	s, err := Open(cfg, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestMigrateCreatesEveryTable(t *testing.T) {
	s := newTestStore(t)

	for _, table := range []string{
		"authorities", "certificates", "revocations",
		"users", "api_tokens", "audit_logs",
		"notifications", "jobs", "settings",
	} {
		if !s.DB().Migrator().HasTable(table) {
			t.Errorf("table %q was not created", table)
		}
	}

	// Migration must be idempotent — `certio migrate` will be run repeatedly.
	if err := s.Migrate(); err != nil {
		t.Errorf("second Migrate: %v", err)
	}
}

func TestJSONFieldRoundTrip(t *testing.T) {
	s := newTestStore(t)

	ca := &Authority{
		Name: "Test Root", Slug: "test-root", Type: AuthorityTypeRoot,
		Subject:      JSON(pki.Subject{CommonName: "Test Root", Organization: "jkanTech", Country: "CD"}),
		KeyAlgorithm: pki.AlgoECDSA, KeyCurve: "P-256",
		SerialNumber: "0a1b2c", NotBefore: time.Now(), NotAfter: time.Now().AddDate(10, 0, 0),
		CertPEM: "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
		Status:  StatusActive,
	}
	if err := s.Authorities.Create(ca); err != nil {
		t.Fatalf("Create authority: %v", err)
	}
	if ca.ID == "" {
		t.Fatal("BeforeCreate did not assign an ID")
	}

	loaded, err := s.Authorities.Get(ca.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if loaded.Subject.Data.CommonName != "Test Root" {
		t.Errorf("subject did not round-trip: %+v", loaded.Subject.Data)
	}
	if loaded.Subject.Data.Organization != "jkanTech" {
		t.Errorf("organization did not round-trip: %+v", loaded.Subject.Data)
	}

	// SANs are a slice inside a JSON column — the shape most likely to break.
	cert := &Certificate{
		AuthorityID: ca.ID, CommonName: "api.jkaninda.dev", Profile: pki.ProfileServer,
		Subject:      JSON(pki.Subject{CommonName: "api.jkaninda.dev"}),
		SANs:         JSON(pki.SANSet{{Type: pki.SANDNS, Value: "api.jkaninda.dev"}, {Type: pki.SANIP, Value: "10.0.0.1"}}),
		KeyUsage:     JSON([]string{"DigitalSignature", "KeyEncipherment"}),
		ExtKeyUsage:  JSON([]string{"ServerAuth"}),
		Labels:       JSON(map[string]string{"env": "prod", "team": "platform"}),
		KeyAlgorithm: pki.AlgoECDSA, KeyCurve: "P-256",
		SerialNumber: "deadbeef", NotBefore: time.Now(), NotAfter: time.Now().AddDate(0, 0, 397),
		CertPEM: "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
		Status:  StatusActive,
	}
	if err := s.Certificates.Create(cert); err != nil {
		t.Fatalf("Create certificate: %v", err)
	}

	loadedCert, err := s.Certificates.Get(cert.ID)
	if err != nil {
		t.Fatalf("Get certificate: %v", err)
	}
	if len(loadedCert.SANs.Data) != 2 {
		t.Fatalf("SANs did not round-trip: %+v", loadedCert.SANs.Data)
	}
	if loadedCert.SANs.Data[1].Value != "10.0.0.1" {
		t.Errorf("SAN value wrong: %+v", loadedCert.SANs.Data)
	}
	if loadedCert.Labels.Data["env"] != "prod" {
		t.Errorf("labels did not round-trip: %+v", loadedCert.Labels.Data)
	}
}

func TestSerialIsUniquePerAuthority(t *testing.T) {
	s := newTestStore(t)

	makeCA := func(slug string) *Authority {
		ca := &Authority{
			Name: slug, Slug: slug, Type: AuthorityTypeRoot,
			Subject:      JSON(pki.Subject{CommonName: slug}),
			KeyAlgorithm: pki.AlgoECDSA, KeyCurve: "P-256",
			SerialNumber: "00", NotBefore: time.Now(), NotAfter: time.Now().AddDate(10, 0, 0),
			CertPEM: "stub", Status: StatusActive,
		}
		if err := s.Authorities.Create(ca); err != nil {
			t.Fatalf("Create authority: %v", err)
		}
		return ca
	}

	caA, caB := makeCA("ca-a"), makeCA("ca-b")

	newCert := func(caID, serial string) *Certificate {
		return &Certificate{
			AuthorityID: caID, CommonName: "x.jkaninda.dev", Profile: pki.ProfileServer,
			Subject:      JSON(pki.Subject{CommonName: "x.jkaninda.dev"}),
			SANs:         JSON(pki.SANSet{{Type: pki.SANDNS, Value: "x.jkaninda.dev"}}),
			KeyAlgorithm: pki.AlgoECDSA, KeyCurve: "P-256",
			SerialNumber: serial, NotBefore: time.Now(), NotAfter: time.Now().AddDate(0, 0, 397),
			CertPEM: "stub", Status: StatusActive,
		}
	}

	if err := s.Certificates.Create(newCert(caA.ID, "aabb")); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	// Same serial under a different CA is legal.
	if err := s.Certificates.Create(newCert(caB.ID, "aabb")); err != nil {
		t.Errorf("the same serial under a different CA should be allowed: %v", err)
	}
	// Same serial under the same CA is not.
	if err := s.Certificates.Create(newCert(caA.ID, "aabb")); err == nil {
		t.Error("a duplicate serial within one CA was accepted")
	}
}

func TestDeleteAuthorityBlockedWhileInUse(t *testing.T) {
	s := newTestStore(t)

	ca := &Authority{
		Name: "In Use", Slug: "in-use", Type: AuthorityTypeRoot,
		Subject:      JSON(pki.Subject{CommonName: "In Use"}),
		KeyAlgorithm: pki.AlgoECDSA, KeyCurve: "P-256",
		SerialNumber: "01", NotBefore: time.Now(), NotAfter: time.Now().AddDate(10, 0, 0),
		CertPEM: "stub", Status: StatusActive,
	}
	if err := s.Authorities.Create(ca); err != nil {
		t.Fatalf("Create: %v", err)
	}
	cert := &Certificate{
		AuthorityID: ca.ID, CommonName: "held.jkaninda.dev", Profile: pki.ProfileServer,
		Subject:      JSON(pki.Subject{CommonName: "held.jkaninda.dev"}),
		SANs:         JSON(pki.SANSet{{Type: pki.SANDNS, Value: "held.jkaninda.dev"}}),
		KeyAlgorithm: pki.AlgoECDSA, KeyCurve: "P-256",
		SerialNumber: "02", NotBefore: time.Now(), NotAfter: time.Now().AddDate(0, 0, 397),
		CertPEM: "stub", Status: StatusActive,
	}
	if err := s.Certificates.Create(cert); err != nil {
		t.Fatalf("Create certificate: %v", err)
	}

	if err := s.Authorities.Delete(ca.ID, false); err == nil {
		t.Error("deleting a CA with issued certificates should be blocked")
	}
	if err := s.Authorities.Delete(ca.ID, true); err != nil {
		t.Fatalf("forced delete: %v", err)
	}
	if _, err := s.Authorities.Get(ca.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("CA still present after a forced delete: %v", err)
	}
	if _, err := s.Certificates.Get(cert.ID); !errors.Is(err, ErrNotFound) {
		t.Error("issued certificate survived a forced CA delete")
	}
}

func TestDueForAutoRenew(t *testing.T) {
	s := newTestStore(t)

	ca := &Authority{
		Name: "Renew CA", Slug: "renew-ca", Type: AuthorityTypeRoot,
		Subject:      JSON(pki.Subject{CommonName: "Renew CA"}),
		KeyAlgorithm: pki.AlgoECDSA, KeyCurve: "P-256",
		SerialNumber: "03", NotBefore: time.Now(), NotAfter: time.Now().AddDate(10, 0, 0),
		CertPEM: "stub", Status: StatusActive,
	}
	if err := s.Authorities.Create(ca); err != nil {
		t.Fatalf("Create: %v", err)
	}

	add := func(name string, daysLeft, renewBefore int, autoRenew bool, status string) {
		c := &Certificate{
			AuthorityID: ca.ID, CommonName: name, Profile: pki.ProfileServer,
			Subject:      JSON(pki.Subject{CommonName: name}),
			SANs:         JSON(pki.SANSet{{Type: pki.SANDNS, Value: name}}),
			KeyAlgorithm: pki.AlgoECDSA, KeyCurve: "P-256",
			SerialNumber: name, NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(0, 0, daysLeft),
			CertPEM:   "stub",
			Status:    status,
			AutoRenew: autoRenew, RenewBeforeDays: renewBefore,
		}
		if err := s.Certificates.Create(c); err != nil {
			t.Fatalf("Create %s: %v", name, err)
		}
	}

	add("due.jkaninda.dev", 10, 30, true, StatusActive)     // inside the window
	add("notdue.jkaninda.dev", 200, 30, true, StatusActive) // outside the window
	add("manual.jkaninda.dev", 5, 30, false, StatusActive)  // auto-renew off
	add("revoked.jkaninda.dev", 5, 30, true, StatusRevoked) // revoked
	add("expired.jkaninda.dev", -5, 30, true, StatusActive) // already expired, still due

	due, err := s.Certificates.DueForAutoRenew(time.Now())
	if err != nil {
		t.Fatalf("DueForAutoRenew: %v", err)
	}

	names := map[string]bool{}
	for _, c := range due {
		names[c.CommonName] = true
	}
	if !names["due.jkaninda.dev"] {
		t.Error("a certificate inside its renewal window was not returned")
	}
	if !names["expired.jkaninda.dev"] {
		t.Error("an expired auto-renew certificate was not returned")
	}
	if names["notdue.jkaninda.dev"] {
		t.Error("a certificate outside its renewal window was returned")
	}
	if names["manual.jkaninda.dev"] {
		t.Error("a certificate with auto-renew off was returned")
	}
	if names["revoked.jkaninda.dev"] {
		t.Error("a revoked certificate was returned for renewal")
	}
}

func TestDeriveStatus(t *testing.T) {
	cases := []struct {
		daysLeft int
		current  string
		want     string
	}{
		{100, StatusActive, StatusActive},
		{10, StatusActive, StatusExpiring},
		{0, StatusActive, StatusExpiring},
		{-1, StatusActive, StatusExpired},
		{-100, StatusExpiring, StatusExpired},
		{100, StatusRevoked, StatusRevoked},
		{-100, StatusRevoked, StatusRevoked},
	}
	for _, tc := range cases {
		c := Certificate{
			NotAfter: time.Now().AddDate(0, 0, tc.daysLeft).Add(time.Hour),
			Status:   tc.current,
		}
		if got := c.DeriveStatus(30); got != tc.want {
			t.Errorf("DeriveStatus(daysLeft=%d, current=%s) = %s, want %s",
				tc.daysLeft, tc.current, got, tc.want)
		}
	}
}

func TestAuditLogIsAppendOnlyAndFiltered(t *testing.T) {
	s := newTestStore(t)

	for i, action := range []string{"ca.create", "cert.issue", "cert.revoke", "cert.issue"} {
		entry := &AuditLog{
			ActorType: ActorUser, ActorID: "user-1", ActorName: "admin@jkaninda.dev",
			Action: action, ResourceType: "certificate", ResourceID: "res-" + string(rune('a'+i)),
			Metadata: JSON(map[string]any{"index": i}),
			Success:  true,
		}
		if err := s.Audit.Append(entry); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	page, err := s.Audit.List(AuditFilter{Action: "cert.issue"}, Pagination{Page: 1, Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if page.Total != 2 {
		t.Errorf("filtered total = %d, want 2", page.Total)
	}

	all, err := s.Audit.List(AuditFilter{}, Pagination{Page: 1, Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if all.Total != 4 {
		t.Errorf("total = %d, want 4", all.Total)
	}
	if len(all.Items) > 0 && all.Items[0].Metadata.Data["index"] == nil {
		t.Error("audit metadata did not round-trip")
	}

	recent, err := s.Audit.Recent(2)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(recent) != 2 {
		t.Errorf("Recent(2) returned %d entries", len(recent))
	}
}

func TestPagination(t *testing.T) {
	p := Pagination{}
	p.Normalize()
	if p.Page != 1 || p.Limit != 25 {
		t.Errorf("zero pagination normalized to %+v", p)
	}

	p = Pagination{Page: -3, Limit: 5000}
	p.Normalize()
	if p.Page != 1 || p.Limit != 200 {
		t.Errorf("out-of-range pagination normalized to %+v", p)
	}

	p = Pagination{Page: 3, Limit: 20}
	p.Normalize()
	if p.Offset() != 40 {
		t.Errorf("Offset() = %d, want 40", p.Offset())
	}
}

func TestResolveAuthorityByIDOrSlug(t *testing.T) {
	s := newTestStore(t)
	ca := &Authority{
		Name: "jkanTech Root", Slug: "jkantech-root", Type: AuthorityTypeRoot,
		Subject:      JSON(pki.Subject{CommonName: "jkanTech Root"}),
		KeyAlgorithm: pki.AlgoECDSA, KeyCurve: "P-256",
		SerialNumber: "04", NotBefore: time.Now(), NotAfter: time.Now().AddDate(10, 0, 0),
		CertPEM: "stub", Status: StatusActive,
	}
	if err := s.Authorities.Create(ca); err != nil {
		t.Fatalf("Create: %v", err)
	}

	byID, err := s.Authorities.Resolve(ca.ID)
	if err != nil {
		t.Fatalf("Resolve by ID: %v", err)
	}
	bySlug, err := s.Authorities.Resolve("jkantech-root")
	if err != nil {
		t.Fatalf("Resolve by slug: %v", err)
	}
	if byID.ID != bySlug.ID {
		t.Error("Resolve returned different authorities for the ID and the slug")
	}
	if _, err := s.Authorities.Resolve("does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Resolve on a missing authority = %v, want ErrNotFound", err)
	}
}
