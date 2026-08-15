package service

import (
	"crypto/x509"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jkaninda/certio/internal/audit"
	"github.com/jkaninda/certio/internal/config"
	certiocrypto "github.com/jkaninda/certio/internal/crypto"
	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/store"
)

// newTestService builds a fully wired Service over a temporary database.
func newTestService(t *testing.T) *Service {
	t.Helper()

	cfg := config.Default()
	cfg.Database.Path = filepath.Join(t.TempDir(), "certio-service-test.db")
	cfg.Server.BaseURL = "https://certio.jkaninda.dev"

	st, err := store.Open(cfg, nil)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	master, err := certiocrypto.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	keyring, err := certiocrypto.NewKeyring(master)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return New(st, keyring, cfg, nil)
}

func testActor() audit.Actor {
	return audit.Actor{Type: store.ActorUser, ID: "test-user", Name: "test@jkaninda.dev", IP: "127.0.0.1"}
}

// createRoot is the shared fixture for tests that need an issuing CA.
func createRoot(t *testing.T, s *Service, passphrase string) *store.Authority {
	t.Helper()
	ca, err := s.CreateAuthority(testActor(), CreateAuthorityInput{
		Name: "jkanTech Root CA",
		Type: store.AuthorityTypeRoot,
		Subject: pki.Subject{
			CommonName: "jkanTech Root CA", Organization: "jkanTech", Country: "CD",
		},
		KeyAlgorithm: "ecdsa-p256",
		ValidityDays: 3650,
		Passphrase:   passphrase,
	})
	if err != nil {
		t.Fatalf("CreateAuthority: %v", err)
	}
	return ca
}

func TestCreateRootAuthorityStoresEncryptedKey(t *testing.T) {
	s := newTestService(t)
	ca := createRoot(t, s, "")

	if ca.Slug != "jkantech-root-ca" {
		t.Errorf("slug = %q", ca.Slug)
	}
	if ca.Type != store.AuthorityTypeRoot {
		t.Errorf("type = %q", ca.Type)
	}
	if ca.SerialNumber == "" || ca.FingerprintSHA256 == "" {
		t.Error("serial number or fingerprint was not recorded")
	}
	if ca.CRLURL != "https://certio.jkaninda.dev/ca/"+ca.ID+"/crl.pem" {
		t.Errorf("CRL URL = %q", ca.CRLURL)
	}

	// The key must be stored only as ciphertext.
	if len(ca.KeyEncrypted) == 0 {
		t.Fatal("no encrypted key was stored")
	}
	if strings.Contains(string(ca.KeyEncrypted), "PRIVATE KEY") {
		t.Fatal("the private key was stored in plaintext")
	}

	// And it must decrypt back into a working signer.
	loaded, err := s.LoadCA(ca, "")
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if !pki.KeyMatchesCertificate(loaded.PrivateKey, loaded.Certificate) {
		t.Error("the decrypted key does not match the CA certificate")
	}
}

func TestPassphraseProtectedCARequiresItToSign(t *testing.T) {
	s := newTestService(t)
	ca := createRoot(t, s, "correct horse battery staple")

	if !ca.PassphraseProtected {
		t.Fatal("the CA was not marked passphrase-protected")
	}

	if _, err := s.LoadCA(ca, ""); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("LoadCA without a passphrase = %v, want ErrPassphraseRequired", err)
	}
	if _, err := s.LoadCA(ca, "wrong"); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("LoadCA with the wrong passphrase = %v, want ErrPassphraseRequired", err)
	}
	if _, err := s.LoadCA(ca, "correct horse battery staple"); err != nil {
		t.Errorf("LoadCA with the right passphrase: %v", err)
	}

	// Issuance must fail without it, and succeed with it.
	in := IssueInput{
		AuthorityID: ca.ID,
		Subject:     pki.Subject{CommonName: "locked.jkaninda.dev"},
		SANs:        pki.SANSet{{Type: pki.SANDNS, Value: "locked.jkaninda.dev"}},
		Profile:     pki.ProfileServer,
	}
	if _, err := s.Issue(testActor(), in); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("Issue without the passphrase = %v, want ErrPassphraseRequired", err)
	}
	in.CAPassphrase = "correct horse battery staple"
	if _, err := s.Issue(testActor(), in); err != nil {
		t.Errorf("Issue with the passphrase: %v", err)
	}
}

func TestIssueEndToEnd(t *testing.T) {
	s := newTestService(t)
	ca := createRoot(t, s, "")

	result, err := s.Issue(testActor(), IssueInput{
		AuthorityID: ca.ID,
		Subject:     pki.Subject{CommonName: "*.jkaninda.dev", Organization: "jkanTech"},
		SANs: pki.SANSet{
			{Type: pki.SANDNS, Value: "jkaninda.dev"},
			{Type: pki.SANDNS, Value: "*.jkaninda.dev"},
			{Type: pki.SANIP, Value: "127.0.0.1"},
		},
		Profile:      pki.ProfileServer,
		KeyAlgorithm: "rsa-2048",
		ValidityDays: 397,
		AutoRenew:    true,
		Labels:       map[string]string{"env": "prod"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	cert := result.Certificate
	if cert.CommonName != "*.jkaninda.dev" {
		t.Errorf("common name = %q", cert.CommonName)
	}
	if cert.KeyAlgorithm != pki.AlgoRSA || cert.KeySize != 2048 {
		t.Errorf("key = %s-%d", cert.KeyAlgorithm, cert.KeySize)
	}
	if len(cert.SANs.Data) != 3 {
		t.Errorf("SANs = %v", cert.SANs.Data.Strings())
	}
	if !cert.AutoRenew || cert.RenewBeforeDays != 30 {
		t.Errorf("auto-renew = %v, renew_before = %d", cert.AutoRenew, cert.RenewBeforeDays)
	}
	if cert.Labels.Data["env"] != "prod" {
		t.Errorf("labels = %v", cert.Labels.Data)
	}
	if len(result.PrivateKeyPEM) == 0 {
		t.Error("a managed issuance returned no private key")
	}

	// The issued chain must verify the way a real client would.
	if err := result.Bundle.Verify(time.Now(), x509.ExtKeyUsageServerAuth); err != nil {
		t.Errorf("issued bundle does not verify: %v", err)
	}

	// The CRL distribution point must be baked in, so revocation is checkable.
	if len(result.Bundle.Certificate.CRLDistributionPoints) != 1 {
		t.Errorf("CRL distribution points = %v", result.Bundle.Certificate.CRLDistributionPoints)
	}

	// Reloading from the database must reproduce a working bundle.
	bundle, stored, err := s.LoadBundle(cert.ID, true)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if stored.ID != cert.ID {
		t.Error("LoadBundle returned the wrong certificate")
	}
	if bundle.PrivateKey == nil {
		t.Fatal("LoadBundle did not decrypt the private key")
	}
	if !pki.KeyMatchesCertificate(bundle.PrivateKey, bundle.Certificate) {
		t.Error("the reloaded key does not match the certificate")
	}
}

func TestSignCSRNeverStoresAKey(t *testing.T) {
	s := newTestService(t)
	ca := createRoot(t, s, "")

	// The requester generates their own key — this half never leaves the test.
	key, err := pki.GenerateKey(pki.KeySpec{Algorithm: pki.AlgoECDSA, Curve: "P-256"})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrPEM, err := pki.CreateCSR(key, pki.CSRRequest{
		Subject: pki.Subject{CommonName: "byo.jkaninda.dev", Organization: "jkanTech"},
		SANs:    pki.SANSet{{Type: pki.SANDNS, Value: "byo.jkaninda.dev"}},
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}

	result, err := s.SignCSR(testActor(), SignCSRInput{
		AuthorityID: ca.ID, CSRPEM: string(csrPEM), Profile: pki.ProfileServer,
	})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}

	cert := result.Certificate
	if cert.HasPrivateKey() {
		t.Fatal("a CSR-signed certificate stored a private key")
	}
	if cert.CSRPEM == "" {
		t.Error("the CSR was not retained")
	}
	if len(result.PrivateKeyPEM) != 0 {
		t.Error("SignCSR returned private key material")
	}
	if !pki.PublicKeysEqual(result.Bundle.Certificate.PublicKey, key.Public()) {
		t.Error("the signed certificate does not carry the CSR's public key")
	}

	// Downloading the key must fail — there is none.
	if _, _, err := s.LoadBundle(cert.ID, true); !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("LoadBundle(withKey) = %v, want ErrKeyUnavailable", err)
	}

	// And renewing without rekeying must explain why it cannot work.
	_, err = s.Renew(testActor(), cert.ID, RenewInput{Rekey: false})
	if !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("Renew without rekey = %v, want ErrKeyUnavailable", err)
	}
	if err != nil && !strings.Contains(err.Error(), "submit a new CSR") {
		t.Errorf("the error should suggest the way forward, got: %v", err)
	}

	// Rekeying is the documented escape hatch and must work.
	if _, err := s.Renew(testActor(), cert.ID, RenewInput{Rekey: true}); err != nil {
		t.Errorf("Renew with rekey: %v", err)
	}
}

func TestRenewCreatesANewRowAndPreservesHistory(t *testing.T) {
	s := newTestService(t)
	ca := createRoot(t, s, "")

	original, err := s.Issue(testActor(), IssueInput{
		AuthorityID: ca.ID,
		Subject:     pki.Subject{CommonName: "renew.jkaninda.dev"},
		SANs:        pki.SANSet{{Type: pki.SANDNS, Value: "renew.jkaninda.dev"}},
		Profile:     pki.ProfileServer,
		Notes:       "kept across renewal",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	renewed, err := s.Renew(testActor(), original.Certificate.ID, RenewInput{})
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}

	if renewed.Certificate.ID == original.Certificate.ID {
		t.Fatal("renewal mutated the original row instead of creating a new one")
	}
	if renewed.Certificate.RenewedFromID == nil || *renewed.Certificate.RenewedFromID != original.Certificate.ID {
		t.Error("renewed_from_id does not point at the original")
	}
	if renewed.Certificate.SerialNumber == original.Certificate.SerialNumber {
		t.Error("the renewal reused the serial number")
	}
	if renewed.Certificate.Notes != "kept across renewal" {
		t.Error("metadata was not carried across the renewal")
	}

	// The original must still be there, intact and downloadable.
	stillThere, err := s.Store.Certificates.Get(original.Certificate.ID)
	if err != nil {
		t.Fatalf("the original certificate is gone: %v", err)
	}
	if stillThere.Status != store.StatusActive {
		t.Errorf("the original's status changed to %q", stillThere.Status)
	}

	// Without rekeying, the public key is preserved so pinning survives.
	if !pki.PublicKeysEqual(renewed.Bundle.Certificate.PublicKey, original.Bundle.Certificate.PublicKey) {
		t.Error("renewal without rekey changed the public key")
	}

	history, err := s.Store.Certificates.RenewalHistory(renewed.Certificate.ID)
	if err != nil {
		t.Fatalf("RenewalHistory: %v", err)
	}
	if len(history) != 2 {
		t.Errorf("history has %d entries, want 2", len(history))
	}

	// Rekeying must actually change the key.
	rekeyed, err := s.Renew(testActor(), renewed.Certificate.ID, RenewInput{Rekey: true})
	if err != nil {
		t.Fatalf("Renew(rekey): %v", err)
	}
	if pki.PublicKeysEqual(rekeyed.Bundle.Certificate.PublicKey, original.Bundle.Certificate.PublicKey) {
		t.Error("the rekeyed renewal reused the old key")
	}
}

func TestRevokeUpdatesStatusAndPublishesCRL(t *testing.T) {
	s := newTestService(t)
	ca := createRoot(t, s, "")

	issued, err := s.Issue(testActor(), IssueInput{
		AuthorityID: ca.ID,
		Subject:     pki.Subject{CommonName: "revoke.jkaninda.dev"},
		SANs:        pki.SANSet{{Type: pki.SANDNS, Value: "revoke.jkaninda.dev"}},
		Profile:     pki.ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	rev, err := s.Revoke(testActor(), issued.Certificate.ID, RevokeInput{ReasonCode: pki.ReasonKeyCompromise})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if rev.Reason != "keyCompromise" {
		t.Errorf("reason = %q", rev.Reason)
	}

	after, err := s.Store.Certificates.Get(issued.Certificate.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.Status != store.StatusRevoked {
		t.Errorf("status after revocation = %q", after.Status)
	}

	// Revoking twice must be refused rather than silently duplicated.
	if _, err := s.Revoke(testActor(), issued.Certificate.ID, RevokeInput{ReasonCode: 0}); !errors.Is(err, ErrConflict) {
		t.Errorf("second revoke = %v, want ErrConflict", err)
	}
	// An invalid reason code must be refused.
	if _, err := s.Revoke(testActor(), issued.Certificate.ID, RevokeInput{ReasonCode: 7}); !errors.Is(err, ErrValidation) {
		t.Errorf("revoke with reason 7 = %v, want ErrValidation", err)
	}

	// The published CRL must list the serial and verify against the CA.
	crlPEM, err := s.CRLFor(ca.ID)
	if err != nil {
		t.Fatalf("CRLFor: %v", err)
	}
	crl, err := pki.ParseCRL(crlPEM)
	if err != nil {
		t.Fatalf("ParseCRL: %v", err)
	}
	caCert, err := pki.ParseCertificatePEM([]byte(ca.CertPEM))
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("the published CRL is not signed by the CA: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("the CRL lists %d entries, want 1", len(crl.RevokedCertificateEntries))
	}
	if pki.FormatSerial(crl.RevokedCertificateEntries[0].SerialNumber) != issued.Certificate.SerialNumber {
		t.Error("the CRL lists the wrong serial number")
	}

	// A revoked certificate must not be renewable.
	if _, err := s.Renew(testActor(), issued.Certificate.ID, RenewInput{}); !errors.Is(err, ErrValidation) {
		t.Errorf("renewing a revoked certificate = %v, want ErrValidation", err)
	}
}

func TestIntermediateCAChain(t *testing.T) {
	s := newTestService(t)
	root := createRoot(t, s, "")

	intermediate, err := s.CreateAuthority(testActor(), CreateAuthorityInput{
		Name:         "jkanTech Issuing CA",
		Type:         store.AuthorityTypeIntermediate,
		ParentID:     root.ID,
		Subject:      pki.Subject{CommonName: "jkanTech Issuing CA", Organization: "jkanTech"},
		KeyAlgorithm: "ecdsa-p384",
		ValidityDays: 1825,
	})
	if err != nil {
		t.Fatalf("CreateAuthority(intermediate): %v", err)
	}
	if intermediate.ParentID == nil || *intermediate.ParentID != root.ID {
		t.Fatal("the intermediate is not linked to its parent")
	}

	issued, err := s.Issue(testActor(), IssueInput{
		AuthorityID: intermediate.ID,
		Subject:     pki.Subject{CommonName: "deep.jkaninda.dev"},
		SANs:        pki.SANSet{{Type: pki.SANDNS, Value: "deep.jkaninda.dev"}},
		Profile:     pki.ProfilePeer,
	})
	if err != nil {
		t.Fatalf("Issue from the intermediate: %v", err)
	}

	// The stored bundle must contain leaf + intermediate + root and verify.
	bundle, _, err := s.LoadBundle(issued.Certificate.ID, false)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if len(bundle.Chain) != 2 {
		t.Fatalf("chain has %d issuers, want 2", len(bundle.Chain))
	}
	if err := bundle.Verify(time.Now(), x509.ExtKeyUsageClientAuth); err != nil {
		t.Errorf("the three-level chain does not verify: %v", err)
	}

	certs, err := pki.ParseCertificatesPEM(bundle.FullChainPEM())
	if err != nil {
		t.Fatalf("parse fullchain: %v", err)
	}
	if len(certs) != 3 {
		t.Errorf("fullchain has %d certificates, want 3", len(certs))
	}
}

func TestImportAuthorityAdoptsExistingCA(t *testing.T) {
	s := newTestService(t)

	// Stand in for an existing openssl-managed CA.
	external, err := pki.CreateRootCA(pki.CARequest{
		Subject:      pki.Subject{CommonName: "Legacy jkanTech CA", Organization: "jkanTech"},
		KeySpec:      pki.KeySpec{Algorithm: pki.AlgoRSA, Size: 2048},
		ValidityDays: 1825,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	certPEM := pki.EncodeCertificatePEM(external.Certificate)
	keyPEM, err := pki.MarshalPrivateKeyPEM(external.PrivateKey)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyPEM: %v", err)
	}

	imported, err := s.ImportAuthority(testActor(), ImportAuthorityInput{
		CertPEM: string(certPEM), KeyPEM: string(keyPEM),
	})
	if err != nil {
		t.Fatalf("ImportAuthority: %v", err)
	}
	if imported.Name != "Legacy jkanTech CA" {
		t.Errorf("name = %q", imported.Name)
	}
	if imported.Type != store.AuthorityTypeRoot {
		t.Errorf("type = %q", imported.Type)
	}

	// Importing the same CA twice must be refused on fingerprint, not name.
	_, err = s.ImportAuthority(testActor(), ImportAuthorityInput{
		Name: "A Different Name", CertPEM: string(certPEM), KeyPEM: string(keyPEM),
	})
	if !errors.Is(err, ErrConflict) {
		t.Errorf("re-import = %v, want ErrConflict", err)
	}

	// The adopted CA must be able to issue immediately.
	if _, err := s.Issue(testActor(), IssueInput{
		AuthorityID: imported.ID,
		Subject:     pki.Subject{CommonName: "adopted.jkaninda.dev"},
		SANs:        pki.SANSet{{Type: pki.SANDNS, Value: "adopted.jkaninda.dev"}},
		Profile:     pki.ProfileServer,
	}); err != nil {
		t.Errorf("the adopted CA cannot issue: %v", err)
	}

	// A mismatched key pair must be rejected as a validation error.
	otherKey, _ := pki.GenerateKey(pki.KeySpec{Algorithm: pki.AlgoECDSA, Curve: "P-256"})
	otherKeyPEM, _ := pki.MarshalPrivateKeyPEM(otherKey)
	_, err = s.ImportAuthority(testActor(), ImportAuthorityInput{
		CertPEM: string(certPEM), KeyPEM: string(otherKeyPEM),
	})
	if !errors.Is(err, ErrValidation) {
		t.Errorf("mismatched key = %v, want ErrValidation", err)
	}
}

func TestKeyDownloadPolicy(t *testing.T) {
	s := newTestService(t)
	ca := createRoot(t, s, "")

	issue := func(cn string) *store.Certificate {
		result, err := s.Issue(testActor(), IssueInput{
			AuthorityID: ca.ID,
			Subject:     pki.Subject{CommonName: cn},
			SANs:        pki.SANSet{{Type: pki.SANDNS, Value: cn}},
			Profile:     pki.ProfileServer,
		})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		return result.Certificate
	}

	t.Run("always", func(t *testing.T) {
		s.Config.Security.KeyDownloadPolicy = config.KeyDownloadAlways
		cert := issue("always.jkaninda.dev")
		for i := range 3 {
			if err := s.AuthorizeKeyDownload(testActor(), cert); err != nil {
				t.Fatalf("download %d: %v", i+1, err)
			}
		}
	})

	t.Run("once", func(t *testing.T) {
		s.Config.Security.KeyDownloadPolicy = config.KeyDownloadOnce
		cert := issue("once.jkaninda.dev")
		if err := s.AuthorizeKeyDownload(testActor(), cert); err != nil {
			t.Fatalf("first download: %v", err)
		}
		if err := s.AuthorizeKeyDownload(testActor(), cert); !errors.Is(err, ErrForbidden) {
			t.Errorf("second download = %v, want ErrForbidden", err)
		}
	})

	t.Run("never", func(t *testing.T) {
		s.Config.Security.KeyDownloadPolicy = config.KeyDownloadNever
		cert := issue("never.jkaninda.dev")
		if err := s.AuthorizeKeyDownload(testActor(), cert); !errors.Is(err, ErrForbidden) {
			t.Errorf("download = %v, want ErrForbidden", err)
		}
	})

	// Every denial must be visible in the audit log.
	page, err := s.Store.Audit.List(store.AuditFilter{Action: audit.ActionKeyDownloadDenied},
		store.Pagination{Page: 1, Limit: 50})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if page.Total != 2 {
		t.Errorf("denied downloads recorded = %d, want 2", page.Total)
	}
}

func TestExportFormats(t *testing.T) {
	s := newTestService(t)
	ca := createRoot(t, s, "")

	issued, err := s.Issue(testActor(), IssueInput{
		AuthorityID: ca.ID,
		Subject:     pki.Subject{CommonName: "*.jkaninda.dev"},
		SANs: pki.SANSet{
			{Type: pki.SANDNS, Value: "jkaninda.dev"},
			{Type: pki.SANDNS, Value: "*.jkaninda.dev"},
		},
		Profile: pki.ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	bundle, cert, err := s.LoadBundle(issued.Certificate.ID, true)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}

	cases := []struct {
		format   string
		opts     ExportOptions
		wantExt  string
		contains string
	}{
		{pki.ProfileServer, ExportOptions{Format: FormatPEM}, ".crt", "BEGIN CERTIFICATE"},
		{"fullchain", ExportOptions{Format: FormatFullchain}, "-fullchain.pem", "BEGIN CERTIFICATE"},
		{"chain", ExportOptions{Format: FormatChain}, "-chain.pem", "BEGIN CERTIFICATE"},
		{"key", ExportOptions{Format: FormatKey}, ".key", "BEGIN PRIVATE KEY"},
		{"k8s", ExportOptions{Format: FormatK8s, Namespace: "prod"}, ".yaml", "kubernetes.io/tls"},
		{"nginx", ExportOptions{Format: FormatNginx}, ".conf", "ssl_certificate"},
		{"traefik", ExportOptions{Format: FormatTraefik}, ".yaml", "certFile"},
		{"haproxy", ExportOptions{Format: FormatHAProxy}, ".cfg", "bind *:443 ssl"},
		{"goma", ExportOptions{Format: FormatGoma}, "-goma.yml", "gateway:"},
		{"goma-route", ExportOptions{Format: FormatGomaRoute}, "-goma-route.yml", "routes:"},
		{"compose", ExportOptions{Format: FormatCompose}, ".yml", "services:"},
	}

	for _, tc := range cases {
		t.Run(tc.opts.Format, func(t *testing.T) {
			export, err := s.ExportCertificate(cert, bundle, tc.opts)
			if err != nil {
				t.Fatalf("ExportCertificate: %v", err)
			}
			if !strings.HasSuffix(export.Filename, tc.wantExt) {
				t.Errorf("filename = %q, want it to end in %q", export.Filename, tc.wantExt)
			}
			// A wildcard CN must not produce a filename starting with '*'.
			if strings.ContainsAny(export.Filename, `*/\`) {
				t.Errorf("filename %q is not filesystem-safe", export.Filename)
			}
			if !strings.Contains(string(export.Data), tc.contains) {
				t.Errorf("export does not contain %q:\n%s", tc.contains, truncate(string(export.Data), 400))
			}
		})
	}

	// PKCS#12 needs a password and must produce real binary output.
	if _, err := s.ExportCertificate(cert, bundle, ExportOptions{Format: FormatPKCS12}); !errors.Is(err, ErrValidation) {
		t.Errorf("PKCS#12 without a password = %v, want ErrValidation", err)
	}
	p12, err := s.ExportCertificate(cert, bundle, ExportOptions{Format: FormatPKCS12, Password: "changeit"})
	if err != nil {
		t.Fatalf("PKCS#12: %v", err)
	}
	if len(p12.Data) < 500 {
		t.Errorf("PKCS#12 output is only %d bytes", len(p12.Data))
	}

	// The ZIP bundle must contain every artifact plus the README.
	zipExport, err := s.ExportCertificate(cert, bundle, ExportOptions{Format: FormatZIP})
	if err != nil {
		t.Fatalf("ZIP: %v", err)
	}
	if len(zipExport.Data) == 0 {
		t.Error("the ZIP bundle is empty")
	}

	// An unknown format must be a validation error, not a panic.
	if _, err := s.ExportCertificate(cert, bundle, ExportOptions{Format: "pkcs42"}); !errors.Is(err, ErrValidation) {
		t.Errorf("unknown format = %v, want ErrValidation", err)
	}
}

func TestAuthenticationFlow(t *testing.T) {
	s := newTestService(t)
	auth := NewAuthenticator([]byte("test-signing-secret-value"), "certio", time.Minute, time.Hour)

	user, err := s.CreateUser(testActor(), CreateUserInput{
		Email: "admin@jkaninda.dev", Password: "a-long-enough-password", Role: store.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// A short password must be refused.
	if _, err := s.CreateUser(testActor(), CreateUserInput{
		Email: "weak@jkaninda.dev", Password: "short",
	}); !errors.Is(err, ErrValidation) {
		t.Errorf("short password = %v, want ErrValidation", err)
	}

	result, err := s.Login(testActor(), auth, LoginInput{
		Email: "admin@jkaninda.dev", Password: "a-long-enough-password",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.TwoFactorRequired {
		t.Fatal("Login demanded a second factor from an account without one")
	}
	if result.User.ID != user.ID {
		t.Error("Login returned the wrong user")
	}
	pair := result.Tokens
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("Login returned an empty token")
	}

	// Wrong password and unknown email must be indistinguishable.
	if _, err := s.Login(testActor(), auth, LoginInput{
		Email: "admin@jkaninda.dev", Password: "wrong-password",
	}); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password = %v", err)
	}
	if _, err := s.Login(testActor(), auth, LoginInput{
		Email: "nobody@jkaninda.dev", Password: "any-password",
	}); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown email = %v", err)
	}

	// The access token must resolve to a principal.
	claims, err := auth.Parse(pair.AccessToken)
	if err != nil {
		t.Fatalf("Parse(access): %v", err)
	}
	principal, err := PrincipalFromClaims(claims)
	if err != nil {
		t.Fatalf("PrincipalFromClaims: %v", err)
	}
	if principal.UserID != user.ID || !principal.IsAdmin() {
		t.Errorf("principal = %+v", principal)
	}

	// A refresh token must not authorise a request.
	refreshClaims, err := auth.Parse(pair.RefreshToken)
	if err != nil {
		t.Fatalf("Parse(refresh): %v", err)
	}
	if _, err := PrincipalFromClaims(refreshClaims); err == nil {
		t.Error("a refresh token was accepted as an access token")
	}

	// But it must be exchangeable.
	if _, _, err := s.Refresh(auth, pair.RefreshToken); err != nil {
		t.Errorf("Refresh: %v", err)
	}
	if _, _, err := s.Refresh(auth, pair.AccessToken); err == nil {
		t.Error("an access token was accepted as a refresh token")
	}

	// A token signed with a different secret must be rejected.
	other := NewAuthenticator([]byte("a-completely-different-secret"), "certio", time.Minute, time.Hour)
	if _, err := auth.Parse(mustIssue(t, other, user).AccessToken); err == nil {
		t.Error("a token signed with the wrong secret was accepted")
	}
}

func TestAPITokenAuthentication(t *testing.T) {
	s := newTestService(t)
	user, err := s.CreateUser(testActor(), CreateUserInput{
		Email: "ci@jkaninda.dev", Password: "automation-password-1", Role: store.RoleOperator,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	token, plaintext, err := s.CreateAPIToken(testActor(), CreateTokenInput{
		UserID: user.ID, Name: "ci-pipeline", Scopes: []string{"certificates:write"},
	})
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	if plaintext == "" || !strings.HasPrefix(plaintext, "certio_") {
		t.Fatalf("token plaintext = %q", plaintext)
	}
	if strings.Contains(token.TokenHash, plaintext) {
		t.Fatal("the plaintext token was stored")
	}

	principal, err := s.AuthenticateAPIToken(plaintext)
	if err != nil {
		t.Fatalf("AuthenticateAPIToken: %v", err)
	}
	if principal.UserID != user.ID || principal.TokenID != token.ID {
		t.Errorf("principal = %+v", principal)
	}
	if !principal.CanWrite() || principal.IsAdmin() {
		t.Errorf("an operator should be able to write but not be an admin: %+v", principal)
	}

	if _, err := s.AuthenticateAPIToken("certio_not-a-real-token"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown token = %v", err)
	}

	// A revoked token must stop working immediately.
	if err := s.RevokeAPIToken(testActor(), token.ID); err != nil {
		t.Fatalf("RevokeAPIToken: %v", err)
	}
	if _, err := s.AuthenticateAPIToken(plaintext); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("revoked token = %v, want ErrInvalidCredentials", err)
	}
}

func TestLastAdminIsProtected(t *testing.T) {
	s := newTestService(t)
	admin, err := s.CreateUser(testActor(), CreateUserInput{
		Email: "only@jkaninda.dev", Password: "the-only-admin-pw", Role: store.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	viewer := store.RoleViewer
	if _, err := s.UpdateUser(testActor(), admin.ID, UpdateUserInput{Role: &viewer}); !errors.Is(err, ErrValidation) {
		t.Errorf("demoting the last admin = %v, want ErrValidation", err)
	}
	if err := s.DeleteUser(testActor(), admin.ID); !errors.Is(err, ErrValidation) {
		t.Errorf("deleting the last admin = %v, want ErrValidation", err)
	}

	// With a second admin, both operations become legal.
	if _, err := s.CreateUser(testActor(), CreateUserInput{
		Email: "second@jkaninda.dev", Password: "the-second-admin-pw", Role: store.RoleAdmin,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := s.UpdateUser(testActor(), admin.ID, UpdateUserInput{Role: &viewer}); err != nil {
		t.Errorf("demoting with a spare admin: %v", err)
	}
}

func TestBootstrapIsIdempotent(t *testing.T) {
	s := newTestService(t)

	user, err := s.Bootstrap("first@jkaninda.dev", "bootstrap-password-1", "First Admin")
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if user == nil {
		t.Fatal("Bootstrap did not create the first admin")
	}
	if user.Role != store.RoleAdmin {
		t.Errorf("the bootstrapped user has role %q", user.Role)
	}

	// A second call must not create anything or reset the password.
	again, err := s.Bootstrap("second@jkaninda.dev", "another-password-99", "Second")
	if err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	if again != nil {
		t.Error("Bootstrap created a second account on a non-empty instance")
	}
	count, _ := s.Store.Users.Count()
	if count != 1 {
		t.Errorf("user count = %d, want 1", count)
	}
}

func TestDeleteAuthorityIsAudited(t *testing.T) {
	s := newTestService(t)
	ca := createRoot(t, s, "")

	if _, err := s.Issue(testActor(), IssueInput{
		AuthorityID: ca.ID,
		Subject:     pki.Subject{CommonName: "blocking.jkaninda.dev"},
		SANs:        pki.SANSet{{Type: pki.SANDNS, Value: "blocking.jkaninda.dev"}},
		Profile:     pki.ProfileServer,
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Blocked without force...
	if err := s.DeleteAuthority(testActor(), ca.ID, false); !errors.Is(err, store.ErrInUse) {
		t.Errorf("delete without force = %v, want ErrInUse", err)
	}
	// ...and the refusal is itself audited.
	page, err := s.Store.Audit.List(store.AuditFilter{Action: audit.ActionCADelete},
		store.Pagination{Page: 1, Limit: 10})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if page.Total != 1 || page.Items[0].Success {
		t.Errorf("the blocked delete was not audited as a failure: %+v", page.Items)
	}

	if err := s.DeleteAuthority(testActor(), ca.ID, true); err != nil {
		t.Fatalf("forced delete: %v", err)
	}
}

func TestDashboard(t *testing.T) {
	s := newTestService(t)
	ca := createRoot(t, s, "")

	for _, cn := range []string{"one.jkaninda.dev", "two.jkaninda.dev", "three.jkaninda.dev"} {
		if _, err := s.Issue(testActor(), IssueInput{
			AuthorityID: ca.ID,
			Subject:     pki.Subject{CommonName: cn},
			SANs:        pki.SANSet{{Type: pki.SANDNS, Value: cn}},
			Profile:     pki.ProfileServer,
		}); err != nil {
			t.Fatalf("Issue %s: %v", cn, err)
		}
	}

	stats, err := s.Dashboard()
	if err != nil {
		t.Fatalf("Dashboard: %v", err)
	}
	if stats.Authorities.Total != 1 {
		t.Errorf("authorities = %+v", stats.Authorities)
	}
	if stats.Certificates.Total != 3 || stats.Certificates.Active != 3 {
		t.Errorf("certificates = %+v", stats.Certificates)
	}
	if len(stats.Timeline) != 3 {
		t.Errorf("timeline has %d entries, want 3", len(stats.Timeline))
	}
	for _, entry := range stats.Timeline {
		if entry.Severity != SeverityOK {
			t.Errorf("%s: severity = %q, want ok", entry.CommonName, entry.Severity)
		}
		if entry.AuthorityName != "jkanTech Root CA" {
			t.Errorf("%s: ca name = %q", entry.CommonName, entry.AuthorityName)
		}
		if entry.PercentElapsed < 0 || entry.PercentElapsed > 100 {
			t.Errorf("%s: percent elapsed = %d", entry.CommonName, entry.PercentElapsed)
		}
	}
	if stats.ByProfile[pki.ProfileServer] != 3 {
		t.Errorf("by profile = %v", stats.ByProfile)
	}
	if len(stats.RecentActivity) == 0 {
		t.Error("the activity feed is empty")
	}
}

func TestTrustGuideCoversEveryPlatform(t *testing.T) {
	s := newTestService(t)
	ca := createRoot(t, s, "")

	guide := s.TrustGuide(ca)
	if len(guide) < 6 {
		t.Fatalf("the trust guide has only %d platforms", len(guide))
	}

	wantPlatforms := map[string]bool{"linux-debian": false, "macos": false, "windows": false, "java": false, "node": false}
	for _, entry := range guide {
		if _, ok := wantPlatforms[entry.Platform]; ok {
			wantPlatforms[entry.Platform] = true
		}
		if entry.Commands == "" {
			t.Errorf("%s has no commands", entry.Platform)
		}
		// Every recipe must point at this instance's real download URL.
		if !strings.Contains(entry.Commands, ca.ID) && !strings.Contains(entry.Commands, "Dockerfile") {
			t.Errorf("%s does not reference the CA download URL:\n%s", entry.Platform, entry.Commands)
		}
	}
	for platform, found := range wantPlatforms {
		if !found {
			t.Errorf("the trust guide is missing %s", platform)
		}
	}
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"jkanTech Root CA": "jkantech-root-ca",
		"  Spaces  Here  ": "spaces-here",
		"Ünïcödé Nämé":     "n-c-d-n-m",
		"*.jkaninda.dev":   "jkaninda-dev",
		"!!!":              "ca",
		"":                 "ca",
		"already-a-slug":   "already-a-slug",
	}
	for input, want := range cases {
		if got := Slugify(input); got != want {
			t.Errorf("Slugify(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRefreshStatuses(t *testing.T) {
	s := newTestService(t)
	ca := createRoot(t, s, "")

	issued, err := s.Issue(testActor(), IssueInput{
		AuthorityID: ca.ID,
		Subject:     pki.Subject{CommonName: "aging.jkaninda.dev"},
		SANs:        pki.SANSet{{Type: pki.SANDNS, Value: "aging.jkaninda.dev"}},
		Profile:     pki.ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Backdate the expiry so the scan has something to reclassify.
	soon := time.Now().AddDate(0, 0, 5)
	if err := s.Store.Certificates.UpdateFields(issued.Certificate.ID, map[string]any{"not_after": soon}); err != nil {
		t.Fatalf("UpdateFields: %v", err)
	}

	changed, err := s.RefreshCertificateStatuses()
	if err != nil {
		t.Fatalf("RefreshCertificateStatuses: %v", err)
	}
	if changed != 1 {
		t.Errorf("changed = %d, want 1", changed)
	}

	after, err := s.Store.Certificates.Get(issued.Certificate.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.Status != store.StatusExpiring {
		t.Errorf("status = %q, want expiring", after.Status)
	}
}

func mustIssue(t *testing.T, auth *Authenticator, user *store.User) *TokenPair {
	t.Helper()
	pair, err := auth.Issue(user)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return pair
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
