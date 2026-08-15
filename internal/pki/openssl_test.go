package pki

import (
	"bytes"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests cross-check Certio against the openssl binary. openssl is a
// *reference*, never a runtime dependency, so the whole file skips when it is
// not installed — CI on a distroless image still passes.
func opensslPath(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed; skipping cross-check against the reference implementation")
	}
	return path
}

// runOpenssl runs openssl with the given arguments and returns everything it
// wrote, both streams joined.
//
// Both, because openssl splits its output between them differently per build:
// OpenSSL 3.x prints "Certificate request self-signature verify OK" on stdout,
// while LibreSSL — which is what /usr/bin/openssl is on macOS — prints
// "verify OK" on stderr and leaves stdout to the -text dump alone. Reading only
// stdout made these tests pass against one openssl on PATH and fail against
// another, on the same signature, which is the opposite of a cross-check.
func runOpenssl(t *testing.T, stdin []byte, args ...string) string {
	t.Helper()
	cmd := exec.Command(opensslPath(t), args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("openssl %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String() + stderr.String()
}

// normalizeDN collapses the two ways openssl renders distinguished names.
// OpenSSL 1.1 and some 3.x builds print "CN = example.com"; others print
// "CN=example.com". Stripping the spaces around '=' makes assertions work on
// every version without pinning one.
func normalizeDN(s string) string {
	s = strings.ReplaceAll(s, " = ", "=")
	return strings.ReplaceAll(s, ", ", ",")
}

// assertContains checks for a substring after DN normalization.
func assertContains(t *testing.T, haystack, needle, context string) {
	t.Helper()
	if !strings.Contains(normalizeDN(haystack), normalizeDN(needle)) {
		t.Errorf("%s does not contain %q\n--- output ---\n%s", context, needle, haystack)
	}
}

// TestOpensslReadsCertioCertificates is the acceptance test for §13 of the
// plan: every openssl recipe in the repo README has a Certio equivalent, and
// openssl must be able to read back what Certio produces.
func TestOpensslReadsCertioCertificates(t *testing.T) {
	opensslPath(t)

	root, err := CreateRootCA(CARequest{
		Subject: Subject{
			CommonName:   "jkanTech Root CA",
			Organization: "jkanTech",
			Country:      "CD",
			Province:     "Kinshasa",
			Locality:     "Gombe",
		},
		KeySpec:      KeySpec{Algorithm: AlgoRSA, Size: 2048},
		ValidityDays: 1825,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	issued, err := Issue(root, IssueRequest{
		Subject: Subject{CommonName: "*.jkaninda.dev", Organization: "jkanTech", Country: "CD"},
		SANs: SANSet{
			{SANDNS, "jkaninda.dev"},
			{SANDNS, "*.jkaninda.dev"},
			{SANIP, "127.0.0.1"},
			{SANEmail, "admin@jkaninda.dev"},
		},
		KeySpec:      KeySpec{Algorithm: AlgoRSA, Size: 2048},
		Profile:      ProfileServer,
		ValidityDays: 397,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	text := runOpenssl(t, EncodeCertificatePEM(issued.Certificate), "x509", "-noout", "-text")

	// openssl's rendering of everything Certio set must contain these.
	wants := []string{
		"CN = *.jkaninda.dev",
		"O = jkanTech",
		"C = CD",
		"Issuer:",
		"jkanTech Root CA",
		"X509v3 Subject Alternative Name:",
		"DNS:jkaninda.dev",
		"DNS:*.jkaninda.dev",
		"IP Address:127.0.0.1",
		"email:admin@jkaninda.dev",
		"X509v3 Basic Constraints: critical",
		"CA:FALSE",
		"X509v3 Key Usage: critical",
		"Digital Signature",
		"Key Encipherment",
		"X509v3 Extended Key Usage:",
		"TLS Web Server Authentication",
		"X509v3 Subject Key Identifier:",
		"X509v3 Authority Key Identifier:",
		"sha256WithRSAEncryption",
	}
	for _, want := range wants {
		assertContains(t, text, want, "openssl x509 -text")
	}

	// The serial openssl prints must be the serial Certio recorded.
	serialOut := runOpenssl(t, EncodeCertificatePEM(issued.Certificate), "x509", "-noout", "-serial")
	gotSerial := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(serialOut), "serial="))
	wantSerial := FormatSerial(issued.Certificate.SerialNumber)
	if gotSerial != wantSerial {
		t.Errorf("serial: openssl says %s, Certio says %s", gotSerial, wantSerial)
	}

	// And the SHA-256 fingerprint must match too.
	fpOut := runOpenssl(t, EncodeCertificatePEM(issued.Certificate), "x509", "-noout", "-fingerprint", "-sha256")
	gotFP := strings.ToLower(strings.ReplaceAll(
		strings.TrimSpace(strings.SplitN(fpOut, "=", 2)[1]), ":", ""))
	if gotFP != Fingerprint(issued.Certificate) {
		t.Errorf("fingerprint: openssl says %s, Certio says %s", gotFP, Fingerprint(issued.Certificate))
	}
}

// TestOpensslVerifiesCertioChain runs the same path check a TLS client would:
// `openssl verify -CAfile root.pem -untrusted chain.pem leaf.pem`.
func TestOpensslVerifiesCertioChain(t *testing.T) {
	opensslPath(t)

	root, err := CreateRootCA(CARequest{
		Subject:      Subject{CommonName: "Verify Root", Organization: "jkanTech"},
		KeySpec:      KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		ValidityDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	mid, err := CreateIntermediateCA(root, CARequest{
		Subject:      Subject{CommonName: "Verify Intermediate", Organization: "jkanTech"},
		KeySpec:      KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		ValidityDays: 1825,
	})
	if err != nil {
		t.Fatalf("CreateIntermediateCA: %v", err)
	}
	leaf, err := Issue(mid, IssueRequest{
		Subject: Subject{CommonName: "verify.jkaninda.dev"},
		SANs:    SANSet{{SANDNS, "verify.jkaninda.dev"}},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}

	rootPath := write("root.pem", EncodeCertificatePEM(root.Certificate))
	midPath := write("intermediate.pem", EncodeCertificatePEM(mid.Certificate))
	leafPath := write("leaf.pem", EncodeCertificatePEM(leaf.Certificate))

	out := runOpenssl(t, nil, "verify", "-CAfile", rootPath, "-untrusted", midPath, leafPath)
	if !strings.Contains(out, "OK") {
		t.Errorf("openssl verify did not report OK:\n%s", out)
	}

	// The same check through crypto/x509 must agree.
	bundle := Bundle{Certificate: leaf.Certificate, Chain: leaf.Chain}
	if err := bundle.Verify(time.Now(), x509.ExtKeyUsageServerAuth); err != nil {
		t.Errorf("crypto/x509 disagrees with openssl: %v", err)
	}
}

// TestCertioReadsOpensslOutput is the reverse direction: certificates and keys
// generated by openssl must import cleanly, which is what makes adopting an
// existing CA (this repo's jkantech-ca.crt/.key) work.
func TestCertioReadsOpensslOutput(t *testing.T) {
	opensslPath(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ca.key")
	certPath := filepath.Join(dir, "ca.crt")

	runOpenssl(t, nil, "genpkey", "-algorithm", "RSA",
		"-pkeyopt", "rsa_keygen_bits:2048", "-out", keyPath)
	runOpenssl(t, nil, "req", "-x509", "-new", "-nodes",
		"-key", keyPath, "-sha256", "-days", "1825", "-out", certPath,
		"-subj", "/C=CD/ST=Kinshasa/L=Gombe/O=jkanTech/CN=jkanTech CA",
		"-addext", "basicConstraints=critical,CA:TRUE",
		"-addext", "keyUsage=critical,keyCertSign,cRLSign")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	ca, err := ImportCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("ImportCA on openssl-generated material: %v", err)
	}
	if ca.Certificate.Subject.CommonName != "jkanTech CA" {
		t.Errorf("imported CN = %q", ca.Certificate.Subject.CommonName)
	}
	if ca.Certificate.Subject.Organization[0] != "jkanTech" {
		t.Errorf("imported O = %v", ca.Certificate.Subject.Organization)
	}

	// The adopted CA must be able to issue a working certificate.
	issued, err := Issue(ca, IssueRequest{
		Subject: Subject{CommonName: "adopted.jkaninda.dev"},
		SANs:    SANSet{{SANDNS, "adopted.jkaninda.dev"}, {SANIP, "127.0.0.1"}},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("issue from an adopted CA: %v", err)
	}
	bundle := Bundle{Certificate: issued.Certificate, Chain: issued.Chain}
	if err := bundle.Verify(time.Now(), x509.ExtKeyUsageServerAuth); err != nil {
		t.Errorf("certificate from an adopted CA does not verify: %v", err)
	}
}

// TestOpensslReadsCertioCSR checks the BYO-CSR flow in both directions.
func TestOpensslReadsCertioCSR(t *testing.T) {
	opensslPath(t)

	key, err := GenerateKey(KeySpec{Algorithm: AlgoRSA, Size: 2048})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrPEM, err := CreateCSR(key, CSRRequest{
		Subject: Subject{CommonName: "csr.jkaninda.dev", Organization: "jkanTech", Country: "CD"},
		SANs:    SANSet{{SANDNS, "csr.jkaninda.dev"}, {SANIP, "10.0.0.1"}},
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}

	text := runOpenssl(t, csrPEM, "req", "-noout", "-text", "-verify")
	for _, want := range []string{
		"CN = csr.jkaninda.dev",
		"DNS:csr.jkaninda.dev",
		"IP Address:10.0.0.1",
	} {
		assertContains(t, text, want, "openssl req -text")
	}
	// openssl prints one of these depending on version; both mean "signature ok".
	if !strings.Contains(text, "verify OK") && !strings.Contains(text, "Certificate request self-signature verify OK") {
		t.Errorf("openssl did not verify the CSR self-signature:\n%s", text)
	}
}

// TestOpensslReadsCertioCRL checks that a published CRL is one real clients can
// consume.
func TestOpensslReadsCertioCRL(t *testing.T) {
	opensslPath(t)

	ca, err := CreateRootCA(CARequest{
		Subject:      Subject{CommonName: "CRL Root", Organization: "jkanTech"},
		KeySpec:      KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		ValidityDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	issued, err := Issue(ca, IssueRequest{
		Subject: Subject{CommonName: "gone.jkaninda.dev"},
		SANs:    SANSet{{SANDNS, "gone.jkaninda.dev"}},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	der, err := GenerateCRL(ca, CRLRequest{
		Revoked: []RevokedCertificate{{
			SerialNumber: issued.Certificate.SerialNumber,
			RevokedAt:    time.Now(),
			ReasonCode:   ReasonKeyCompromise,
		}},
	})
	if err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}

	text := runOpenssl(t, EncodeCRLPEM(der), "crl", "-noout", "-text")
	if !strings.Contains(text, "CRL Root") {
		t.Errorf("openssl crl -text does not name the issuer:\n%s", text)
	}
	if !strings.Contains(strings.ToLower(text), strings.ToLower(FormatSerial(issued.Certificate.SerialNumber))) {
		t.Errorf("openssl crl -text does not list the revoked serial:\n%s", text)
	}
	if !strings.Contains(text, "Key Compromise") {
		t.Errorf("openssl crl -text does not show the reason code:\n%s", text)
	}
}

// TestOpensslReadsCertioPKCS12 checks the .p12 export against the tool most
// people will use to import it.
func TestOpensslReadsCertioPKCS12(t *testing.T) {
	opensslPath(t)

	ca, err := CreateRootCA(CARequest{
		Subject:      Subject{CommonName: "P12 Root", Organization: "jkanTech"},
		KeySpec:      KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		ValidityDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	issued, err := Issue(ca, IssueRequest{
		Subject: Subject{CommonName: "p12.jkaninda.dev"},
		SANs:    SANSet{{SANDNS, "p12.jkaninda.dev"}},
		KeySpec: KeySpec{Algorithm: AlgoRSA, Size: 2048},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	bundle := Bundle{Certificate: issued.Certificate, PrivateKey: issued.PrivateKey, Chain: issued.Chain}
	p12, err := bundle.PKCS12("changeit")
	if err != nil {
		t.Fatalf("PKCS12: %v", err)
	}

	path := filepath.Join(t.TempDir(), "bundle.p12")
	if err := os.WriteFile(path, p12, 0o600); err != nil {
		t.Fatalf("write p12: %v", err)
	}

	out := runOpenssl(t, nil, "pkcs12", "-in", path, "-info", "-nokeys", "-passin", "pass:changeit")
	if !strings.Contains(out, "p12.jkaninda.dev") {
		t.Errorf("openssl pkcs12 does not show the leaf subject:\n%s", out)
	}
	if !strings.Contains(out, "P12 Root") {
		t.Errorf("openssl pkcs12 does not include the CA chain:\n%s", out)
	}
}
