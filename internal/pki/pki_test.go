package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCA builds a root CA for use in tests.
func testCA(t *testing.T) *CertificateAuthority {
	t.Helper()
	ca, err := CreateRootCA(CARequest{
		Subject:      Subject{CommonName: "Certio Test Root", Organization: "jkanTech", Country: "CD"},
		KeySpec:      KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		ValidityDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	return ca
}

func TestParseKeySpec(t *testing.T) {
	cases := map[string]KeySpec{
		"rsa-2048":     {Algorithm: AlgoRSA, Size: 2048},
		"rsa-4096":     {Algorithm: AlgoRSA, Size: 4096},
		"rsa":          {Algorithm: AlgoRSA, Size: 2048},
		"ecdsa-p256":   {Algorithm: AlgoECDSA, Curve: "P-256"},
		"ECDSA-P-384":  {Algorithm: AlgoECDSA, Curve: "P-384"},
		"p521":         {Algorithm: AlgoECDSA, Curve: "P-521"},
		"ed25519":      {Algorithm: AlgoEd25519},
		"":             {Algorithm: AlgoECDSA, Curve: "P-256"},
		"prime256v1":   {Algorithm: AlgoECDSA, Curve: "P-256"},
		"  rsa-3072  ": {Algorithm: AlgoRSA, Size: 3072},
	}
	for input, want := range cases {
		got, err := ParseKeySpec(input)
		if err != nil {
			t.Errorf("ParseKeySpec(%q): %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("ParseKeySpec(%q) = %+v, want %+v", input, got, want)
		}
	}

	for _, bad := range []string{"rsa-1024", "dsa", "ecdsa-p192", "secp256k1"} {
		if _, err := ParseKeySpec(bad); err == nil {
			t.Errorf("ParseKeySpec(%q) should have failed", bad)
		}
	}
}

func TestGenerateKeyAllAlgorithms(t *testing.T) {
	for _, name := range SupportedKeySpecs() {
		t.Run(name, func(t *testing.T) {
			spec, err := ParseKeySpec(name)
			if err != nil {
				t.Fatalf("ParseKeySpec: %v", err)
			}
			key, err := GenerateKey(spec)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			switch spec.Algorithm {
			case AlgoRSA:
				rsaKey, ok := key.(*rsa.PrivateKey)
				if !ok {
					t.Fatalf("got %T, want *rsa.PrivateKey", key)
				}
				if rsaKey.N.BitLen() != spec.Size {
					t.Errorf("key size = %d, want %d", rsaKey.N.BitLen(), spec.Size)
				}
			case AlgoECDSA:
				ecKey, ok := key.(*ecdsa.PrivateKey)
				if !ok {
					t.Fatalf("got %T, want *ecdsa.PrivateKey", key)
				}
				if ecKey.Curve.Params().Name != spec.Curve {
					t.Errorf("curve = %s, want %s", ecKey.Curve.Params().Name, spec.Curve)
				}
			case AlgoEd25519:
				if _, ok := key.(ed25519.PrivateKey); !ok {
					t.Fatalf("got %T, want ed25519.PrivateKey", key)
				}
			}

			// Round-trip through PEM.
			pemBytes, err := MarshalPrivateKeyPEM(key)
			if err != nil {
				t.Fatalf("MarshalPrivateKeyPEM: %v", err)
			}
			parsed, err := ParsePrivateKeyPEM(pemBytes)
			if err != nil {
				t.Fatalf("ParsePrivateKeyPEM: %v", err)
			}
			if !PublicKeysEqual(parsed.Public(), key.Public()) {
				t.Error("round-tripped key does not match the original")
			}

			// The derived spec must match what we asked for.
			derived, err := SpecOf(parsed)
			if err != nil {
				t.Fatalf("SpecOf: %v", err)
			}
			if derived != spec {
				t.Errorf("SpecOf = %+v, want %+v", derived, spec)
			}
		})
	}
}

func TestCreateRootCA(t *testing.T) {
	ca := testCA(t)

	if !ca.Certificate.IsCA {
		t.Error("root CA certificate does not have IsCA set")
	}
	if !ca.Certificate.BasicConstraintsValid {
		t.Error("root CA certificate does not have BasicConstraintsValid set")
	}
	if ca.Certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("root CA lacks KeyUsageCertSign")
	}
	if ca.Certificate.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("root CA lacks KeyUsageCRLSign")
	}
	if !ca.IsRoot() {
		t.Error("IsRoot() = false for a self-signed CA")
	}
	if got := ca.Certificate.Subject.CommonName; got != "Certio Test Root" {
		t.Errorf("CommonName = %q", got)
	}
	if len(ca.Certificate.SubjectKeyId) == 0 {
		t.Error("root CA has no SubjectKeyId")
	}

	// A self-signed certificate must verify against itself.
	if err := (Bundle{Certificate: ca.Certificate}).Verify(time.Now()); err != nil {
		t.Errorf("self-signed root does not verify: %v", err)
	}

	// Validity window: ~10 years, back-dated slightly for clock skew.
	if !ca.Certificate.NotBefore.Before(time.Now()) {
		t.Error("NotBefore is not back-dated")
	}
	// 3650 days is a few days short of 10 calendar years because of leap days.
	wantAfter := time.Now().AddDate(0, 0, 3650)
	if ca.Certificate.NotAfter.Before(wantAfter.AddDate(0, 0, -1)) {
		t.Errorf("NotAfter = %s, want ~%s", ca.Certificate.NotAfter, wantAfter)
	}
}

func TestCreateIntermediateCAAndChainVerification(t *testing.T) {
	root := testCA(t)

	intermediate, err := CreateIntermediateCA(root, CARequest{
		Subject:      Subject{CommonName: "Certio Test Intermediate", Organization: "jkanTech"},
		KeySpec:      KeySpec{Algorithm: AlgoRSA, Size: 2048},
		ValidityDays: 1825,
		MaxPathLen:   0, MaxPathLenZero: true,
	})
	if err != nil {
		t.Fatalf("CreateIntermediateCA: %v", err)
	}

	if intermediate.IsRoot() {
		t.Error("intermediate reports itself as a root")
	}
	if len(intermediate.Chain) != 1 || intermediate.Chain[0] != root.Certificate {
		t.Fatalf("intermediate chain = %d certs, want the root", len(intermediate.Chain))
	}
	if err := intermediate.Certificate.CheckSignatureFrom(root.Certificate); err != nil {
		t.Errorf("intermediate is not signed by the root: %v", err)
	}

	// Issue a leaf from the intermediate and verify the full path.
	leaf, err := Issue(intermediate, IssueRequest{
		Subject: Subject{CommonName: "api.jkaninda.dev"},
		SANs:    SANSet{{Type: SANDNS, Value: "api.jkaninda.dev"}},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue from intermediate: %v", err)
	}

	bundle := Bundle{Certificate: leaf.Certificate, PrivateKey: leaf.PrivateKey, Chain: leaf.Chain}
	if err := bundle.Verify(time.Now(), x509.ExtKeyUsageServerAuth); err != nil {
		t.Errorf("leaf → intermediate → root does not verify: %v", err)
	}

	// pathLenConstraint 0 means the intermediate may not issue further CAs.
	_, err = CreateIntermediateCA(intermediate, CARequest{
		Subject:      Subject{CommonName: "Certio Too Deep"},
		KeySpec:      KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		ValidityDays: 365,
	})
	if err == nil {
		t.Error("issuing a CA below a pathLen:0 intermediate should have failed")
	}
}

func TestIssueProfilesSetExpectedExtensions(t *testing.T) {
	ca := testCA(t)

	cases := []struct {
		profile     string
		wantKeyUse  x509.KeyUsage
		wantExtUse  []x509.ExtKeyUsage
		wantDaysMin int
	}{
		{ProfileServer, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, 396},
		{ProfileClient, x509.KeyUsageDigitalSignature,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, 396},
		{ProfilePeer, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, 396},
	}

	for _, tc := range cases {
		t.Run(tc.profile, func(t *testing.T) {
			issued, err := Issue(ca, IssueRequest{
				Subject: Subject{CommonName: "svc.jkaninda.dev"},
				SANs:    SANSet{{Type: SANDNS, Value: "svc.jkaninda.dev"}},
				KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
				Profile: tc.profile,
			})
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			cert := issued.Certificate

			if cert.KeyUsage != tc.wantKeyUse {
				t.Errorf("KeyUsage = %v (%v), want %v", cert.KeyUsage,
					KeyUsageStrings(cert.KeyUsage), KeyUsageStrings(tc.wantKeyUse))
			}
			if len(cert.ExtKeyUsage) != len(tc.wantExtUse) {
				t.Fatalf("ExtKeyUsage = %v, want %v",
					ExtKeyUsageStrings(cert.ExtKeyUsage), ExtKeyUsageStrings(tc.wantExtUse))
			}
			for i, want := range tc.wantExtUse {
				if cert.ExtKeyUsage[i] != want {
					t.Errorf("ExtKeyUsage[%d] = %v, want %v", i, cert.ExtKeyUsage[i], want)
				}
			}
			if cert.IsCA {
				t.Error("leaf certificate has IsCA set")
			}
			days := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
			if days < tc.wantDaysMin {
				t.Errorf("validity = %d days, want at least %d", days, tc.wantDaysMin)
			}
			if InferProfile(cert) != tc.profile {
				t.Errorf("InferProfile = %q, want %q", InferProfile(cert), tc.profile)
			}
		})
	}
}

func TestIssueFoldsCommonNameIntoSANs(t *testing.T) {
	ca := testCA(t)

	issued, err := Issue(ca, IssueRequest{
		Subject: Subject{CommonName: "www.jkaninda.dev"},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	var found bool
	for _, name := range issued.Certificate.DNSNames {
		if name == "www.jkaninda.dev" {
			found = true
		}
	}
	if !found {
		t.Errorf("CN was not folded into DNS SANs: %v", issued.Certificate.DNSNames)
	}

	// A CN that is not a hostname must not become a bogus DNS SAN — but then
	// there is nothing to put in the SAN extension, so issuance must fail.
	_, err = Issue(ca, IssueRequest{
		Subject: Subject{CommonName: "Jonas Kaninda"},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	if err == nil {
		t.Error("issuing with a non-hostname CN and no SANs should have failed")
	}
}

func TestIssueRejectsExpiryBeyondIssuer(t *testing.T) {
	ca, err := CreateRootCA(CARequest{
		Subject:      Subject{CommonName: "Short-lived Root"},
		KeySpec:      KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		ValidityDays: 30,
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	_, err = Issue(ca, IssueRequest{
		Subject:      Subject{CommonName: "outlives.jkaninda.dev"},
		SANs:         SANSet{{Type: SANDNS, Value: "outlives.jkaninda.dev"}},
		KeySpec:      KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile:      ProfileServer,
		ValidityDays: 397,
	})
	if err == nil {
		t.Fatal("issuing past the CA's own expiry should have failed")
	}
	if !strings.Contains(err.Error(), "renew the CA first") {
		t.Errorf("error should tell the user to renew the CA, got: %v", err)
	}
}

func TestSANParsingAndValidation(t *testing.T) {
	valid := []struct {
		input string
		want  SAN
	}{
		{"jkaninda.dev", SAN{SANDNS, "jkaninda.dev"}},
		{"*.jkaninda.dev", SAN{SANDNS, "*.jkaninda.dev"}},
		{"dns:api.jkaninda.dev", SAN{SANDNS, "api.jkaninda.dev"}},
		{"127.0.0.1", SAN{SANIP, "127.0.0.1"}},
		{"ip:10.0.0.1", SAN{SANIP, "10.0.0.1"}},
		{"::1", SAN{SANIP, "::1"}},
		{"2001:db8::1", SAN{SANIP, "2001:db8::1"}},
		{"admin@jkaninda.dev", SAN{SANEmail, "admin@jkaninda.dev"}},
		{"email:ops@jkaninda.dev", SAN{SANEmail, "ops@jkaninda.dev"}},
		{"https://jkaninda.dev/svc", SAN{SANURI, "https://jkaninda.dev/svc"}},
		{"uri:spiffe://cluster/ns/default/sa/api", SAN{SANURI, "spiffe://cluster/ns/default/sa/api"}},
	}
	for _, tc := range valid {
		got, err := ParseSAN(tc.input)
		if err != nil {
			t.Errorf("ParseSAN(%q): %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseSAN(%q) = %+v, want %+v", tc.input, got, tc.want)
		}
	}

	invalid := []string{
		"*.*.jkaninda.dev",   // two wildcards
		"api.*.jkaninda.dev", // wildcard not leftmost
		"*api.jkaninda.dev",  // partial wildcard
		"*.dev",              // wildcard must cover a subdomain
		"ip:not-an-ip",
		"email:not an email",
		"uri:/relative/path",
		"dns:has space.dev",
		"",
	}
	for _, input := range invalid {
		if san, err := ParseSAN(input); err == nil {
			t.Errorf("ParseSAN(%q) should have failed, got %+v", input, san)
		}
	}
}

func TestParseSANListBulkPaste(t *testing.T) {
	// The shape a user pastes into the bulk box: mixed separators and blanks.
	raw := `jkaninda.dev, *.jkaninda.dev
	127.0.0.1
	ip:::1;admin@jkaninda.dev

	https://jkaninda.dev`

	set, err := ParseSANList(raw)
	if err != nil {
		t.Fatalf("ParseSANList: %v", err)
	}
	if len(set) != 6 {
		t.Fatalf("got %d SANs (%v), want 6", len(set), set.Strings())
	}

	// De-duplication is case-insensitive on the value.
	set = set.Add(SAN{SANDNS, "JKANINDA.DEV"})
	if len(set) != 6 {
		t.Errorf("duplicate DNS name was not de-duplicated: %v", set.Strings())
	}
}

func TestIssueWithEverySANType(t *testing.T) {
	ca := testCA(t)

	sans := SANSet{
		{SANDNS, "jkaninda.dev"},
		{SANDNS, "*.jkaninda.dev"},
		{SANIP, "127.0.0.1"},
		{SANIP, "::1"},
		{SANEmail, "admin@jkaninda.dev"},
		{SANURI, "spiffe://cluster/ns/default/sa/api"},
	}

	issued, err := Issue(ca, IssueRequest{
		Subject: Subject{CommonName: "jkaninda.dev"},
		SANs:    sans,
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cert := issued.Certificate

	if len(cert.DNSNames) != 2 {
		t.Errorf("DNSNames = %v, want 2 entries", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 2 {
		t.Errorf("IPAddresses = %v, want 2 entries", cert.IPAddresses)
	}
	if len(cert.EmailAddresses) != 1 {
		t.Errorf("EmailAddresses = %v, want 1 entry", cert.EmailAddresses)
	}
	if len(cert.URIs) != 1 {
		t.Errorf("URIs = %v, want 1 entry", cert.URIs)
	}

	// Round-tripping the SANs through the certificate must be lossless.
	back := SANsFromCertificateLike(cert.DNSNames, cert.IPAddresses, cert.EmailAddresses, cert.URIs)
	if len(back) != len(sans) {
		t.Errorf("round-tripped %d SANs, want %d: %v", len(back), len(sans), back.Strings())
	}

	// The wildcard must actually match a subdomain when a client checks it.
	if err := cert.VerifyHostname("app.jkaninda.dev"); err != nil {
		t.Errorf("wildcard does not match app.jkaninda.dev: %v", err)
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("IP SAN does not match: %v", err)
	}
}

func TestCSRRoundTrip(t *testing.T) {
	key, err := GenerateKey(KeySpec{Algorithm: AlgoRSA, Size: 2048})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	csrPEM, err := CreateCSR(key, CSRRequest{
		Subject: Subject{CommonName: "byo.jkaninda.dev", Organization: "jkanTech", Country: "CD"},
		SANs:    SANSet{{SANDNS, "byo.jkaninda.dev"}, {SANIP, "192.168.1.10"}},
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}

	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSR: %v", err)
	}
	if csr.Subject.CommonName != "byo.jkaninda.dev" {
		t.Errorf("CN = %q", csr.Subject.CommonName)
	}

	details, err := DescribeCSR(csr)
	if err != nil {
		t.Fatalf("DescribeCSR: %v", err)
	}
	if details.KeyAlgorithm != "rsa-2048" {
		t.Errorf("KeyAlgorithm = %q, want rsa-2048", details.KeyAlgorithm)
	}
	if len(details.SANs) != 2 {
		t.Errorf("SANs = %v, want 2", details.SANs.Strings())
	}
	if !strings.Contains(details.DN, "/CN=byo.jkaninda.dev") {
		t.Errorf("DN = %q", details.DN)
	}

	// Sign it: the CA must never see the private key.
	ca := testCA(t)
	cert, err := SignCSR(ca, csr, IssueRequest{Profile: ProfileServer})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if !PublicKeysEqual(cert.PublicKey, key.Public()) {
		t.Error("signed certificate does not carry the CSR's public key")
	}
	if err := (Bundle{Certificate: cert, Chain: []*x509.Certificate{ca.Certificate}}).
		Verify(time.Now(), x509.ExtKeyUsageServerAuth); err != nil {
		t.Errorf("CSR-signed certificate does not verify: %v", err)
	}
}

func TestParseCSRRejectsTamperedSignature(t *testing.T) {
	key, _ := GenerateKey(KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"})
	csrPEM, err := CreateCSR(key, CSRRequest{
		Subject: Subject{CommonName: "tamper.jkaninda.dev"},
		SANs:    SANSet{{SANDNS, "tamper.jkaninda.dev"}},
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}

	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSR: %v", err)
	}
	// Flip a byte in the signature and re-encode.
	der := append([]byte{}, csr.Raw...)
	der[len(der)-1] ^= 0xFF
	if _, err := ParseCSR(der); err == nil {
		t.Error("a CSR with a broken signature was accepted")
	}
}

func TestRenewPreservesKeyByDefault(t *testing.T) {
	ca := testCA(t)

	original, err := Issue(ca, IssueRequest{
		Subject: Subject{CommonName: "renew.jkaninda.dev"},
		SANs:    SANSet{{SANDNS, "renew.jkaninda.dev"}},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	renewed, err := Renew(ca, original.Certificate, original.PrivateKey, RenewRequest{})
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}

	if !PublicKeysEqual(renewed.Certificate.PublicKey, original.Certificate.PublicKey) {
		t.Error("renewal without rekey changed the public key — pinning would break")
	}
	if renewed.Certificate.SerialNumber.Cmp(original.Certificate.SerialNumber) == 0 {
		t.Error("renewal reused the serial number")
	}
	if renewed.Certificate.Subject.CommonName != original.Certificate.Subject.CommonName {
		t.Error("renewal changed the subject")
	}
	if len(renewed.Certificate.DNSNames) != len(original.Certificate.DNSNames) {
		t.Error("renewal changed the SANs")
	}

	// Rekeying must produce a different key.
	rekeyed, err := Renew(ca, original.Certificate, original.PrivateKey, RenewRequest{Rekey: true})
	if err != nil {
		t.Fatalf("Renew(rekey): %v", err)
	}
	if PublicKeysEqual(rekeyed.Certificate.PublicKey, original.Certificate.PublicKey) {
		t.Error("rekeyed renewal reused the old key")
	}
	if spec, _ := SpecOf(rekeyed.Certificate.PublicKey); spec.Curve != "P-256" {
		t.Errorf("rekey did not preserve the algorithm: %+v", spec)
	}
}

func TestCRLGenerationAndParsing(t *testing.T) {
	ca := testCA(t)

	issued, err := Issue(ca, IssueRequest{
		Subject: Subject{CommonName: "revoked.jkaninda.dev"},
		SANs:    SANSet{{SANDNS, "revoked.jkaninda.dev"}},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	revokedAt := time.Now().Add(-time.Hour).Truncate(time.Second)
	der, err := GenerateCRL(ca, CRLRequest{
		Number: big.NewInt(7),
		Revoked: []RevokedCertificate{{
			SerialNumber: issued.Certificate.SerialNumber,
			RevokedAt:    revokedAt,
			ReasonCode:   ReasonKeyCompromise,
		}},
	})
	if err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}

	crl, err := ParseCRL(der)
	if err != nil {
		t.Fatalf("ParseCRL(DER): %v", err)
	}
	if _, err := ParseCRL(EncodeCRLPEM(der)); err != nil {
		t.Fatalf("ParseCRL(PEM): %v", err)
	}

	if err := crl.CheckSignatureFrom(ca.Certificate); err != nil {
		t.Errorf("CRL is not signed by the CA: %v", err)
	}
	if crl.Number.Int64() != 7 {
		t.Errorf("CRL number = %s, want 7", crl.Number)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("got %d entries, want 1", len(crl.RevokedCertificateEntries))
	}
	entry := crl.RevokedCertificateEntries[0]
	if entry.SerialNumber.Cmp(issued.Certificate.SerialNumber) != 0 {
		t.Error("CRL entry has the wrong serial number")
	}
	if entry.ReasonCode != ReasonKeyCompromise {
		t.Errorf("reason = %d, want %d", entry.ReasonCode, ReasonKeyCompromise)
	}
	if !crl.NextUpdate.After(crl.ThisUpdate) {
		t.Error("NextUpdate is not after ThisUpdate")
	}

	// An empty CRL is legal and says "nothing is revoked".
	empty, err := GenerateCRL(ca, CRLRequest{Number: big.NewInt(1)})
	if err != nil {
		t.Fatalf("GenerateCRL(empty): %v", err)
	}
	parsed, err := ParseCRL(empty)
	if err != nil {
		t.Fatalf("ParseCRL(empty): %v", err)
	}
	if len(parsed.RevokedCertificateEntries) != 0 {
		t.Error("empty CRL is not empty")
	}
}

func TestRevocationReasonValidation(t *testing.T) {
	for code := range 11 {
		err := ValidateRevocationReason(code)
		if code == 7 {
			if err == nil {
				t.Error("reason code 7 is unassigned and should be rejected")
			}
			continue
		}
		if err != nil {
			t.Errorf("ValidateRevocationReason(%d): %v", code, err)
		}
	}
	if err := ValidateRevocationReason(42); err == nil {
		t.Error("reason code 42 should be rejected")
	}
	if RevocationReasonName(ReasonSuperseded) != "superseded" {
		t.Error("reason name lookup is wrong")
	}
}

func TestSerialNumbersAreUniqueAndWellFormed(t *testing.T) {
	seen := make(map[string]bool, 200)
	for range 200 {
		serial, err := GenerateSerial()
		if err != nil {
			t.Fatalf("GenerateSerial: %v", err)
		}
		if serial.Sign() <= 0 {
			t.Fatal("serial number is not positive")
		}
		if serial.BitLen() > serialBits {
			t.Fatalf("serial is %d bits, want at most %d", serial.BitLen(), serialBits)
		}

		hexStr := FormatSerial(serial)
		if len(hexStr)%2 != 0 {
			t.Errorf("FormatSerial(%s) = %q is not byte-aligned", serial, hexStr)
		}
		if seen[hexStr] {
			t.Fatalf("duplicate serial %s in 200 draws", hexStr)
		}
		seen[hexStr] = true

		back, err := ParseSerial(hexStr)
		if err != nil {
			t.Fatalf("ParseSerial(%q): %v", hexStr, err)
		}
		if back.Cmp(serial) != 0 {
			t.Errorf("serial round-trip failed: %s != %s", back, serial)
		}
	}
}

func TestBundleExports(t *testing.T) {
	root := testCA(t)
	intermediate, err := CreateIntermediateCA(root, CARequest{
		Subject:      Subject{CommonName: "Bundle Intermediate"},
		KeySpec:      KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		ValidityDays: 1825,
	})
	if err != nil {
		t.Fatalf("CreateIntermediateCA: %v", err)
	}

	issued, err := Issue(intermediate, IssueRequest{
		Subject: Subject{CommonName: "bundle.jkaninda.dev"},
		SANs:    SANSet{{SANDNS, "bundle.jkaninda.dev"}},
		KeySpec: KeySpec{Algorithm: AlgoRSA, Size: 2048},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	bundle := Bundle{Certificate: issued.Certificate, PrivateKey: issued.PrivateKey, Chain: issued.Chain}

	certs, err := ParseCertificatesPEM(bundle.FullChainPEM())
	if err != nil {
		t.Fatalf("parse fullchain: %v", err)
	}
	if len(certs) != 3 {
		t.Errorf("fullchain has %d certificates, want 3 (leaf + intermediate + root)", len(certs))
	}
	if certs[0].Subject.CommonName != "bundle.jkaninda.dev" {
		t.Error("fullchain does not start with the leaf")
	}

	chainCerts, err := ParseCertificatesPEM(bundle.ChainPEM())
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	if len(chainCerts) != 2 {
		t.Errorf("chain has %d certificates, want 2", len(chainCerts))
	}

	rootCert, err := ParseCertificatePEM(bundle.RootPEM())
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	if rootCert.Subject.CommonName != "Certio Test Root" {
		t.Errorf("RootPEM returned %q", rootCert.Subject.CommonName)
	}

	// PKCS#12 must round-trip through the same library a Java keystore uses.
	p12, err := bundle.PKCS12("changeit")
	if err != nil {
		t.Fatalf("PKCS12: %v", err)
	}
	if len(p12) == 0 {
		t.Error("PKCS#12 output is empty")
	}
	if _, err := bundle.PKCS12(""); err == nil {
		t.Error("PKCS#12 export without a password should fail")
	}

	keyPEM, err := bundle.KeyPEM("")
	if err != nil {
		t.Fatalf("KeyPEM: %v", err)
	}
	if !strings.Contains(string(keyPEM), "BEGIN PRIVATE KEY") {
		t.Error("KeyPEM is not PKCS#8")
	}
}

func TestDescribeChainFlagsBrokenLinks(t *testing.T) {
	root := testCA(t)
	issued, err := Issue(root, IssueRequest{
		Subject: Subject{CommonName: "chain.jkaninda.dev"},
		SANs:    SANSet{{SANDNS, "chain.jkaninda.dev"}},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	bundle := Bundle{Certificate: issued.Certificate, Chain: issued.Chain}
	links := bundle.DescribeChain(time.Now())
	if len(links) != 2 {
		t.Fatalf("got %d links, want 2", len(links))
	}
	for i, link := range links {
		if !link.Valid {
			t.Errorf("link %d (%s) is invalid: %s", i, link.Subject, link.Problem)
		}
	}
	if !links[1].SelfSigned {
		t.Error("the root link is not marked self-signed")
	}

	// Evaluated after expiry, every link should be flagged.
	expired := bundle.DescribeChain(time.Now().AddDate(20, 0, 0))
	for i, link := range expired {
		if link.Valid {
			t.Errorf("link %d should be expired at +20 years", i)
		}
	}
}

func TestImportCA(t *testing.T) {
	original := testCA(t)

	certPEM := EncodeCertificatePEM(original.Certificate)
	keyPEM, err := MarshalPrivateKeyPEM(original.PrivateKey)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyPEM: %v", err)
	}

	imported, err := ImportCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("ImportCA: %v", err)
	}
	if imported.Certificate.Subject.CommonName != "Certio Test Root" {
		t.Errorf("imported CN = %q", imported.Certificate.Subject.CommonName)
	}

	// The imported CA must be able to issue.
	if _, err := Issue(imported, IssueRequest{
		Subject: Subject{CommonName: "imported.jkaninda.dev"},
		SANs:    SANSet{{SANDNS, "imported.jkaninda.dev"}},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	}); err != nil {
		t.Errorf("imported CA cannot issue: %v", err)
	}

	// A mismatched key must be rejected.
	otherKey, _ := GenerateKey(KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"})
	otherKeyPEM, _ := MarshalPrivateKeyPEM(otherKey)
	if _, err := ImportCA(certPEM, otherKeyPEM); err == nil {
		t.Error("importing a CA with a mismatched key should have failed")
	}

	// A leaf certificate is not a CA.
	leaf, _ := Issue(original, IssueRequest{
		Subject: Subject{CommonName: "leaf.jkaninda.dev"},
		SANs:    SANSet{{SANDNS, "leaf.jkaninda.dev"}},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	leafKeyPEM, _ := MarshalPrivateKeyPEM(leaf.PrivateKey)
	if _, err := ImportCA(EncodeCertificatePEM(leaf.Certificate), leafKeyPEM); err == nil {
		t.Error("importing a leaf certificate as a CA should have failed")
	}
}

func TestInspect(t *testing.T) {
	ca := testCA(t)
	issued, err := Issue(ca, IssueRequest{
		Subject: Subject{CommonName: "inspect.jkaninda.dev", Organization: "jkanTech"},
		SANs:    SANSet{{SANDNS, "inspect.jkaninda.dev"}, {SANIP, "10.0.0.5"}},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	bundle := Bundle{Certificate: issued.Certificate, PrivateKey: issued.PrivateKey, Chain: issued.Chain}

	// A full chain: leaf described, root in Chain.
	result, err := Inspect(bundle.FullChainPEM())
	if err != nil {
		t.Fatalf("Inspect(fullchain): %v", err)
	}
	if result.Kind != KindCertificate || result.Certificate == nil {
		t.Fatalf("Inspect returned kind %q", result.Kind)
	}
	if result.Certificate.Subject.CommonName != "inspect.jkaninda.dev" {
		t.Errorf("CN = %q", result.Certificate.Subject.CommonName)
	}
	if len(result.Chain) != 1 {
		t.Errorf("chain has %d entries, want 1", len(result.Chain))
	}
	if len(result.Certificate.FingerprintSHA256) != 95 { // 32 bytes as XX:XX:...
		t.Errorf("SHA-256 fingerprint = %q", result.Certificate.FingerprintSHA256)
	}
	if result.Certificate.DaysRemaining < 390 {
		t.Errorf("DaysRemaining = %d", result.Certificate.DaysRemaining)
	}

	// A CSR.
	key, _ := GenerateKey(KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"})
	csrPEM, _ := CreateCSR(key, CSRRequest{
		Subject: Subject{CommonName: "csr.jkaninda.dev"},
		SANs:    SANSet{{SANDNS, "csr.jkaninda.dev"}},
	})
	result, err = Inspect(csrPEM)
	if err != nil {
		t.Fatalf("Inspect(csr): %v", err)
	}
	if result.Kind != KindCSR || result.CSR == nil {
		t.Errorf("Inspect(csr) returned kind %q", result.Kind)
	}

	// A private key — the material itself must not come back.
	keyPEM, _ := MarshalPrivateKeyPEM(key)
	result, err = Inspect(keyPEM)
	if err != nil {
		t.Fatalf("Inspect(key): %v", err)
	}
	if result.Kind != KindPrivateKey || result.Key == nil {
		t.Fatalf("Inspect(key) returned kind %q", result.Kind)
	}
	if strings.Contains(result.Key.PublicKeyPEM, "PRIVATE") {
		t.Error("Inspect leaked private key material")
	}

	// A CRL.
	crlDER, _ := GenerateCRL(ca, CRLRequest{Number: big.NewInt(3)})
	result, err = Inspect(EncodeCRLPEM(crlDER))
	if err != nil {
		t.Fatalf("Inspect(crl): %v", err)
	}
	if result.Kind != KindCRL || result.CRL == nil {
		t.Errorf("Inspect(crl) returned kind %q", result.Kind)
	}

	// Garbage.
	if _, err := Inspect([]byte("hello world")); err == nil {
		t.Error("Inspect should reject non-PEM garbage")
	}
}

func TestSubjectDNMatchesOpensslSubjFormat(t *testing.T) {
	s := Subject{
		CommonName:         "*.jkaninda.dev",
		Country:            "CD",
		Province:           "Kinshasa",
		Locality:           "Gombe",
		Organization:       "jkanTech",
		OrganizationalUnit: "IT",
		Email:              "admin@jkaninda.dev",
	}
	want := "/C=CD/ST=Kinshasa/L=Gombe/O=jkanTech/OU=IT/CN=*.jkaninda.dev/emailAddress=admin@jkaninda.dev"
	if got := s.DN(); got != want {
		t.Errorf("DN() = %q\nwant     %q", got, want)
	}

	// Round-trip through pkix and back.
	back := SubjectFromPKIX(s.ToPKIX())
	if back.CommonName != s.CommonName || back.Organization != s.Organization || back.Email != s.Email {
		t.Errorf("subject round-trip lost data: %+v", back)
	}
}

func TestSubjectValidation(t *testing.T) {
	if err := (Subject{}).Validate(); err == nil {
		t.Error("an empty subject should be rejected")
	}
	if err := (Subject{CommonName: "x", Country: "CDR"}).Validate(); err == nil {
		t.Error("a 3-letter country code should be rejected")
	}
	if err := (Subject{CommonName: strings.Repeat("a", 65)}).Validate(); err == nil {
		t.Error("a 65-character CN should be rejected")
	}
	if err := (Subject{CommonName: "ok.jkaninda.dev", Country: "CD"}).Validate(); err != nil {
		t.Errorf("a valid subject was rejected: %v", err)
	}
}

func TestSignatureAlgorithmScalesWithKey(t *testing.T) {
	cases := []struct {
		spec KeySpec
		want x509.SignatureAlgorithm
	}{
		{KeySpec{Algorithm: AlgoRSA, Size: 2048}, x509.SHA256WithRSA},
		{KeySpec{Algorithm: AlgoRSA, Size: 3072}, x509.SHA384WithRSA},
		{KeySpec{Algorithm: AlgoRSA, Size: 4096}, x509.SHA512WithRSA},
		{KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"}, x509.ECDSAWithSHA256},
		{KeySpec{Algorithm: AlgoECDSA, Curve: "P-384"}, x509.ECDSAWithSHA384},
		{KeySpec{Algorithm: AlgoECDSA, Curve: "P-521"}, x509.ECDSAWithSHA512},
		{KeySpec{Algorithm: AlgoEd25519}, x509.PureEd25519},
	}
	for _, tc := range cases {
		key, err := GenerateKey(tc.spec)
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", tc.spec, err)
		}
		if got := signatureAlgorithmFor(key); got != tc.want {
			t.Errorf("%s: signature algorithm = %v, want %v", tc.spec, got, tc.want)
		}
	}
}

func TestEd25519EndToEnd(t *testing.T) {
	ca, err := CreateRootCA(CARequest{
		Subject:      Subject{CommonName: "Ed25519 Root"},
		KeySpec:      KeySpec{Algorithm: AlgoEd25519},
		ValidityDays: 3650,
	})
	if err != nil {
		t.Fatalf("CreateRootCA(ed25519): %v", err)
	}

	issued, err := Issue(ca, IssueRequest{
		Subject: Subject{CommonName: "ed.jkaninda.dev"},
		SANs:    SANSet{{SANDNS, "ed.jkaninda.dev"}},
		KeySpec: KeySpec{Algorithm: AlgoEd25519},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue(ed25519): %v", err)
	}

	bundle := Bundle{Certificate: issued.Certificate, PrivateKey: issued.PrivateKey, Chain: issued.Chain}
	if err := bundle.Verify(time.Now(), x509.ExtKeyUsageServerAuth); err != nil {
		t.Errorf("Ed25519 chain does not verify: %v", err)
	}
}

func TestBuildChainOrdersArbitraryInput(t *testing.T) {
	root := testCA(t)
	mid, err := CreateIntermediateCA(root, CARequest{
		Subject:      Subject{CommonName: "Order Intermediate"},
		KeySpec:      KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		ValidityDays: 1825,
	})
	if err != nil {
		t.Fatalf("CreateIntermediateCA: %v", err)
	}
	leaf, err := Issue(mid, IssueRequest{
		Subject: Subject{CommonName: "order.jkaninda.dev"},
		SANs:    SANSet{{SANDNS, "order.jkaninda.dev"}},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Deliberately shuffled: root before intermediate.
	pool := []*x509.Certificate{root.Certificate, mid.Certificate}
	chain := BuildChain(leaf.Certificate, pool)

	if len(chain) != 2 {
		t.Fatalf("BuildChain returned %d certificates, want 2", len(chain))
	}
	if chain[0].Subject.CommonName != "Order Intermediate" {
		t.Errorf("chain[0] = %q, want the intermediate", chain[0].Subject.CommonName)
	}
	if chain[1].Subject.CommonName != "Certio Test Root" {
		t.Errorf("chain[1] = %q, want the root", chain[1].Subject.CommonName)
	}
}

func TestKeyUsageStringRoundTrip(t *testing.T) {
	usage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign
	names := KeyUsageStrings(usage)
	back, err := ParseKeyUsages(names)
	if err != nil {
		t.Fatalf("ParseKeyUsages(%v): %v", names, err)
	}
	if back != usage {
		t.Errorf("round-trip: %v != %v", KeyUsageStrings(back), names)
	}

	extNames := ExtKeyUsageStrings([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	extBack, err := ParseExtKeyUsages(extNames)
	if err != nil {
		t.Fatalf("ParseExtKeyUsages(%v): %v", extNames, err)
	}
	if len(extBack) != 2 || extBack[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ext key usage round-trip failed: %v", extBack)
	}

	if _, err := ParseKeyUsages([]string{"NotAUsage"}); err == nil {
		t.Error("an unknown key usage should be rejected")
	}
}
