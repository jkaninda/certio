package pki

import (
	"crypto/x509"
	"net"
	"strings"
	"testing"
)

// TestPermitsDNS covers the RFC 5280 matching rule, whose sharp edge is that
// the boundary must fall on a label: a constraint on "example.com" must not
// quietly cover "notexample.com".
func TestPermitsDNS(t *testing.T) {
	n := NameConstraints{
		PermittedDNS: []string{"corp.example.com", ".lab.example.com"},
		ExcludedDNS:  []string{"secret.corp.example.com"},
	}

	cases := map[string]bool{
		"corp.example.com":          true,
		"api.corp.example.com":      true,
		"a.b.corp.example.com":      true,
		"*.corp.example.com":        true,
		"lab.example.com":           true,
		"host.lab.example.com":      true,
		"secret.corp.example.com":   false,
		"a.secret.corp.example.com": false,
		"example.com":               false,
		"notcorp.example.com":       false,
		"corp.example.com.evil.io":  false,
		"":                          false,
	}
	for name, want := range cases {
		if got := n.PermitsDNS(name); got != want {
			t.Errorf("PermitsDNS(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestPermitsDNSUnconstrained checks that an empty permitted list means "any",
// while an exclusion still bites.
func TestPermitsDNSUnconstrained(t *testing.T) {
	n := NameConstraints{ExcludedDNS: []string{"example.com"}}
	if !n.PermitsDNS("anything.io") {
		t.Error("an empty permitted list should allow anything not excluded")
	}
	if n.PermitsDNS("api.example.com") {
		t.Error("the exclusion was not applied")
	}
}

// TestPermitsIP covers CIDR containment in both directions.
func TestPermitsIP(t *testing.T) {
	n := NameConstraints{
		PermittedIP: []string{"10.0.0.0/8", "192.168.1.0/24"},
		ExcludedIP:  []string{"10.99.0.0/16"},
	}
	cases := map[string]bool{
		"10.1.2.3":     true,
		"192.168.1.7":  true,
		"10.99.0.1":    false,
		"192.168.2.7":  false,
		"172.16.0.1":   false,
		"203.0.113.10": false,
	}
	for ip, want := range cases {
		if got := n.PermitsIP(net.ParseIP(ip)); got != want {
			t.Errorf("PermitsIP(%s) = %v, want %v", ip, got, want)
		}
	}
	if n.PermitsIP(nil) {
		t.Error("a nil IP was permitted")
	}
}

// TestPermitsEmail covers the three shapes a constraint may take.
func TestPermitsEmail(t *testing.T) {
	n := NameConstraints{PermittedEmail: []string{"example.com", "ops@other.io"}}
	cases := map[string]bool{
		"someone@example.com": true,
		"ops@other.io":        true,
		"someone@other.io":    false,
		"a@sub.example.com":   false, // a bare host constraint is exact
		"not-an-address":      false,
	}
	for address, want := range cases {
		if got := n.PermitsEmail(address); got != want {
			t.Errorf("PermitsEmail(%q) = %v, want %v", address, got, want)
		}
	}

	sub := NameConstraints{PermittedEmail: []string{".example.com"}}
	if !sub.PermitsEmail("a@sub.example.com") {
		t.Error("a leading-dot constraint should cover subdomains")
	}
}

// TestValidateRejectsBadConstraints checks the guard that keeps a CA from
// being minted with an extension no verifier can parse.
func TestValidateRejectsBadConstraints(t *testing.T) {
	if err := (NameConstraints{PermittedIP: []string{"10.0.0.1"}}).Validate(); err == nil {
		t.Error("Validate accepted a bare IP where a CIDR is required")
	}
	if err := (NameConstraints{PermittedDNS: []string{"*.example.com"}}).Validate(); err == nil {
		t.Error("Validate accepted a wildcard DNS constraint")
	}
	if err := (NameConstraints{PermittedDNS: []string{"example.com"}, PermittedIP: []string{"10.0.0.0/8"}}).Validate(); err != nil {
		t.Errorf("Validate rejected a well-formed set: %v", err)
	}
}

// TestConstrainedCAIsEnforcedByVerification is the test that matters: build a
// constrained root, issue under it, and let crypto/x509 — the same code every
// Go client uses — decide. If this passes, the constraint is real rather than
// decorative.
func TestConstrainedCAIsEnforcedByVerification(t *testing.T) {
	ca, err := CreateRootCA(CARequest{
		Subject:      Subject{CommonName: "Constrained Root", Organization: "jkanTech", Country: "CD"},
		KeySpec:      KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		ValidityDays: 3650,
		NameConstraints: NameConstraints{
			PermittedDNS: []string{"corp.example.com"},
			PermittedIP:  []string{"10.0.0.0/8"},
		},
	})
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	if !ca.Certificate.PermittedDNSDomainsCritical {
		t.Error("the name-constraints extension is not marked critical, so a verifier may ignore it")
	}
	if got := ConstraintsOf(ca.Certificate); len(got.PermittedDNS) != 1 || got.PermittedDNS[0] != "corp.example.com" {
		t.Errorf("ConstraintsOf did not read the extension back: %+v", got)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)

	inside, err := Issue(ca, IssueRequest{
		Subject: Subject{CommonName: "api.corp.example.com"},
		SANs:    SANSet{{Type: SANDNS, Value: "api.corp.example.com"}},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue inside the constraint: %v", err)
	}
	if _, err := inside.Certificate.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: "api.corp.example.com",
	}); err != nil {
		t.Errorf("a permitted name failed verification: %v", err)
	}

	// The engine will happily sign this — the constraint lives in the CA, not
	// in the signing step — and the verifier is what refuses it. That is
	// exactly why the service layer checks first, so the operator sees the
	// problem at issuance rather than in a browser.
	outside, err := Issue(ca, IssueRequest{
		Subject: Subject{CommonName: "evil.example.org"},
		SANs:    SANSet{{Type: SANDNS, Value: "evil.example.org"}},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue outside the constraint: %v", err)
	}
	if _, err := outside.Certificate.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: "evil.example.org",
	}); err == nil {
		t.Fatal("crypto/x509 accepted a name outside the CA's constraints")
	}
}

// TestPermitsSANsNamesTheOffender checks that the error points at the entry to
// remove rather than saying the request was rejected.
func TestPermitsSANsNamesTheOffender(t *testing.T) {
	n := NameConstraints{PermittedDNS: []string{"corp.example.com"}}

	err := n.PermitsSANs(SANSet{
		{Type: SANDNS, Value: "api.corp.example.com"},
		{Type: SANDNS, Value: "api.example.org"},
	})
	if err == nil {
		t.Fatal("PermitsSANs accepted an out-of-scope name")
	}
	if want := "api.example.org"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want it to name %q", err, want)
	}

	if err := (NameConstraints{}).PermitsSANs(SANSet{{Type: SANDNS, Value: "anything.io"}}); err != nil {
		t.Errorf("an unconstrained CA rejected a name: %v", err)
	}
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
