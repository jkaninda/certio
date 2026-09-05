package service

import (
	"strings"
	"testing"

	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/store"
)

// gomaFixture issues a wildcard certificate and returns it with its bundle.
func gomaFixture(t *testing.T, s *Service, profile string) (*store.Certificate, pki.Bundle) {
	t.Helper()
	ca := createRoot(t, s, "")

	issued, err := s.Issue(testActor(), IssueInput{
		AuthorityID: ca.ID,
		Subject:     pki.Subject{CommonName: "*.jkaninda.dev"},
		SANs: pki.SANSet{
			{Type: pki.SANDNS, Value: "jkaninda.dev"},
			{Type: pki.SANDNS, Value: "*.jkaninda.dev"},
			// An IP SAN must not leak into a YAML host list.
			{Type: pki.SANIP, Value: "10.0.0.1"},
		},
		Profile: profile,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	bundle, cert, err := s.LoadBundle(issued.Certificate.ID, false)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	return cert, bundle
}

func TestGomaGlobalConfig(t *testing.T) {
	s := newTestService(t)
	cert, bundle := gomaFixture(t, s, pki.ProfileServer)

	export, err := s.ExportCertificate(cert, bundle, ExportOptions{Format: FormatGoma})
	if err != nil {
		t.Fatalf("ExportCertificate: %v", err)
	}
	out := string(export.Data)

	for _, want := range []string{
		"version: 2",
		"gateway:",
		"  tls:",
		"    certificates:",
		"      - cert: /etc/goma/certs/jkaninda.dev-fullchain.pem",
		"        key: /etc/goma/certs/jkaninda.dev.key",
		// The directory-based alternative is offered, commented out.
		"# certsDir: /etc/goma/certs",
		// And the default fallback block.
		"# default:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the Goma config is missing %q:\n%s", want, out)
		}
	}

	// The SNI hosts this certificate covers are listed so the operator can see
	// what it will match.
	for _, name := range []string{"jkaninda.dev", "*.jkaninda.dev"} {
		if !strings.Contains(out, name) {
			t.Errorf("the Goma config does not mention %q", name)
		}
	}

	if !strings.HasSuffix(export.Filename, "-goma.yml") {
		t.Errorf("filename = %q", export.Filename)
	}
	if export.ContentType != "application/yaml" {
		t.Errorf("content type = %q", export.ContentType)
	}
}

func TestGomaRouteConfig(t *testing.T) {
	s := newTestService(t)
	cert, bundle := gomaFixture(t, s, pki.ProfileServer)

	export, err := s.ExportCertificate(cert, bundle, ExportOptions{Format: FormatGomaRoute})
	if err != nil {
		t.Fatalf("ExportCertificate: %v", err)
	}
	out := string(export.Data)

	for _, want := range []string{
		"version: 2",
		"  routes:",
		"    - path: /",
		"      name: jkaninda.dev",
		"      backends:",
		"        - endpoint:",
		"      tls:",
		// Singular and a mapping: a route carries one certificate. The list
		// form belongs to the gateway-wide block, and Goma would not bind it
		// here.
		"        certificate:",
		"          cert: /etc/goma/certs/jkaninda.dev-fullchain.pem",
		"          key: /etc/goma/certs/jkaninda.dev.key",
		// Otherwise a gateway with a certificate manager would also order an
		// ACME certificate for these hosts.
		"        provider: none",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the Goma route config is missing %q:\n%s", want, out)
		}
	}

	// The list form is what this used to emit and what Goma rejects here.
	if strings.Contains(out, "        certificates:") {
		t.Errorf("the route block uses the gateway-wide list form:\n%s", out)
	}

	// Hosts must be a quoted flow sequence: an unquoted wildcard is invalid YAML.
	if !strings.Contains(out, `hosts: ["jkaninda.dev", "*.jkaninda.dev"]`) {
		t.Errorf("hosts are not a correctly quoted YAML list:\n%s", out)
	}
	// An IP SAN is not a host name and must not appear in the list.
	if strings.Contains(out, `"10.0.0.1"`) {
		t.Errorf("an IP SAN leaked into the host list:\n%s", out)
	}
}

func TestGomaRouteMentionsMutualTLSForPeerProfiles(t *testing.T) {
	s := newTestService(t)

	// A server certificate is presented, not verified, so no mTLS hint.
	serverCert, serverBundle := gomaFixture(t, s, pki.ProfileServer)
	serverOut, err := s.ExportCertificate(serverCert, serverBundle, ExportOptions{Format: FormatGomaRoute})
	if err != nil {
		t.Fatalf("ExportCertificate: %v", err)
	}
	if strings.Contains(string(serverOut.Data), "rootCAs") {
		t.Error("a server-profile route suggests mutual TLS")
	}

	// A peer certificate carries clientAuth, so the snippet points at it —
	// both the route knob for presenting it to the backend and the
	// gateway-wide one for verifying callers, which are different settings and
	// were previously conflated.
	peerCert, peerBundle := gomaFixture(t, s, pki.ProfilePeer)
	peerOut, err := s.ExportCertificate(peerCert, peerBundle, ExportOptions{Format: FormatGomaRoute})
	if err != nil {
		t.Fatalf("ExportCertificate: %v", err)
	}
	for _, want := range []string{"clientCert:", "clientKey:", "rootCAs:", "clientAuth:", "clientCA:"} {
		if !strings.Contains(string(peerOut.Data), want) {
			t.Errorf("a peer-profile route does not mention %q:\n%s", want, peerOut.Data)
		}
	}
}
