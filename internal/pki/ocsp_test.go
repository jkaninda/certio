package pki

import (
	"crypto"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// issueLeaf signs a throwaway end-entity certificate under ca.
func issueLeaf(t *testing.T, ca *CertificateAuthority) *Certificate {
	t.Helper()
	issued, err := Issue(ca, IssueRequest{
		Subject: Subject{CommonName: "api.example.com"},
		SANs:    SANSet{{Type: "dns", Value: "api.example.com"}},
		KeySpec: KeySpec{Algorithm: AlgoECDSA, Curve: "P-256"},
		Profile: ProfileServer,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return issued.Certificate
}

// TestOCSPGoodResponse walks the whole exchange the way a TLS client does:
// build a request, answer it, then verify the answer against the issuer.
func TestOCSPGoodResponse(t *testing.T) {
	ca := testCA(t)
	leaf := issueLeaf(t, ca)

	reqDER, err := ocsp.CreateRequest(leaf, ca.Certificate, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	parsed, err := ParseOCSPRequest(reqDER)
	if err != nil {
		t.Fatalf("ParseOCSPRequest: %v", err)
	}
	if parsed.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Errorf("serial = %v, want %v", parsed.SerialNumber, leaf.SerialNumber)
	}
	if !parsed.MatchesIssuer(ca.Certificate) {
		t.Fatal("MatchesIssuer said the request was for a different CA")
	}

	respDER, err := SignOCSPResponse(ca, OCSPResponse{
		SerialNumber: parsed.SerialNumber,
		Status:       OCSPGood,
		IssuerHash:   parsed.HashAlgorithm,
	})
	if err != nil {
		t.Fatalf("SignOCSPResponse: %v", err)
	}

	// ParseResponseForCert is the strict path: it checks the signature *and*
	// that the CertID matches the certificate that was asked about.
	resp, err := ocsp.ParseResponseForCert(respDER, leaf, ca.Certificate)
	if err != nil {
		t.Fatalf("ParseResponseForCert: %v", err)
	}
	if resp.Status != ocsp.Good {
		t.Errorf("status = %d, want Good", resp.Status)
	}
	if !resp.NextUpdate.After(resp.ThisUpdate) {
		t.Error("nextUpdate is not after thisUpdate, so the answer is uncacheable")
	}
}

// TestOCSPRevokedResponse checks that the reason code survives the round trip,
// since that is what a client shows the user.
func TestOCSPRevokedResponse(t *testing.T) {
	ca := testCA(t)
	leaf := issueLeaf(t, ca)
	revokedAt := time.Now().Add(-time.Hour).Truncate(time.Second)

	respDER, err := SignOCSPResponse(ca, OCSPResponse{
		SerialNumber: leaf.SerialNumber,
		Status:       OCSPRevoked,
		RevokedAt:    revokedAt,
		ReasonCode:   ReasonKeyCompromise,
	})
	if err != nil {
		t.Fatalf("SignOCSPResponse: %v", err)
	}

	resp, err := ocsp.ParseResponseForCert(respDER, leaf, ca.Certificate)
	if err != nil {
		t.Fatalf("ParseResponseForCert: %v", err)
	}
	if resp.Status != ocsp.Revoked {
		t.Fatalf("status = %d, want Revoked", resp.Status)
	}
	if resp.RevocationReason != ReasonKeyCompromise {
		t.Errorf("reason = %d, want %d", resp.RevocationReason, ReasonKeyCompromise)
	}
	if !resp.RevokedAt.Equal(revokedAt.UTC()) {
		t.Errorf("revokedAt = %v, want %v", resp.RevokedAt, revokedAt.UTC())
	}
}

// TestOCSPRequestIssuerMismatch is the check that keeps the responder from
// vouching for a serial some other CA issued.
func TestOCSPRequestIssuerMismatch(t *testing.T) {
	ca := testCA(t)
	other := testCA(t)
	leaf := issueLeaf(t, ca)

	reqDER, err := ocsp.CreateRequest(leaf, ca.Certificate, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	parsed, err := ParseOCSPRequest(reqDER)
	if err != nil {
		t.Fatalf("ParseOCSPRequest: %v", err)
	}

	if parsed.MatchesIssuer(other.Certificate) {
		t.Error("MatchesIssuer accepted a request naming a different CA")
	}
}

// TestOCSPEchoesTheRequestHash checks that a SHA-256 CertID comes back as
// SHA-256. Answering with a SHA-1 CertID would leave the client unable to
// match the response to the question it asked.
func TestOCSPEchoesTheRequestHash(t *testing.T) {
	ca := testCA(t)
	leaf := issueLeaf(t, ca)

	reqDER, err := ocsp.CreateRequest(leaf, ca.Certificate, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	parsed, err := ParseOCSPRequest(reqDER)
	if err != nil {
		t.Fatalf("ParseOCSPRequest: %v", err)
	}
	if parsed.HashAlgorithm != crypto.SHA256 {
		t.Fatalf("HashAlgorithm = %v, want SHA-256", parsed.HashAlgorithm)
	}

	respDER, err := SignOCSPResponse(ca, OCSPResponse{
		SerialNumber: parsed.SerialNumber,
		Status:       OCSPGood,
		IssuerHash:   parsed.HashAlgorithm,
	})
	if err != nil {
		t.Fatalf("SignOCSPResponse: %v", err)
	}
	if _, err := ocsp.ParseResponseForCert(respDER, leaf, ca.Certificate); err != nil {
		t.Fatalf("a SHA-256 request was answered with an unmatchable CertID: %v", err)
	}
}

// TestOCSPRejectsIncompleteInput checks the guards, since a nil dereference in
// a public endpoint is worth a test of its own.
func TestOCSPRejectsIncompleteInput(t *testing.T) {
	ca := testCA(t)

	if _, err := SignOCSPResponse(nil, OCSPResponse{SerialNumber: big.NewInt(1)}); err == nil {
		t.Error("SignOCSPResponse accepted a nil CA")
	}
	if _, err := SignOCSPResponse(ca, OCSPResponse{}); err == nil {
		t.Error("SignOCSPResponse accepted a response with no serial number")
	}
	if _, err := ParseOCSPRequest([]byte("not DER")); err == nil {
		t.Error("ParseOCSPRequest accepted garbage")
	}

	var nilReq *OCSPRequest
	if nilReq.MatchesIssuer(ca.Certificate) {
		t.Error("a nil request matched an issuer")
	}
}
