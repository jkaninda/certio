package pki

import (
	"crypto"
	// SHA-1 is not a choice here: RFC 6960 specifies it for the CertID issuer
	// hashes, and a client that sends one gets no answer if the algorithm is
	// not linked in. It is used to match an identifier, never to sign.
	_ "crypto/sha1" //nolint:gosec // G505: RFC 6960 specifies SHA-1 for CertID
	_ "crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSP status values, re-exported so callers need not import x/crypto.
const (
	OCSPGood    = ocsp.Good
	OCSPRevoked = ocsp.Revoked
	OCSPUnknown = ocsp.Unknown
)

// RFC 6960 unsigned error responses. They carry no signature by design: there
// is nothing yet to attest to.
var (
	OCSPMalformedRequest = ocsp.MalformedRequestErrorResponse
	OCSPInternalError    = ocsp.InternalErrorErrorResponse
	OCSPTryLater         = ocsp.TryLaterErrorResponse
	OCSPUnauthorized     = ocsp.UnauthorizedErrorResponse
)

// OCSPRequest is a decoded status query: which serial, issued by whom.
type OCSPRequest struct {
	SerialNumber *big.Int
	// IssuerKeyHash and IssuerNameHash identify the issuer without naming it,
	// which is how a responder serving several CAs tells them apart.
	IssuerKeyHash  []byte
	IssuerNameHash []byte
	// HashAlgorithm is the digest the client hashed those with. The response
	// has to echo the same one, or the client cannot match the answer to its
	// question.
	HashAlgorithm crypto.Hash
}

// ParseOCSPRequest decodes a DER request body.
func ParseOCSPRequest(der []byte) (*OCSPRequest, error) {
	req, err := ocsp.ParseRequest(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse OCSP request: %w", err)
	}
	hash := req.HashAlgorithm
	if hash == 0 {
		hash = crypto.SHA1
	}
	return &OCSPRequest{
		SerialNumber:   req.SerialNumber,
		IssuerKeyHash:  req.IssuerKeyHash,
		IssuerNameHash: req.IssuerNameHash,
		HashAlgorithm:  hash,
	}, nil
}

// MatchesIssuer reports whether the request is asking about a certificate this
// CA issued. Answering for a serial belonging to some other CA would be
// asserting something Certio has no standing to assert — and, worse, a "good"
// for a serial that CA revoked.
func (r *OCSPRequest) MatchesIssuer(issuer *x509.Certificate) bool {
	if r == nil || issuer == nil || !r.HashAlgorithm.Available() {
		return false
	}
	nameHash, keyHash, err := ocspIssuerHashes(issuer, r.HashAlgorithm)
	if err != nil {
		return false
	}
	return equalBytes(nameHash, r.IssuerNameHash) && equalBytes(keyHash, r.IssuerKeyHash)
}

// ocspIssuerHashes computes the CertID issuer hashes RFC 6960 §4.1.1 defines:
// a digest over the issuer's DER subject, and one over the raw bits of its
// public key — not over the whole SubjectPublicKeyInfo.
func ocspIssuerHashes(issuer *x509.Certificate, hash crypto.Hash) (nameHash, keyHash []byte, err error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, nil, fmt.Errorf("pki: decode issuer public key: %w", err)
	}

	h := hash.New()
	h.Write(spki.PublicKey.RightAlign())
	keyHash = h.Sum(nil)

	h.Reset()
	h.Write(issuer.RawSubject)
	nameHash = h.Sum(nil)

	return nameHash, keyHash, nil
}

// OCSPResponse describes the answer to give.
type OCSPResponse struct {
	SerialNumber *big.Int
	// Status is OCSPGood, OCSPRevoked or OCSPUnknown.
	Status int
	// RevokedAt and ReasonCode are read only when Status is OCSPRevoked.
	RevokedAt  time.Time
	ReasonCode int
	// ThisUpdate and NextUpdate bound how long a client may cache the answer.
	ThisUpdate time.Time
	NextUpdate time.Time
	// IssuerHash must be the algorithm the request used, so the response's
	// CertID matches the one the client asked with. Zero means SHA-1.
	IssuerHash crypto.Hash
}

// SignOCSPResponse produces a DER response signed by the CA itself.
//
// Certio signs directly with the CA key rather than minting a delegated
// responder certificate. A delegated signer is the right answer when the CA
// key lives in an HSM the web process must not reach — but Certio already
// holds that key in this process to issue certificates and sign CRLs, so a
// delegated certificate would add a second credential to rotate and protect no
// additional key material.
func SignOCSPResponse(ca *CertificateAuthority, resp OCSPResponse) ([]byte, error) {
	if ca == nil || ca.Certificate == nil || ca.PrivateKey == nil {
		return nil, errors.New("pki: an issuing CA with its private key is required")
	}
	if resp.SerialNumber == nil {
		return nil, errors.New("pki: an OCSP response needs a serial number")
	}

	thisUpdate := resp.ThisUpdate
	if thisUpdate.IsZero() {
		thisUpdate = time.Now()
	}
	nextUpdate := resp.NextUpdate
	if nextUpdate.IsZero() {
		nextUpdate = thisUpdate.Add(24 * time.Hour)
	}
	issuerHash := resp.IssuerHash
	if issuerHash == 0 {
		issuerHash = crypto.SHA1
	}

	template := ocsp.Response{
		Status:       resp.Status,
		SerialNumber: resp.SerialNumber,
		ThisUpdate:   thisUpdate.UTC(),
		NextUpdate:   nextUpdate.UTC(),
		IssuerHash:   issuerHash,
		// The request's CertID may be SHA-1 — RFC 6960 says so — but nothing
		// drags the response *signature* down with it.
		SignatureAlgorithm: ocspSignatureAlgorithm(ca.PrivateKey),
	}
	if resp.Status == OCSPRevoked {
		template.RevokedAt = resp.RevokedAt.UTC()
		template.RevocationReason = resp.ReasonCode
	}

	// Issuer and responder are the same certificate: this is a directly signed
	// response, so there is no delegated certificate to embed.
	der, err := ocsp.CreateResponse(ca.Certificate, ca.Certificate, template, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("pki: sign OCSP response: %w", err)
	}
	return der, nil
}

// ocspSignatureAlgorithm picks a signature algorithm for the CA's key type.
// Ed25519 has no OCSP-registered algorithm, so it returns zero and lets
// x/crypto fall back to the key's default.
func ocspSignatureAlgorithm(key crypto.Signer) x509.SignatureAlgorithm {
	switch signatureAlgorithmFor(key) {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		return x509.SHA256WithRSA
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return x509.ECDSAWithSHA256
	default:
		return 0
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
