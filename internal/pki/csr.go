package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// CSRRequest describes a certificate signing request to create.
type CSRRequest struct {
	Subject Subject
	SANs    SANSet
}

// CreateCSR builds and signs a PKCS#10 request with an existing key.
func CreateCSR(key crypto.Signer, req CSRRequest) ([]byte, error) {
	req.Subject = req.Subject.Normalize()
	if err := req.Subject.Validate(); err != nil {
		return nil, err
	}

	sans := req.SANs.AddDNS(req.Subject.CommonName)
	if err := sans.Validate(); err != nil {
		return nil, err
	}
	dnsNames, ips, emails, uris, err := sans.Split()
	if err != nil {
		return nil, err
	}

	template := &x509.CertificateRequest{
		Subject:            req.Subject.ToPKIX(),
		DNSNames:           dnsNames,
		IPAddresses:        ips,
		EmailAddresses:     emails,
		URIs:               uris,
		SignatureAlgorithm: signatureAlgorithmFor(key),
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("pki: create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: BlockCertificateReq, Bytes: der}), nil
}

// CertificateRequest aliases x509.CertificateRequest so callers can work with
// this package without importing crypto/x509 alongside it.
type CertificateRequest = x509.CertificateRequest

// ParseCSRDER parses a raw DER certificate request — the form ACME carries a
// CSR in, base64url-encoded rather than PEM-wrapped.
func ParseCSRDER(der []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: the CSR signature does not verify: %w", err)
	}
	return csr, nil
}

// EncodeCSRPEM wraps a DER certificate request in a PEM block.
func EncodeCSRPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: BlockCertificateReq, Bytes: der})
}

// ParseCSR decodes and verifies a PEM or DER certificate signing request. The
// self-signature is always checked: an unverified CSR proves nothing about
// possession of the private key.
func ParseCSR(data []byte) (*x509.CertificateRequest, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		switch block.Type {
		case BlockCertificateReq, BlockNewCertReq:
			der = block.Bytes
		default:
			return nil, fmt.Errorf("pki: expected a CERTIFICATE REQUEST block, got %q", block.Type)
		}
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: CSR signature is invalid: %w", err)
	}
	return csr, nil
}

// CSRDetails is the parsed view of a CSR shown for confirmation before signing.
type CSRDetails struct {
	Subject            Subject `json:"subject"`
	SANs               SANSet  `json:"sans"`
	KeyAlgorithm       string  `json:"key_algorithm"`
	KeySize            int     `json:"key_size,omitempty"`
	SignatureAlgorithm string  `json:"signature_algorithm"`
	DN                 string  `json:"dn"`
}

// DescribeCSR summarises a CSR for the confirmation step of the BYO-CSR flow.
func DescribeCSR(csr *x509.CertificateRequest) (CSRDetails, error) {
	spec, err := SpecOf(csr.PublicKey)
	if err != nil {
		return CSRDetails{}, err
	}
	subject := SubjectFromPKIX(csr.Subject)
	return CSRDetails{
		Subject:            subject,
		SANs:               SANsFromCertificateLike(csr.DNSNames, csr.IPAddresses, csr.EmailAddresses, csr.URIs),
		KeyAlgorithm:       spec.String(),
		KeySize:            spec.Size,
		SignatureAlgorithm: csr.SignatureAlgorithm.String(),
		DN:                 subject.DN(),
	}, nil
}

// ValidateCSRForSigning rejects requests Certio will not sign: a weak key, a
// missing subject, or SANs that fail validation.
func ValidateCSRForSigning(csr *x509.CertificateRequest) error {
	if csr == nil {
		return errors.New("pki: no CSR supplied")
	}
	spec, err := SpecOf(csr.PublicKey)
	if err != nil {
		return err
	}
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("pki: CSR uses a key Certio will not sign: %w", err)
	}
	if csr.Subject.CommonName == "" && len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) == 0 {
		return errors.New("pki: CSR has neither a common name nor any SANs")
	}
	sans := SANsFromCertificateLike(csr.DNSNames, csr.IPAddresses, csr.EmailAddresses, csr.URIs)
	for _, san := range sans {
		if err := san.Validate(); err != nil {
			return err
		}
	}
	return nil
}
