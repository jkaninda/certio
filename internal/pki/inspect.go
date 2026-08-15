package pki

import (
	"crypto/sha1" //nolint:gosec // SHA-1 fingerprints are still what tooling prints
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// Detected input kinds for the inspect endpoint.
const (
	KindCertificate = "certificate"
	KindCSR         = "csr"
	KindPrivateKey  = "private_key"
	KindCRL         = "crl"
	KindPublicKey   = "public_key"
)

// CertificateDetails is the decoded view of a certificate, shaped for both the
// inspect page and the certificate detail page.
type CertificateDetails struct {
	Kind               string    `json:"kind"`
	Subject            Subject   `json:"subject"`
	SubjectDN          string    `json:"subject_dn"`
	Issuer             Subject   `json:"issuer"`
	IssuerDN           string    `json:"issuer_dn"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DaysRemaining      int       `json:"days_remaining"`
	Expired            bool      `json:"expired"`
	SelfSigned         bool      `json:"self_signed"`
	IsCA               bool      `json:"is_ca"`
	MaxPathLen         int       `json:"max_path_len,omitempty"`
	SANs               SANSet    `json:"sans"`
	KeyAlgorithm       string    `json:"key_algorithm"`
	KeySize            int       `json:"key_size,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	KeyUsage           []string  `json:"key_usage"`
	ExtKeyUsage        []string  `json:"ext_key_usage"`
	FingerprintSHA256  string    `json:"fingerprint_sha256"`
	FingerprintSHA1    string    `json:"fingerprint_sha1"`
	SubjectKeyID       string    `json:"subject_key_id,omitempty"`
	AuthorityKeyID     string    `json:"authority_key_id,omitempty"`
	CRLDistribution    []string  `json:"crl_distribution_points,omitempty"`
	OCSPServer         []string  `json:"ocsp_servers,omitempty"`
	Profile            string    `json:"profile"`
	PEM                string    `json:"pem"`
}

// DescribeCertificate decodes a certificate into its API representation.
func DescribeCertificate(cert *x509.Certificate) CertificateDetails {
	spec, _ := SpecOf(cert.PublicKey)
	subject := SubjectFromPKIX(cert.Subject)
	issuer := SubjectFromPKIX(cert.Issuer)

	sha256Sum := sha256.Sum256(cert.Raw)
	sha1Sum := sha1.Sum(cert.Raw) //nolint:gosec // fingerprint display only

	now := time.Now()
	return CertificateDetails{
		Kind:               KindCertificate,
		Subject:            subject,
		SubjectDN:          subject.DN(),
		Issuer:             issuer,
		IssuerDN:           issuer.DN(),
		SerialNumber:       FormatSerial(cert.SerialNumber),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DaysRemaining:      int(cert.NotAfter.Sub(now).Hours() / 24),
		Expired:            now.After(cert.NotAfter),
		SelfSigned:         isSelfSigned(cert),
		IsCA:               cert.IsCA,
		MaxPathLen:         cert.MaxPathLen,
		SANs:               SANsFromCertificateLike(cert.DNSNames, cert.IPAddresses, cert.EmailAddresses, cert.URIs),
		KeyAlgorithm:       spec.Display(),
		KeySize:            spec.Size,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		KeyUsage:           KeyUsageStrings(cert.KeyUsage),
		ExtKeyUsage:        ExtKeyUsageStrings(cert.ExtKeyUsage),
		FingerprintSHA256:  colonHex(sha256Sum[:]),
		FingerprintSHA1:    colonHex(sha1Sum[:]),
		SubjectKeyID:       colonHex(cert.SubjectKeyId),
		AuthorityKeyID:     colonHex(cert.AuthorityKeyId),
		CRLDistribution:    cert.CRLDistributionPoints,
		OCSPServer:         cert.OCSPServer,
		Profile:            InferProfile(cert),
		PEM:                string(EncodeCertificatePEM(cert)),
	}
}

// Fingerprint returns the SHA-256 fingerprint of a certificate as plain
// lowercase hex, which is the form stored in the database.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// colonHex renders bytes as the colon-separated uppercase hex that openssl and
// browsers display for fingerprints and key identifiers.
func colonHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":")
}

// InspectResult is the discriminated union returned by the inspect endpoint.
// Exactly one of the pointer fields is set.
type InspectResult struct {
	Kind        string              `json:"kind"`
	Certificate *CertificateDetails `json:"certificate,omitempty"`
	CSR         *CSRDetails         `json:"csr,omitempty"`
	Key         *KeyDetails         `json:"key,omitempty"`
	CRL         *CRLDetails         `json:"crl,omitempty"`
	// Chain holds the remaining certificates when a full chain was pasted.
	Chain []CertificateDetails `json:"chain,omitempty"`
}

// KeyDetails describes a private key without revealing any of its material.
type KeyDetails struct {
	Kind         string `json:"kind"`
	KeyAlgorithm string `json:"key_algorithm"`
	KeySize      int    `json:"key_size,omitempty"`
	PublicKeyPEM string `json:"public_key_pem"`
}

// CRLDetails describes a parsed revocation list.
type CRLDetails struct {
	Kind       string           `json:"kind"`
	Issuer     string           `json:"issuer"`
	Number     string           `json:"number"`
	ThisUpdate time.Time        `json:"this_update"`
	NextUpdate time.Time        `json:"next_update"`
	Entries    []CRLEntryDetail `json:"entries"`
}

// CRLEntryDetail is one revoked certificate in a parsed CRL.
type CRLEntryDetail struct {
	SerialNumber string    `json:"serial_number"`
	RevokedAt    time.Time `json:"revoked_at"`
	Reason       string    `json:"reason"`
	ReasonCode   int       `json:"reason_code"`
}

// Inspect decodes any PEM document a user might paste — certificate, chain,
// CSR, key or CRL — and returns a structured description. Nothing is persisted.
func Inspect(data []byte) (*InspectResult, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("pki: nothing to inspect")
	}

	block, _ := pem.Decode([]byte(trimmed))
	if block == nil {
		// Not PEM — try DER for each supported type before giving up.
		return inspectDER([]byte(trimmed))
	}

	switch {
	case block.Type == BlockCertificate:
		certs, err := ParseCertificatesPEM([]byte(trimmed))
		if err != nil {
			return nil, err
		}
		leaf := DescribeCertificate(certs[0])
		result := &InspectResult{Kind: KindCertificate, Certificate: &leaf}
		for _, c := range certs[1:] {
			result.Chain = append(result.Chain, DescribeCertificate(c))
		}
		return result, nil

	case block.Type == BlockCertificateReq || block.Type == BlockNewCertReq:
		csr, err := ParseCSR([]byte(trimmed))
		if err != nil {
			return nil, err
		}
		details, err := DescribeCSR(csr)
		if err != nil {
			return nil, err
		}
		return &InspectResult{Kind: KindCSR, CSR: &details}, nil

	case block.Type == BlockCRL:
		crl, err := ParseCRL([]byte(trimmed))
		if err != nil {
			return nil, err
		}
		details := describeCRL(crl)
		return &InspectResult{Kind: KindCRL, CRL: &details}, nil

	case strings.Contains(block.Type, "PRIVATE KEY"):
		key, err := ParsePrivateKeyPEM([]byte(trimmed))
		if err != nil {
			return nil, err
		}
		spec, err := SpecOf(key)
		if err != nil {
			return nil, err
		}
		pubPEM, err := MarshalPublicKeyPEM(key.Public())
		if err != nil {
			return nil, err
		}
		return &InspectResult{Kind: KindPrivateKey, Key: &KeyDetails{
			Kind:         KindPrivateKey,
			KeyAlgorithm: spec.Display(),
			KeySize:      spec.Size,
			PublicKeyPEM: string(pubPEM),
		}}, nil
	}

	return nil, fmt.Errorf("pki: unsupported PEM block type %q", block.Type)
}

// inspectDER handles raw DER input by trying each supported structure.
func inspectDER(data []byte) (*InspectResult, error) {
	if cert, err := x509.ParseCertificate(data); err == nil {
		details := DescribeCertificate(cert)
		return &InspectResult{Kind: KindCertificate, Certificate: &details}, nil
	}
	if csr, err := x509.ParseCertificateRequest(data); err == nil {
		details, err := DescribeCSR(csr)
		if err != nil {
			return nil, err
		}
		return &InspectResult{Kind: KindCSR, CSR: &details}, nil
	}
	if crl, err := x509.ParseRevocationList(data); err == nil {
		details := describeCRL(crl)
		return &InspectResult{Kind: KindCRL, CRL: &details}, nil
	}
	return nil, fmt.Errorf("pki: input is neither valid PEM nor recognisable DER")
}

func describeCRL(crl *x509.RevocationList) CRLDetails {
	entries := make([]CRLEntryDetail, 0, len(crl.RevokedCertificateEntries))
	for _, e := range crl.RevokedCertificateEntries {
		entries = append(entries, CRLEntryDetail{
			SerialNumber: FormatSerial(e.SerialNumber),
			RevokedAt:    e.RevocationTime,
			Reason:       RevocationReasonName(e.ReasonCode),
			ReasonCode:   e.ReasonCode,
		})
	}
	number := ""
	if crl.Number != nil {
		number = crl.Number.String()
	}
	return CRLDetails{
		Kind:       KindCRL,
		Issuer:     crl.Issuer.String(),
		Number:     number,
		ThisUpdate: crl.ThisUpdate,
		NextUpdate: crl.NextUpdate,
		Entries:    entries,
	}
}
